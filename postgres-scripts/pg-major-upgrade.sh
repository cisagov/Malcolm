#!/usr/bin/env bash

# pg-major-upgrade.sh
#
# Runs BEFORE the postgres server is launched (called from
# docker-entrypoint-startdb.sh). If ${PGDATA} contains a cluster from an
# older PostgreSQL major version, and this image contains the matching old
# server binaries (/usr/libexec/postgresqlNN, installed via apk), perform an
# automatic in-place pg_upgrade to this image's major version.
#
# Design notes:
#   - pg_upgrade runs in COPY mode (not --link): the old cluster is never
#     mutated, so any failure is recoverable by moving the old files back.
#   - Everything (staging dirs, markers, preserved backup) lives INSIDE
#     ${PGDATA}, because ${PGDATA} itself is the volume mount point.
#   - Single recovery invariant: if ${PGDATA}/.pg-upgrade-old exists, it is
#     the authoritative cluster. On startup we restore it and start over.
#   - On success, the old cluster is preserved at
#     ${PGDATA}/.pg-preupgrade-<ver> and a marker is left for
#     post-upgrade-tasks.sh (a docker-entrypoint-startdb.d/ script) to run
#     extension updates + analyze, then remove the backup after the first
#     clean startup.
#
# Supporting a new upgrade path in the future (e.g. 18 -> 19 when the base
# image moves to postgres:19-alpine) only requires adding the corresponding
# apk package(s) (postgresql17, postgresql18, ...) in postgresql.Dockerfile;
# pg_upgrade handles multi-major jumps directly.

set -uo pipefail

ENCODING=""
COLLATE=""
CTYPE=""
CHECKSUM_ARG=""

PGDATA="${PGDATA:-/var/lib/postgresql/data}"
PG_SUPERUSER="${POSTGRES_USER:-postgres}"

MARKER_IN_PROGRESS="${PGDATA}/.pg-upgrade-in-progress"
MARKER_POST_TASKS="${PGDATA}/.pg-upgrade-post-tasks"
UPDATE_EXTENSIONS_SQL="${PGDATA}/.pg-upgrade-update-extensions.sql"
STAGE_OLD="${PGDATA}/.pg-upgrade-old"
STAGE_NEW="${PGDATA}/.pg-upgrade-new"

NEW_BINDIR="$(dirname "$(command -v postgres)")"
NEW_MAJOR="$("${NEW_BINDIR}"/postgres --version | sed -E 's/.* ([0-9]+)\..*/\1/')"

log() {
    printf '%s: %s\n' "$(basename "$0")" "$*" >&2
}

# names in ${PGDATA} that belong to the upgrade machinery and must never be
# swept up when relocating cluster contents
is_upgrade_artifact() {
    case "$(basename "$1")" in
        .pg-upgrade-*|.pg-preupgrade-*) return 0 ;;
        *) return 1 ;;
    esac
}

# move all cluster contents of ${PGDATA} into $1 (staging), leaving our
# artifacts in place
move_cluster_contents() {
    local dest="$1"
    local item
    local failed=false
    shopt -s dotglob nullglob
    for item in "${PGDATA}"/*; do
        [[ "$item" == "$dest" ]] && continue
        is_upgrade_artifact "$item" && continue
        if ! mv -- "$item" "$dest"/; then
            failed=true
            break
        fi
    done
    shopt -u dotglob nullglob

    [[ "${failed}" == "false" ]]
}

# restore the authoritative old cluster from ${STAGE_OLD} back into
# ${PGDATA}, discarding everything else the upgrade attempt created
restore_old_cluster() {
    local item
    local restore_failed=false

    if [[ ! -d "${STAGE_OLD}" ]]; then
        log "ERROR: cannot restore original cluster: ${STAGE_OLD} does not exist"
        return 1
    fi

    log "restoring original cluster contents from ${STAGE_OLD}"

    # Remove anything in PGDATA except:
    #   - the authoritative old cluster staging directory
    #   - preserved failure logs
    #
    # This discards a partially initialized/upgraded new cluster and any
    # transient upgrade markers/artifacts.
    shopt -s dotglob nullglob
    for item in "${PGDATA}"/*; do
        [[ "${item}" == "${STAGE_OLD}" ]] && continue
        if is_upgrade_artifact "${item}"; then
            # transient artifacts of THIS attempt get discarded; preserved
            # backups, pending post-task state, and failure logs survive
            [[ "${item}" != "${STAGE_NEW}" && "${item}" != "${MARKER_IN_PROGRESS}" ]] && continue
        fi
        if ! rm -rf -- "${item}"; then
            log "ERROR: failed to remove upgrade artifact during restore: ${item}"
            restore_failed=true
        fi
    done

    if [[ "${restore_failed}" == "true" ]]; then
        shopt -u dotglob nullglob
        log "ERROR: restore aborted before moving original cluster back into place"
        return 1
    fi

    # Move the authoritative old cluster contents back to PGDATA.
    # With nullglob, this is safe even if STAGE_OLD is unexpectedly empty,
    # but an empty restored cluster is not useful, so verify PG_VERSION after.
    for item in "${STAGE_OLD}"/*; do
        if ! mv -- "${item}" "${PGDATA}"/; then
            log "ERROR: failed to restore original cluster item: ${item}"
            restore_failed=true
        fi
    done
    shopt -u dotglob nullglob

    if [[ "${restore_failed}" == "true" ]]; then
        log "ERROR: original cluster restore is incomplete; manual intervention may be required"
        return 1
    fi

    if ! rmdir -- "${STAGE_OLD}"; then
        log "ERROR: restored original cluster, but failed to remove empty staging directory: ${STAGE_OLD}"
        return 1
    fi

    if [[ ! -s "${PGDATA}/PG_VERSION" ]]; then
        log "ERROR: restored cluster is missing ${PGDATA}/PG_VERSION; manual intervention required"
        return 1
    fi

    rm -f -- "${MARKER_IN_PROGRESS}"
    log "original cluster restored successfully"
    return 0
}

fail() {
    local reason="$*"
    local logsrc
    local failed_logs="${PGDATA}/.pg-upgrade-failed-logs"

    log "ERROR: ${reason}"

    # Preserve pg_upgrade logs before restore wipes staging directories.
    # PG >= 15 commonly writes pg_upgrade_output.d under the new datadir,
    # but also check PGDATA because pg_upgrade was invoked from there.
    for logsrc in "${STAGE_NEW}/pg_upgrade_output.d" "${PGDATA}/pg_upgrade_output.d"; do
        if [[ -d "${logsrc}" ]]; then
            rm -rf -- "${failed_logs}"

            if mv -- "${logsrc}" "${failed_logs}"; then
                log "pg_upgrade logs preserved at ${failed_logs}"
            else
                log "WARNING: failed to preserve pg_upgrade logs from ${logsrc}"
            fi

            break
        fi
    done

    if [[ -d "${STAGE_OLD}" ]]; then
        if restore_old_cluster; then
            log "upgrade failed; the original cluster has been restored and will be retried on next container start"
        else
            log "CRITICAL: upgrade failed and automatic restore did not complete; manual intervention is required"
        fi
    else
        rm -f -- "${MARKER_IN_PROGRESS}"
        log "upgrade failed before the original cluster was moved aside; no restore was required"
    fi

    exit 1
}

################################################################################

# ----- recovery from a previous interrupted attempt --------------------------
if [[ -d "${STAGE_OLD}" ]]; then
    log "found remnants of an interrupted upgrade attempt"
    restore_old_cluster || exit 1
elif [[ -f "${MARKER_IN_PROGRESS}" ]]; then
    # died before the old cluster was moved aside; nothing was touched
    rm -rf "${MARKER_IN_PROGRESS}" "${STAGE_NEW}"
fi

# ----- do we even need to do anything? ---------------------------------------
[[ -s "${PGDATA}/PG_VERSION" ]] || exit 0
OLD_MAJOR="$(< "${PGDATA}/PG_VERSION")"
[[ "${OLD_MAJOR}" == "${NEW_MAJOR}" ]] && exit 0

if [[ ! "${OLD_MAJOR}" =~ ^[0-9]+$ ]]; then
    log "ERROR: data directory reports unsupported PostgreSQL version '${OLD_MAJOR}'. Aborting."
    exit 1
fi

if (( OLD_MAJOR > NEW_MAJOR )); then
    log "ERROR: data directory was initialized by PostgreSQL ${OLD_MAJOR}, which is NEWER than this image's PostgreSQL ${NEW_MAJOR}. Downgrades are not supported; use an image providing PostgreSQL ${OLD_MAJOR} or later."
    exit 1
fi

OLD_BINDIR="/usr/libexec/postgresql${OLD_MAJOR}"
if [[ ! -x "${OLD_BINDIR}/postgres" ]]; then
    log "ERROR: data directory is PostgreSQL ${OLD_MAJOR} but this image has no ${OLD_BINDIR} binaries to upgrade from. Aborting."
    exit 1
fi

log "PostgreSQL ${OLD_MAJOR} data directory detected; beginning automatic upgrade to PostgreSQL ${NEW_MAJOR}"
touch "${MARKER_IN_PROGRESS}"

# ----- preflight: free space (copy mode needs ~1x the old cluster size) ------
OLD_KB="$(du -sk "${PGDATA}" 2>/dev/null | cut -f1)"
AVAIL_KB="$(df -Pk "${PGDATA}" | awk 'NR==2 {print $4}')"
if (( AVAIL_KB < (OLD_KB + OLD_KB / 5) )); then
    rm -f "${MARKER_IN_PROGRESS}"
    log "ERROR: not enough free space for upgrade (need ~$(( OLD_KB + OLD_KB / 5 )) KB, have ${AVAIL_KB} KB). Aborting without modifying anything."
    exit 1
fi

# ----- move the old cluster aside ---------------------------------------------
mkdir -p "${STAGE_OLD}" && chmod 750 "${STAGE_OLD}" || fail "could not create ${STAGE_OLD}"
move_cluster_contents "${STAGE_OLD}" || fail "could not relocate existing cluster into ${STAGE_OLD}"
touch "${MARKER_IN_PROGRESS}"

# a hard-killed previous container may have left a stale pid file
rm -f "${STAGE_OLD}/postmaster.pid"

# ----- detect old cluster settings we must replicate in the new initdb -------
# (these single-user-mode invocations also perform crash recovery if the old
# cluster was not shut down cleanly, which pg_upgrade requires)
single_user_query() {
    local QUERY="$1"
    local CAPTURED_STDOUT=
    local CAPTURED_STDERR=
    local POSTGRES_STATUS=

    {
        IFS= read -r -d '' CAPTURED_STDERR
        IFS= read -r -d '' CAPTURED_STDOUT
        IFS= read -r -d '' POSTGRES_STATUS
    } < <(
        {
            set +e
            CAPTURED_STDOUT="$("${OLD_BINDIR}/postgres" --single -D "${STAGE_OLD}" template1 <<< "$QUERY")"
            POSTGRES_STATUS=$?
            printf '\0%s\0%s\0' "$CAPTURED_STDOUT" "$POSTGRES_STATUS" >&2
        } 2>&1
    )
    [[ -n "$CAPTURED_STDERR" ]] && log "\"$QUERY\": $CAPTURED_STDERR"
    printf '%s\n' "$CAPTURED_STDOUT"
    return "$POSTGRES_STATUS"
}

ENCODING="$(single_user_query 'SHOW SERVER_ENCODING' | grep -o 'server_encoding = "[^"]*"' | cut -d'"' -f2)"
COLLATE="$(single_user_query "SELECT datcollate FROM pg_database WHERE datname='template0'" | grep -o 'datcollate = "[^"]*"' | cut -d'"' -f2)"
CTYPE="$(single_user_query "SELECT datctype FROM pg_database WHERE datname='template0'" | grep -o 'datctype = "[^"]*"' | cut -d'"' -f2)"
LOCPROVIDER="$(single_user_query "SELECT datlocprovider FROM pg_database WHERE datname='template0'" | grep -o 'datlocprovider = "[^"]*"' | cut -d'"' -f2)"
[[ -n "${ENCODING}" ]] || fail "could not determine encoding of old cluster"
[[ -n "${COLLATE}" ]] || fail "could not determine collation of old cluster"
[[ -n "${CTYPE}" ]] || CTYPE="${COLLATE}"
[[ "${LOCPROVIDER:-c}" == "c" ]] || fail "old cluster uses locale provider '${LOCPROVIDER}' (expected libc); automatic upgrade only supports libc"

# PG >= 18 initdb enables data checksums by default; pg_upgrade requires the
# checksum setting of old and new clusters to match
if "${OLD_BINDIR}/pg_controldata" "${STAGE_OLD}" | grep -q 'Data page checksum version: *0'; then
    CHECKSUM_ARG="--no-data-checksums"
else
    CHECKSUM_ARG="--data-checksums"
fi

log "old cluster: encoding=${ENCODING} collate=${COLLATE} ctype=${CTYPE} ${CHECKSUM_ARG}"

# ----- initdb the new cluster --------------------------------------------------
mkdir -p "${STAGE_NEW}" && chmod 750 "${STAGE_NEW}" || fail "could not create ${STAGE_NEW}"
"${NEW_BINDIR}/initdb" \
    --username="${PG_SUPERUSER}" \
    --encoding="${ENCODING}" \
    --lc-collate="${COLLATE}" \
    --lc-ctype="${CTYPE}" \
    --locale-provider=libc \
    ${CHECKSUM_ARG} \
    -D "${STAGE_NEW}" >/dev/null || fail "initdb of new PostgreSQL ${NEW_MAJOR} cluster failed"

# ----- pg_upgrade ---------------------------------------------------------------
cd "${PGDATA}" || fail "could not cd to ${PGDATA}"
touch "${MARKER_IN_PROGRESS}"
"${NEW_BINDIR}/pg_upgrade" \
    --username="${PG_SUPERUSER}" \
    --old-bindir="${OLD_BINDIR}" \
    --new-bindir="${NEW_BINDIR}" \
    --old-datadir="${STAGE_OLD}" \
    --new-datadir="${STAGE_NEW}" \
    --jobs="$(nproc)" || fail "pg_upgrade from PostgreSQL ${OLD_MAJOR} to ${NEW_MAJOR} failed (see pg_upgrade_output.d in the data volume for logs)"

# pg_upgrade may emit these helper scripts into cwd
rm -f "${PGDATA}/delete_old_cluster.sh"
# discard any stale extension-update SQL from a previous upgrade cycle so
# post-upgrade-tasks.sh only ever applies output from THIS upgrade
rm -f -- "${UPDATE_EXTENSIONS_SQL}"
[[ -f "${PGDATA}/update_extensions.sql" ]] && mv "${PGDATA}/update_extensions.sql" "${UPDATE_EXTENSIONS_SQL}"

# ----- promote the new cluster ---------------------------------------------------
# preserve the auth/ident configuration the original cluster was using
cp -f "${STAGE_OLD}/pg_hba.conf" "${STAGE_OLD}/pg_ident.conf" "${STAGE_NEW}"/ 2>/dev/null

move_cluster_contents_from_new() {
    local item
    local failed=false

    shopt -s dotglob nullglob
    for item in "${STAGE_NEW}"/*; do
        if ! mv -- "$item" "${PGDATA}"/; then
            failed=true
            break
        fi
    done
    shopt -u dotglob nullglob

    [[ "${failed}" == "false" ]]
}
move_cluster_contents_from_new || fail "could not move upgraded cluster into place"
rmdir -- "${STAGE_NEW}" || fail "could not remove empty upgraded staging directory ${STAGE_NEW}"

# keep the untouched old cluster around until the first clean startup on the
# new version; post-upgrade-tasks.sh removes it
BACKUP_DIR="${PGDATA}/.pg-preupgrade-${OLD_MAJOR}"
rm -rf "${BACKUP_DIR}"
mv "${STAGE_OLD}" "${BACKUP_DIR}"
echo "${OLD_MAJOR}" > "${MARKER_POST_TASKS}"
rm -f "${MARKER_IN_PROGRESS}"
sync

log "upgrade to PostgreSQL ${NEW_MAJOR} complete; previous cluster preserved at ${BACKUP_DIR} until first clean startup"
exit 0
