#!/usr/bin/env bash

# post-upgrade-tasks.sh (/docker-entrypoint-startdb.d/)
#
# Runs on every container start after the server is accepting connections
# (via docker-entrypoint-startdb.sh). No-op unless pg-major-upgrade.sh left
# a marker indicating a major-version upgrade just occurred. Finishes the
# upgrade: applies extension updates emitted by pg_upgrade, regenerates
# optimizer statistics, and removes the preserved pre-upgrade cluster copy
# now that the new cluster has started cleanly.
#
# Ordering matters: the marker is removed LAST, so if any step fails the
# whole sequence is retried on the next container start (each step is
# idempotent).

PGDATA="${PGDATA:-/var/lib/postgresql/data}"
PG_SUPERUSER="${POSTGRES_USER:-postgres}"
MAIN_DB="${POSTGRES_DB:-postgres}"

MARKER_POST_TASKS="${PGDATA}/.pg-upgrade-post-tasks"
UPDATE_EXTENSIONS_SQL="${PGDATA}/.pg-upgrade-update-extensions.sql"

[[ -f "${MARKER_POST_TASKS}" ]] || exit 0

OLD_MAJOR="$(< "${MARKER_POST_TASKS}")"
echo "$(basename "$0"): finalizing upgrade from PostgreSQL ${OLD_MAJOR}"

if [[ -f "${UPDATE_EXTENSIONS_SQL}" ]]; then
    psql -v ON_ERROR_STOP=1 --username "${PG_SUPERUSER}" --dbname "${MAIN_DB}" \
        -f "${UPDATE_EXTENSIONS_SQL}" || exit 1
    rm -f "${UPDATE_EXTENSIONS_SQL}"
fi

vacuumdb --all --analyze-in-stages --missing-stats-only --jobs="$(nproc)" --username "${PG_SUPERUSER}" || exit 1
vacuumdb --all --analyze-only --jobs="$(nproc)" --username "${PG_SUPERUSER}" || exit 1

# new cluster is up and post-tasks succeeded: drop the pre-upgrade backup
rm -rf -- "${PGDATA}/.pg-preupgrade-${OLD_MAJOR}" || exit 1
rm -rf -- "${PGDATA}"/pg_upgrade_output.d "${PGDATA}/.pg-upgrade-failed-logs" || exit 1
rm -f -- "${MARKER_POST_TASKS}" || exit 1

echo "$(basename "$0"): post-upgrade tasks complete; pre-upgrade PostgreSQL ${OLD_MAJOR} backup removed"
exit 0
