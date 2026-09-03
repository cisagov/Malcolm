#!/usr/bin/env bash

# collation-version-refresh.sh (/docker-entrypoint-startdb.d/)
#
# Runs on every container start after the server is accepting connections.
# Detects collations (and database default collations) whose recorded version
# no longer matches what the underlying library (ICU/libc) currently
# provides. This happens whenever the base image's ICU library is upgraded
# under an existing data volume, e.g. after a PostgreSQL major-version
# upgrade or an Alpine icu-libs bump. Example: NetBox's "natural_sort"
# ICU collation.
#
# Remediation per PostgreSQL docs: REINDEX objects depending on the
# collation FIRST, then ALTER COLLATION ... REFRESH VERSION to record the
# new version. We use REINDEX DATABASE as a blunt-but-correct instrument;
# Malcolm's databases are small enough that precision isn't worth the
# pg_depend spelunking.
#
# No-ops when all collation versions match. Failures are logged but
# non-fatal; the check reruns on every container start.

PG_SUPERUSER="${POSTGRES_USER:-postgres}"

psql_super() {
    psql -X -tA --username "${PG_SUPERUSER}" "$@"
}

DATABASES="$(psql_super -c "SELECT datname FROM pg_database WHERE datallowconn AND NOT datistemplate")"

for DB in ${DATABASES}; do

    # collation objects with stale versions (NULL collversion = untracked, skip)
    MISMATCHED="$(psql_super --dbname "${DB}" -c \
        "SELECT quote_ident(collnamespace::regnamespace::text) || '.' || quote_ident(collname)
         FROM pg_collation
         WHERE collversion IS NOT NULL
           AND collversion IS DISTINCT FROM pg_collation_actual_version(oid)")"

    # database default collation version
    DB_MISMATCH="$(psql_super --dbname "${DB}" -c \
        "SELECT 1 FROM pg_database
         WHERE datname = current_database()
           AND datcollversion IS NOT NULL
           AND datcollversion IS DISTINCT FROM pg_database_collation_actual_version(oid)")"

    [[ -z "${MISMATCHED}" ]] && [[ -z "${DB_MISMATCH}" ]] && continue

    echo "$(basename "$0"): collation version mismatch detected in database \"${DB}\"; reindexing"

    if ! psql_super --dbname "${DB}" -v ON_ERROR_STOP=1 -c "REINDEX DATABASE"; then
        echo "$(basename "$0"): ERROR: REINDEX of \"${DB}\" failed; leaving collation versions unrefreshed (will retry on next start)" >&2
        continue
    fi

    while IFS= read -r COLLATION; do
        [[ -z "${COLLATION}" ]] && continue
        psql_super --dbname "${DB}" -v ON_ERROR_STOP=1 \
            -c "ALTER COLLATION ${COLLATION} REFRESH VERSION" \
            || echo "$(basename "$0"): ERROR: failed to refresh version of collation ${COLLATION} in \"${DB}\"" >&2
    done <<< "${MISMATCHED}"

    if [[ -n "${DB_MISMATCH}" ]]; then
        psql_super --dbname "${DB}" -v ON_ERROR_STOP=1 \
            -c "ALTER DATABASE \"${DB}\" REFRESH COLLATION VERSION" \
            || echo "$(basename "$0"): ERROR: failed to refresh default collation version of \"${DB}\"" >&2
    fi

    echo "$(basename "$0"): collation versions refreshed in database \"${DB}\""
done

exit 0
