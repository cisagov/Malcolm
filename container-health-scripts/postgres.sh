#!/usr/bin/env bash

set -euo pipefail

# if postgres is disabled, exit successfully
[[ "${POSTGRES_DISABLED:-false}" == 'true' ]] && exit 0

# report unhealthy/not-ready while an automatic major-version upgrade is running
#   so dependent services do not start before PostgreSQL is accepting connections.
#   pg-major-upgrade.sh touches the marker as it progresses through phases;
#   a marker not updated in 2 hours is stale, e.g. a wedged upgrade, and we
#   fall through to the normal check and report unhealthy.
UPGRADE_MARKER="${PGDATA:-/var/lib/postgresql/data}/.pg-upgrade-in-progress"
if [[ -f "${UPGRADE_MARKER}" ]] && [[ -n "$(find "${UPGRADE_MARKER}" -mmin -120 2>/dev/null)" ]]; then
    echo "postgresql not ready, major version upgrade in progress"
    exit 1
fi

# check if postgres is ready and responding
pg_isready -d "${POSTGRES_DB}" -U "${POSTGRES_USER}" >/dev/null 2>&1 || exit 1
