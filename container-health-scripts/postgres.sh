#!/usr/bin/env bash

set -euo pipefail

# if postgres is disabled, exit successfully
[[ "${POSTGRES_DISABLED:-false}" == 'true' ]] && exit 0

# check if postgres is ready and responding
pg_isready -d "${POSTGRES_DB}" -U "${POSTGRES_USER}" >/dev/null 2>&1 || exit 1
