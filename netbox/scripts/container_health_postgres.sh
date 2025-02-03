#!/bin/bash

set -euo pipefail

# if postgres is disabled, exit successfully
if [[ "${NETBOX_POSTGRES_DISABLED:-false}" == 'true' ]]; then
  exit 0
fi

# check if postgres is ready and responding
pg_isready -d "${POSTGRES_DB}" -U "${POSTGRES_USER}" || exit 1

# if we got here, everything is good
exit 0
