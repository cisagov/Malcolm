#!/bin/bash

set -euo pipefail

# if redis is disabled, exit successfully
if [[ "${NETBOX_REDIS_DISABLED:-false}" == 'true' ]]; then
  exit 0
fi

# check if redis process is running
pidof redis-server >/dev/null || exit 1

# if we got here, everything is good
exit 0
