#!/usr/bin/env bash

set -euo pipefail

# if redis is disabled, exit successfully
[[ "${NETBOX_REDIS_DISABLED:-false}" == 'true' ]] && exit 0

# check if redis process is running
pidof redis-server >/dev/null
