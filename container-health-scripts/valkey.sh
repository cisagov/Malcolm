#!/usr/bin/env bash

set -euo pipefail

# if redis is disabled, exit successfully
[[ "${VALKEY_DISABLED:-false}" == 'true' ]] && exit 0

# check if redis process is running
pidof valkey-server >/dev/null
