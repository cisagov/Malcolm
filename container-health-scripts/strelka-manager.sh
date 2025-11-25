#!/usr/bin/env bash

set -euo pipefail

[[ "${STRELKA_MANAGER_DISABLED:-false}" == 'true' ]] && exit 0

pidof strelka-manager >/dev/null
