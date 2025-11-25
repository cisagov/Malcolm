#!/usr/bin/env bash

set -euo pipefail

[[ "${STRELKA_BACKEND_DISABLED:-false}" == 'true' ]] && exit 0

pgrep -f '/bin/strelka-backend' >/dev/null 2>&1
