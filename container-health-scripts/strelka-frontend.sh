#!/usr/bin/env bash

set -euo pipefail

[[ "${STRELKA_FRONTEND_DISABLED:-false}" == 'true' ]] && exit 0

pidof strelka-frontend >/dev/null
