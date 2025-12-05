#!/usr/bin/env bash

set -euo pipefail

( [[ "${PIPELINE_DISABLED:-false}" == 'true' ]] || [[ "${STRELKA_FRONTEND_DISABLED:-false}" == 'true' ]] ) && exit 0

pidof strelka-frontend >/dev/null
