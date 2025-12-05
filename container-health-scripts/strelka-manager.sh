#!/usr/bin/env bash

set -euo pipefail

( [[ "${PIPELINE_DISABLED:-false}" == 'true' ]] || [[ "${STRELKA_MANAGER_DISABLED:-false}" == 'true' ]] ) && exit 0

pidof strelka-manager >/dev/null
