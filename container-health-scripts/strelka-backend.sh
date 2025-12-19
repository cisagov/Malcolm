#!/usr/bin/env bash

set -euo pipefail

( [[ "${PIPELINE_DISABLED:-false}" == 'true' ]] || [[ "${STRELKA_BACKEND_DISABLED:-false}" == 'true' ]] ) && exit 0

(( $(supervisorctl status 2>/dev/null | grep -v ^ruleinit | grep -cPv '(^INFO:|STARTING|RUNNING|EXITED|Not started$)') == 0 )) && exit 0 || exit 1
