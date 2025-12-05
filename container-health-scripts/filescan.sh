#!/usr/bin/env bash

set -euo pipefail

( [[ "${PIPELINE_DISABLED:-false}" == 'true' ]] || [[ "${FILESCAN_DISABLED:-false}" == 'true' ]] ) && exit 0

JQ_EVAL=$(
    curl --fail --silent -XGET http://localhost:${FILESCAN_HEALTH_PORT:-8001}/health | \
        jq '.state == "running" and ([.programs[][].healthy] | all) and ([.programs[][].state == "running"] | all)' 2>/dev/null
)
[[ "$JQ_EVAL" == "true" ]] && exit 0 && exit 1

