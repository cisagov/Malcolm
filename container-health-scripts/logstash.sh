#!/usr/bin/env bash

set -euo pipefail

JQ_EVAL=$(
    curl --fail --silent -XGET http://localhost:9600/_health_report | \
        jq '(.status == "green") and
            (.indicators.pipelines.status == "green") and
            (all(.indicators.pipelines.indicators[]; .status == "green"))' 2>/dev/null
)

[[ "$JQ_EVAL" == "true" ]] && exit 0 && exit 1
