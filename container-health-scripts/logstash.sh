#!/usr/bin/env bash

set -euo pipefail

JQ_EVAL=$(
    curl --fail --silent -XGET http://localhost:9600/_health_report | \
        jq '(.status | test("green|yellow")) and
            (.indicators.pipelines.status | test("green|yellow")) and
            (all(.indicators.pipelines.indicators[]; .status | test("green|yellow")))' 2>/dev/null
)

[[ "$JQ_EVAL" == "true" ]] && exit 0 && exit 1
