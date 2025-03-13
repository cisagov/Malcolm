#!/usr/bin/env bash

set -euo pipefail

[[ "${NGINX_AUTH_MODE:-keycloak}" != 'keycloak' ]] && exit 0

JQ_EVAL=$(
    curl --fail --silent -XGET http://localhost:9000/keycloak/health | \
        jq '(.status == "UP")' 2>/dev/null
)
[[ "$JQ_EVAL" == "true" ]] && exit 0 && exit 1
