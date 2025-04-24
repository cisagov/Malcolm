#!/usr/bin/env bash

set -euo pipefail

if [[ -n "$SUPERUSER_API_TOKEN" ]]; then
    echo -n "Authorization: Token $SUPERUSER_API_TOKEN" | \
        curl --silent --output /dev/null --fail \
            -H "Content-Type: application/json" \
            -H @- \
            "http://localhost:8080/netbox/api/"
else
    curl --silent --output /dev/null --fail \
        -H "Content-Type: application/json" \
        "http://localhost:8080/netbox/api/"
fi
