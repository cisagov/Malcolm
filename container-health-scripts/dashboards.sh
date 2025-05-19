#!/usr/bin/env bash

set -euo pipefail

OPENSEARCH_CREDS_CONFIG_FILE=${OPENSEARCH_CREDS_CONFIG_FILE:-"/var/local/curlrc/.opensearch.primary.curlrc"}
if [[ -r "$OPENSEARCH_CREDS_CONFIG_FILE" ]]; then
  CURL_CONFIG_PARAMS=(
    --config
    "$OPENSEARCH_CREDS_CONFIG_FILE"
    )
else
  CURL_CONFIG_PARAMS=()
fi

curl "${CURL_CONFIG_PARAMS[@]}" --insecure --silent --output /dev/null --fail "http://localhost:5601/dashboards/api/status"
