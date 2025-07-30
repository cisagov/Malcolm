#!/usr/bin/env bash

set -euo pipefail

if [[ "${OPENSEARCH_PRIMARY:-opensearch-local}" == "opensearch-local" ]]; then
  # check the actual OpenSearch service, encrypted and authenticated via the OpenSearch security plugin
  OPENSEARCH_CREDS_CONFIG_FILE=${OPENSEARCH_CREDS_CONFIG_FILE:-"/var/local/curlrc/.opensearch.primary.curlrc"}
  if [[ -r "$OPENSEARCH_CREDS_CONFIG_FILE" ]]; then
    CURL_CONFIG_PARAMS=(
      --config
      "$OPENSEARCH_CREDS_CONFIG_FILE"
      )
  else
    CURL_CONFIG_PARAMS=()
  fi
  curl "${CURL_CONFIG_PARAMS[@]}" --insecure --silent --output /dev/null --fail "https://localhost:9200"

else
  # the goStatic placeholder service is not running HTTPS
  curl --silent --output /dev/null --fail "http://localhost:9200"
fi