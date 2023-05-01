#!/bin/bash

# Copyright (c) 2023 Battelle Energy Alliance, LLC.  All rights reserved.

set -e

ENCODING="utf-8"

# options
# -v          (verbose)
#
# -w      (wait not only for "up" status, but also wait for actual arkime_sessions3-* logs to exist)
#
# opensearch connection parameters are read from environment variables

WAIT_FOR_LOG_DATA=0
while getopts 'vw' OPTION; do
  case "$OPTION" in
    v)
      set -x
      ;;

    w)
      WAIT_FOR_LOG_DATA=1
      ;;

    ?)
      echo "script usage: $(basename $0) [-v] [-w]" >&2
      exit 1
      ;;
  esac
done
shift "$(($OPTIND -1))"

OPENSEARCH_URL=${OPENSEARCH_URL:-"http://opensearch:9200"}
OPENSEARCH_LOCAL=${OPENSEARCH_LOCAL:-"true"}
OPENSEARCH_SSL_CERTIFICATE_VERIFICATION=${OPENSEARCH_SSL_CERTIFICATE_VERIFICATION:-"false"}
OPENSEARCH_CREDS_CONFIG_FILE=${OPENSEARCH_CREDS_CONFIG_FILE:-"/var/local/curlrc/.opensearch.primary.curlrc"}
if [[ "$OPENSEARCH_LOCAL" == "false" ]] && [[ -r "$OPENSEARCH_CREDS_CONFIG_FILE" ]]; then
  CURL_CONFIG_PARAMS=(
    --config
    "$OPENSEARCH_CREDS_CONFIG_FILE"
    )
else
  CURL_CONFIG_PARAMS=()
fi

# wait for the ES HTTP server to respond at all
until $(curl "${CURL_CONFIG_PARAMS[@]}" --output /dev/null --silent --head --fail "$OPENSEARCH_URL"); do
  # printf '.' >&2
  sleep 1
done

# now wait for the HTTP "Ok" response
until [ "$(curl "${CURL_CONFIG_PARAMS[@]}" --write-out %{http_code} --silent --output /dev/null "$OPENSEARCH_URL")" = "200" ]; do
  # printf '-' >&2
  sleep 1
done

# next wait for ES status to turn to green or yellow
until [[ "$(curl "${CURL_CONFIG_PARAMS[@]}" -fsSL "$OPENSEARCH_URL/_cat/health?h=status" | sed -r 's/^[[:space:]]+|[[:space:]]+$//g')" =~ ^(yellow|green)$ ]]; do
  # printf '+' >&2
  sleep 1
done

echo "OpenSearch is up and healthy at "$OPENSEARCH_URL"" >&2

if (( $WAIT_FOR_LOG_DATA == 1 )); then
  sleep 1

  echo "Waiting until OpenSearch has logs..." >&2

  # wait until at least one arkime_sessions3-* index exists
  until (( $(curl "${CURL_CONFIG_PARAMS[@]}" -fs -H'Content-Type: application/json' -XGET "$OPENSEARCH_URL/_cat/indices/arkime_sessions3-*" 2>/dev/null | wc -l) > 0 )) ; do
    sleep 5
  done
  echo "Log indices exist." >&2

  # wait until at least one record with @timestamp exists
  until curl "${CURL_CONFIG_PARAMS[@]}" -fs -H'Content-Type: application/json' -XPOST "$OPENSEARCH_URL/arkime_sessions3-*/_search" -d'{ "sort": { "@timestamp" : "desc" }, "size" : 1 }' >/dev/null 2>&1 ; do
    sleep 5
  done
  echo "Logs exist." >&2
fi