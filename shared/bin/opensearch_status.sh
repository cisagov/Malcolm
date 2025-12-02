#!/bin/bash

# Copyright (c) 2025 Battelle Energy Alliance, LLC.  All rights reserved.

set -e

ENCODING="utf-8"

# options
# -v       (verbose)
# -t <str> (wait not only for "up" status, but also wait for specified index template ot exist
# -w       (wait not only for "up" status, but also wait for actual network traffic logs to exist)
#
# opensearch connection parameters are read from environment variables

WAIT_FOR_LOG_DATA=0
WAIT_FOR_TEMPLATE=
WAIT_FOR_TEMPLATE_LEGACY=
while getopts 'vwt:l:' OPTION; do
  case "$OPTION" in
    v)
      set -x
      ;;

    w)
      WAIT_FOR_LOG_DATA=1
      ;;

    t)
      WAIT_FOR_TEMPLATE=${OPTARG}
      ;;

    l)
      WAIT_FOR_TEMPLATE_LEGACY=${OPTARG}
      ;;

    ?)
      echo "script usage: $(basename $0) [-v] [-w] [-t <template name>]" >&2
      exit 1
      ;;
  esac
done
shift "$(($OPTIND -1))"


OPENSEARCH_PRIMARY=${OPENSEARCH_PRIMARY:-"opensearch-local"}
if [[ -z "$OPENSEARCH_URL" ]]; then
  if [[ "$OPENSEARCH_PRIMARY" == "opensearch-local" ]]; then
    OPENSEARCH_URL="https://opensearch:9200"
  else
    echo "No URL specified for $OPENSEARCH_PRIMARY, going to sleep" >&2
    sleep infinity
    exit 1
  fi
fi
MALCOLM_NETWORK_INDEX_PATTERN=${MALCOLM_NETWORK_INDEX_PATTERN:-"arkime_sessions3-*"}
ARKIME_NETWORK_INDEX_PATTERN=${ARKIME_NETWORK_INDEX_PATTERN:-"arkime_sessions3-*"}
OPENSEARCH_SSL_CERTIFICATE_VERIFICATION=${OPENSEARCH_SSL_CERTIFICATE_VERIFICATION:-"false"}
OPENSEARCH_CREDS_CONFIG_FILE=${OPENSEARCH_CREDS_CONFIG_FILE:-"/var/local/curlrc/.opensearch.primary.curlrc"}
if [[ -r "$OPENSEARCH_CREDS_CONFIG_FILE" ]]; then
  CURL_CONFIG_PARAMS=(
    --config
    "$OPENSEARCH_CREDS_CONFIG_FILE"
    )
else
  CURL_CONFIG_PARAMS=()
fi

# wait for the ES HTTP server to respond at all
until curl "${CURL_CONFIG_PARAMS[@]}" --output /dev/null --silent --head --fail "$OPENSEARCH_URL" >/dev/null 2>&1; do
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

echo "$OPENSEARCH_PRIMARY is up and healthy at "$OPENSEARCH_URL"" >&2

if [[ -n "$WAIT_FOR_TEMPLATE_LEGACY" ]]; then
  sleep 1
  echo "Waiting until $OPENSEARCH_PRIMARY has legacy template \"$WAIT_FOR_TEMPLATE_LEGACY\"..." >&2
  until ( curl "${CURL_CONFIG_PARAMS[@]}" -fs -H'Content-Type: application/json' -XGET "$OPENSEARCH_URL/_template/$WAIT_FOR_TEMPLATE_LEGACY" 2>/dev/null | grep -q mappings ); do
    sleep 5
  done
  echo "$OPENSEARCH_PRIMARY legacy template \"$WAIT_FOR_TEMPLATE_LEGACY\" exists" >&2
  sleep 5
fi

if [[ -n "$WAIT_FOR_TEMPLATE" ]]; then
  sleep 1
  echo "Waiting until $OPENSEARCH_PRIMARY has index template \"$WAIT_FOR_TEMPLATE\"..." >&2
  until ( curl "${CURL_CONFIG_PARAMS[@]}" -fs -H'Content-Type: application/json' -XGET "$OPENSEARCH_URL/_index_template/$WAIT_FOR_TEMPLATE" 2>/dev/null | grep -q index_templates ); do
    sleep 5
  done
  echo "$OPENSEARCH_PRIMARY index template \"$WAIT_FOR_TEMPLATE\" exists" >&2
  sleep 5
fi

if (( $WAIT_FOR_LOG_DATA == 1 )); then
  sleep 1

  echo "Waiting until $OPENSEARCH_PRIMARY has logs..." >&2

  # wait until at least one network traffic log index exists (get index count where docs.count > 0)
  FOUND_INDEX=
  while true; do
    # use jq if it's available to parse the machine-readable index list as JSON, fall back to awk if it's not
    if command -v jq >/dev/null 2>&1; then
      if (( $(curl "${CURL_CONFIG_PARAMS[@]}" -fs -H'Content-Type: application/json' -XGET "$OPENSEARCH_URL/_cat/indices/$MALCOLM_NETWORK_INDEX_PATTERN?format=json" 2>/dev/null | jq '[.[] | select(.["docs.count"] != "0")] | length' 2>/dev/null) > 0 )); then
        FOUND_INDEX="$MALCOLM_NETWORK_INDEX_PATTERN"
      elif [[ "$MALCOLM_NETWORK_INDEX_PATTERN" != "$ARKIME_NETWORK_INDEX_PATTERN" ]] && (( $(curl "${CURL_CONFIG_PARAMS[@]}" -fs -H'Content-Type: application/json' -XGET "$OPENSEARCH_URL/_cat/indices/$ARKIME_NETWORK_INDEX_PATTERN?format=json" 2>/dev/null | jq '[.[] | select(.["docs.count"] != "0")] | length' 2>/dev/null) > 0 )); then
        FOUND_INDEX="$ARKIME_NETWORK_INDEX_PATTERN"
      fi
    else
      if (( $(curl "${CURL_CONFIG_PARAMS[@]}" -fs -H'Content-Type: application/json' -XGET "$OPENSEARCH_URL/_cat/indices/$MALCOLM_NETWORK_INDEX_PATTERN" 2>/dev/null | awk '$7 != "0"' | wc -l) > 0 )); then
        FOUND_INDEX="$MALCOLM_NETWORK_INDEX_PATTERN"
      elif [[ "$MALCOLM_NETWORK_INDEX_PATTERN" != "$ARKIME_NETWORK_INDEX_PATTERN" ]] && (( $(curl "${CURL_CONFIG_PARAMS[@]}" -fs -H'Content-Type: application/json' -XGET "$OPENSEARCH_URL/_cat/indices/$ARKIME_NETWORK_INDEX_PATTERN" 2>/dev/null | awk '$7 != "0"' | wc -l) > 0 )); then
        FOUND_INDEX="$ARKIME_NETWORK_INDEX_PATTERN"
      fi
    fi
    [[ -n "$FOUND_INDEX" ]] && break || sleep 5
  done
  echo "Logs exist." >&2
fi