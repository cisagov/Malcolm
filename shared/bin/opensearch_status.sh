#!/bin/bash

# Copyright (c) 2022 Battelle Energy Alliance, LLC.  All rights reserved.

set -e

ENCODING="utf-8"

# options
# -v          (verbose)
#
# -e url      (OpenSearch URL, e.g., http://opensearch:9200)
# OR
# -r protocol (OpenSearch protocol, e.g., http or https)
# -i ip       (OpenSearch ip)
# -p port     (OpenSearch port)
#
# -w      (wait not only for "up" status, but also wait for actual arkime_sessions3-* logs to exist)

OS_URL=
OS_PROTOCOL=
OS_HOST=
OS_PORT=
WAIT_FOR_LOG_DATA=0
while getopts 've:r:i:p:w' OPTION; do
  case "$OPTION" in
    v)
      set -x
      ;;

    e)
      OS_URL="$OPTARG"
      ;;

    r)
      OS_PROTOCOL="$OPTARG"
      ;;

    i)
      OS_HOST="$OPTARG"
      ;;

    p)
      OS_PORT="$OPTARG"
      ;;

    w)
      WAIT_FOR_LOG_DATA=1
      ;;

    ?)
      echo "script usage: $(basename $0) [-v] [-e <OpenSearch URL>] [-w]" >&2
      exit 1
      ;;
  esac
done
shift "$(($OPTIND -1))"

if [[ -n "$OS_URL" ]]; then
  OPENSEARCH_URL="$OS_URL"
elif [[ -z $OPENSEARCH_URL ]]; then
  OPENSEARCH_PROTOCOL=${OPENSEARCH_PROTOCOL:-"http"}
  OPENSEARCH_HOST=${OPENSEARCH_HOST:-"opensearch"}
  OPENSEARCH_PORT=${OPENSEARCH_PORT:-"9200"}
  OS_PROTOCOL=${OS_PROTOCOL:-"$OPENSEARCH_PROTOCOL"}
  OS_HOST=${OS_HOST:-"$OPENSEARCH_HOST"}
  OS_PORT=${OS_PORT:-"$OPENSEARCH_PORT"}
  OPENSEARCH_URL="${OS_PROTOCOL}://${OS_HOST}:${OS_PORT}"
fi


# wait for the ES HTTP server to respond at all
until $(curl --output /dev/null --silent --insecure --head --fail "$OPENSEARCH_URL"); do
  # printf '.' >&2
  sleep 1
done

# now wait for the HTTP "Ok" response
until [ "$(curl --write-out %{http_code} --silent --insecure --output /dev/null "$OPENSEARCH_URL")" = "200" ]; do
  # printf '-' >&2
  sleep 1
done

# next wait for ES status to turn to green or yellow
until [[ "$(curl -fsSLk "$OPENSEARCH_URL/_cat/health?h=status" | sed -r 's/^[[:space:]]+|[[:space:]]+$//g')" =~ ^(yellow|green)$ ]]; do
  # printf '+' >&2
  sleep 1
done

echo "OpenSearch is up and healthy at "$OPENSEARCH_URL"" >&2

if (( $WAIT_FOR_LOG_DATA == 1 )); then
  sleep 1

  echo "Waiting until OpenSearch has logs..." >&2

  # wait until at least one arkime_sessions3-* index exists
  until (( $(curl -fsk -H'Content-Type: application/json' -XGET "$OPENSEARCH_URL/_cat/indices/arkime_sessions3-*" 2>/dev/null | wc -l) > 0 )) ; do
    sleep 5
  done
  echo "Log indices exist." >&2

  # wait until at least one record with @timestamp exists
  until curl -fsk -H'Content-Type: application/json' -XPOST "$OPENSEARCH_URL/arkime_sessions3-*/_search" -d'{ "sort": { "@timestamp" : "desc" }, "size" : 1 }' >/dev/null 2>&1 ; do
    sleep 5
  done
  echo "Logs exist." >&2
fi