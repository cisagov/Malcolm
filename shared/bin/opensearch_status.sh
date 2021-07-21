#!/bin/bash

# Copyright (c) 2021 Battelle Energy Alliance, LLC.  All rights reserved.

set -e

ENCODING="utf-8"

# options
# -v      (verbose)
#
# -e url  (Elasticsearch URL, e.g., http://opensearch:9200)
# OR
# -i ip   (Elasticsearch ip)
# -p port (Elasticsearch port)
#
# -w      (wait not only for "up" status, but also wait for actual sessions2-* logs to exist)

OS_URL=
WAIT_FOR_LOG_DATA=0
while getopts 've:i:p:w' OPTION; do
  case "$OPTION" in
    v)
      set -x
      ;;

    e)
      OS_URL="$OPTARG"
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
      echo "script usage: $(basename $0) [-v] [-e <Elasticsearch URL>] [-w]" >&2
      exit 1
      ;;
  esac
done
shift "$(($OPTIND -1))"

if [[ -z $OS_URL ]]; then
  if [[ -n $OPENSEARCH_URL ]]; then
    OS_URL="$OPENSEARCH_URL"
  elif [[ -n $OS_HOST ]] && [[ -n $OS_PORT ]]; then
    OS_URL="http://$OS_HOST:$OS_PORT"
  else
    OS_URL="http://opensearch:9200"
  fi
fi


# wait for the ES HTTP server to respond at all
until $(curl --output /dev/null --silent --head --fail "$OS_URL"); do
  # printf '.' >&2
  sleep 1
done

# now wait for the HTTP "Ok" response
until [ "$(curl --write-out %{http_code} --silent --output /dev/null "$OS_URL")" = "200" ]; do
  # printf '-' >&2
  sleep 1
done

# next wait for ES status to turn to green or yellow
until [[ "$(curl -fsSL "$OS_URL/_cat/health?h=status" | sed -r 's/^[[:space:]]+|[[:space:]]+$//g')" =~ ^(yellow|green)$ ]]; do
  # printf '+' >&2
  sleep 1
done

echo "Elasticsearch is up and healthy at "$OS_URL"" >&2

if (( $WAIT_FOR_LOG_DATA == 1 )); then
  sleep 1

  echo "Waiting until Elasticsearch has logs..." >&2

  # wait until at least one sessions2-* index exists
  until (( $(curl -fs -H'Content-Type: application/json' -XGET "$OS_URL/_cat/indices/sessions2-*" 2>/dev/null | wc -l) > 0 )) ; do
    sleep 5
  done
  echo "Log indices exist." >&2

  # wait until at least one record with @timestamp exists
  until curl -fs -H'Content-Type: application/json' -XPOST "$OS_URL/sessions2-*/_search" -d'{ "sort": { "@timestamp" : "desc" }, "size" : 1 }' >/dev/null 2>&1 ; do
    sleep 5
  done
  echo "Logs exist." >&2
fi