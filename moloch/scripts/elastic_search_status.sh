#!/bin/bash

# Copyright (c) 2019 Battelle Energy Alliance, LLC.  All rights reserved.

set -e

if [ -z "$1" ]; then ELASTICSEARCH_URL="http://$ES_HOST:$ES_PORT"; else ELASTICSEARCH_URL="$1"; fi;

# wait for the ES HTTP server to respond at all
until $(curl --output /dev/null --silent --head --fail "$ELASTICSEARCH_URL"); do
  # printf '.' >&2
  sleep 1
done

# now wait for the HTTP "Ok" response
until [ "$(curl --write-out %{http_code} --silent --output /dev/null "$ELASTICSEARCH_URL")" = "200" ]; do
  # printf '-' >&2
  sleep 1
done

# next wait for ES status to turn to green or yellow
until [[ "$(curl -fsSL "$ELASTICSEARCH_URL/_cat/health?h=status" | sed -r 's/^[[:space:]]+|[[:space:]]+$//g')" =~ ^(yellow|green)$ ]]; do
  # printf '+' >&2
  sleep 1
done

echo "ElasticSearch is up and healthy at "$ELASTICSEARCH_URL"" >&2
