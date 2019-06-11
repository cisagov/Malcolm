#!/usr/bin/env bash

# Copyright (c) 2019 Battelle Energy Alliance, LLC.  All rights reserved.

set -e

echo "Giving ElasticSearch at $ELASTICSEARCH_URL time to start..."

# wait for the ES HTTP server to respond at all
until $(curl --output /dev/null --silent --head --fail "$ELASTICSEARCH_URL"); do
  sleep 1
done

# now wait for the HTTP "Ok" response
until [ "$(curl --write-out %{http_code} --silent --output /dev/null "$ELASTICSEARCH_URL")" = "200" ]; do
  sleep 1
done

# next wait for ES status to turn to green or yellow
until [[ "$(curl -fsSL "$ELASTICSEARCH_URL/_cat/health?h=status" | sed -r 's/^[[:space:]]+|[[:space:]]+$//g')" =~ ^(yellow|green)$ ]]; do
  sleep 1
done

echo "ElasticSearch is running!"
echo

echo "Starting ElastAlert!"
npm start
