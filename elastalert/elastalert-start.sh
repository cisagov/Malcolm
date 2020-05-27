#!/usr/bin/env bash

# Copyright (c) 2020 Battelle Energy Alliance, LLC.  All rights reserved.

set -e

echo "Giving Elasticsearch at $ELASTICSEARCH_URL time to start..."

elastic_search_status.sh

sleep 5

echo "Waiting until Elasticsearch has log data before starting..."

# wait until at least one sessions2-* index exists
until (( $(curl -fs -H'Content-Type: application/json' -XGET "$ELASTICSEARCH_URL/_cat/indices/sessions2-*" 2>/dev/null | wc -l) > 0 )) ; do
  sleep 5
done
echo "Log indices exist."

# wait until at least one record with @timestamp exists
until curl -fs -H'Content-Type: application/json' -XPOST "$ELASTICSEARCH_URL/sessions2-*/_search" -d'{ "sort": { "@timestamp" : "desc" }, "size" : 1 }' >/dev/null 2>&1 ; do
  sleep 5
done
echo "Logs exist."

echo "Starting ElastAlert!"
npm start
