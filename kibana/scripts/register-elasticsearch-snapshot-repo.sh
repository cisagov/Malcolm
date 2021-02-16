#!/bin/bash

# Copyright (c) 2021 Battelle Energy Alliance, LLC.  All rights reserved.

if [ $# -gt 0 ]; then
  ES_URL="$1"
elif [[ -n $ELASTICSEARCH_URL ]]; then
  ES_URL="$ELASTICSEARCH_URL"
elif [[ -n $ES_HOST ]] && [[ -n $ES_PORT ]]; then
  ES_URL="http://$ES_HOST:$ES_PORT"
else
  ES_URL="http://elasticsearch:9200"
fi

[[ -n $ISM_SNAPSHOT_REPO ]] && \
  curl -H "Accept: application/json" \
  -H "Content-type: application/json" \
  -XPUT -fsSL "$ES_URL/_snapshot/$ISM_SNAPSHOT_REPO" \
  -d "{ \"type\": \"fs\", \"settings\": { \"location\": \"$ISM_SNAPSHOT_REPO\", \"compress\": ${ISM_SNAPSHOT_COMPRESSED:-false} } }"