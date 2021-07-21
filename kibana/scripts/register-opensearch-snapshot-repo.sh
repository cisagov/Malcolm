#!/bin/bash

# Copyright (c) 2021 Battelle Energy Alliance, LLC.  All rights reserved.

if [ $# -gt 0 ]; then
  OS_URL="$1"
elif [[ -n $OPENSEARCH_URL ]]; then
  OS_URL="$OPENSEARCH_URL"
elif [[ -n $ES_HOST ]] && [[ -n $OS_PORT ]]; then
  OS_URL="http://$ES_HOST:$OS_PORT"
else
  OS_URL="http://opensearch:9200"
fi

[[ -n $ISM_SNAPSHOT_REPO ]] && \
  curl -w "\n" -H "Accept: application/json" \
  -H "Content-type: application/json" \
  -XPUT -fsSL "$OS_URL/_snapshot/$ISM_SNAPSHOT_REPO" \
  -d "{ \"type\": \"fs\", \"settings\": { \"location\": \"$ISM_SNAPSHOT_REPO\", \"compress\": ${ISM_SNAPSHOT_COMPRESSED:-false} } }"