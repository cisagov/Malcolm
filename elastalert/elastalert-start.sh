#!/usr/bin/env bash

# Copyright (c) 2021 Battelle Energy Alliance, LLC.  All rights reserved.

set -e

export PATH="/usr/local/bin:$PATH"

echo "Giving Elasticsearch at $ELASTICSEARCH_URL time to start..."

elastic_search_status.sh -w

echo "Starting ElastAlert!"
npm start
