#!/usr/bin/env bash

# Copyright (c) 2020 Battelle Energy Alliance, LLC.  All rights reserved.

set -e

echo "Giving Elasticsearch at $ELASTICSEARCH_URL time to start..."

elastic_search_status.sh

echo "Starting ElastAlert!"
npm start
