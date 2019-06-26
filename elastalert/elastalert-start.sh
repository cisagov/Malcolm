#!/usr/bin/env bash

# Copyright (c) 2019 Battelle Energy Alliance, LLC.  All rights reserved.

set -e

echo "Giving ElasticSearch at $ELASTICSEARCH_URL time to start..."

elastic_search_status.sh

echo "Starting ElastAlert!"
npm start
