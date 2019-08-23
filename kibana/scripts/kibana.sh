#!/bin/bash

# Copyright (c) 2019 Battelle Energy Alliance, LLC.  All rights reserved.

echo "Giving Elasticsearch time to start before starting Kibana..."
/data/elastic_search_status.sh 2>&1 && echo "Elasticsearch is running!"

if [[ "$KIBANA_OFFLINE_REGION_MAPS" = "true" ]] ; then
  KIBANA_CFG="/opt/kibana/config/kibana-offline-maps.yml"
else
  KIBANA_CFG="/opt/kibana/config/kibana-standard.yml"
fi

/usr/local/bin/kibana-docker --config "$KIBANA_CFG"
