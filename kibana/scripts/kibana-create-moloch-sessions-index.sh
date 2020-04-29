#!/bin/bash

# Copyright (c) 2020 Battelle Energy Alliance, LLC.  All rights reserved.


set -euo pipefail
shopt -s nocasematch

if [[ -n $ELASTICSEARCH_URL ]]; then
  ES_URL="$ELASTICSEARCH_URL"
elif [[ -n $ES_HOST ]] && [[ -n $ES_PORT ]]; then
  ES_URL="http://$ES_HOST:$ES_PORT"
else
  ES_URL="http://elasticsearch:9200"
fi

KIBANA_URL="http://localhost:5601/kibana"
INDEX_PATTERN=${MOLOCH_INDEX_PATTERN:-"sessions2-*"}
INDEX_PATTERN_ID=${MOLOCH_INDEX_PATTERN_ID:-"sessions2-*"}
INDEX_TIME_FIELD=${MOLOCH_INDEX_TIME_FIELD:-"firstPacket"}

# is the argument to automatically create this index enabled?
if [[ "$CREATE_ES_MOLOCH_SESSION_INDEX" = "true" ]] ; then

  echo "Giving Elasticsearch time to start before configuring Kibana..."
  /data/elastic_search_status.sh 2>&1 && echo "Elasticsearch is running!"

  # is the kibana process server up and responding to requests?
  if curl -f -XGET "$KIBANA_URL/api/saved_objects/index-pattern/" ; then

    # have we not not already created the index pattern?
    if ! curl -f -XGET "$KIBANA_URL/api/saved_objects/index-pattern/$INDEX_PATTERN_ID" ; then

      echo "Importing Kibana saved objects..."

      # load zeek_template containing zeek field type mappings
      curl -XPOST -H "Content-Type: application/json" "$ES_URL/_template/zeek_template?include_type_name=true" -d "@/data/zeek_template.json"

      # From https://github.com/elastic/kibana/issues/3709
      # Create index pattern
      curl -f -XPOST -H "Content-Type: application/json" -H "kbn-xsrf: anything" \
        "$KIBANA_URL/api/saved_objects/index-pattern/$INDEX_PATTERN_ID" \
        -d"{\"attributes\":{\"title\":\"$INDEX_PATTERN\",\"timeFieldName\":\"$INDEX_TIME_FIELD\"}}"

      # Make it the default index
      curl -XPOST -H "Content-Type: application/json" -H "kbn-xsrf: anything" \
        "$KIBANA_URL/api/kibana/settings/defaultIndex" \
        -d"{\"value\":\"$INDEX_PATTERN_ID\"}"

      # install default dashboards, index patterns, etc.
      for i in /opt/kibana/dashboards/*.json; do
        curl -XPOST "$KIBANA_URL/api/kibana/dashboards/import?force=true" -H 'kbn-xsrf:true' -H 'Content-type:application/json' -d "@$i"
      done

      # set dark theme
      curl -XPOST "$KIBANA_URL/api/kibana/settings/theme:darkMode" -H 'kbn-xsrf:true' -H 'Content-type:application/json' -d '{"value":true}'

      # set default query time range
      curl -XPOST "$KIBANA_URL/api/kibana/settings" -H 'kbn-xsrf:true' -H 'Content-type:application/json' -d \
        '{"changes":{"timepicker:timeDefaults":"{\n  \"from\": \"now-24h\",\n  \"to\": \"now\",\n  \"mode\": \"quick\"}"}}'

      # turn off telemetry
      curl -XPOST "$KIBANA_URL/api/telemetry/v2/optIn" -H 'kbn-xsrf:true' -H 'Content-type:application/json' -d '{"enabled":false}'

      # pin filters by default
      curl -XPOST "$KIBANA_URL/api/kibana/settings/filters:pinnedByDefault" -H 'kbn-xsrf:true' -H 'Content-type:application/json' -d '{"value":true}'
    fi
  fi
fi
