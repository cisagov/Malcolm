#!/bin/bash

# Copyright (c) 2021 Battelle Energy Alliance, LLC.  All rights reserved.

set -euo pipefail
shopt -s nocasematch

if [[ -n $ELASTICSEARCH_URL ]]; then
  ES_URL="$ELASTICSEARCH_URL"
elif [[ -n $ES_HOST ]] && [[ -n $ES_PORT ]]; then
  ES_URL="http://$ES_HOST:$ES_PORT"
else
  ES_URL="http://elasticsearch:9200"
fi

if [[ -n $KIBANA_URL ]]; then
  KIB_URL="$KIBANA_URL"
elif [[ -n $KIBANA_HOST ]] && [[ -n $KIBANA_PORT ]]; then
  KIB_URL="http://$KIBANA_HOST:$KIBANA_PORT"
else
  KIB_URL="http://kibana:5601/kibana"
fi

INDEX_PATTERN=${ARKIME_INDEX_PATTERN:-"sessions2-*"}
INDEX_PATTERN_ID=${ARKIME_INDEX_PATTERN_ID:-"sessions2-*"}
INDEX_TIME_FIELD=${ARKIME_INDEX_TIME_FIELD:-"firstPacket"}

INDEX_POLICY_FILE="/data/init/index-management-policy.json"
INDEX_POLICY_FILE_HOST="/data/index-management-policy.json"
ZEEK_TEMPLATE_FILE="/data/init/zeek_template.json"
ZEEK_TEMPLATE_FILE_ORIG="/data/zeek_template.json"
INDEX_POLICY_NAME=${ISM_POLICY_NAME:-"session_index_policy"}

# is the argument to automatically create this index enabled?
if [[ "$CREATE_ES_ARKIME_SESSION_INDEX" = "true" ]] ; then

  # give Elasticsearch time to start before configuring Kibana
  /data/elastic_search_status.sh >/dev/null 2>&1

  # is the kibana process server up and responding to requests?
  if curl -L --silent --output /dev/null --fail -XGET "$KIB_URL/api/status" ; then

    # have we not not already created the index pattern?
    if ! curl -L --silent --output /dev/null --fail -XGET "$KIB_URL/api/saved_objects/index-pattern/$INDEX_PATTERN_ID" ; then

      echo "Elasticsearch is running! Setting up index management policies..."

      # register the repo location for elasticsearch snapshots
      /data/register-elasticsearch-snapshot-repo.sh

      # tweak the sessions template (sessions2-* zeek template file) to use the index management policy
      if [[ -r "$INDEX_POLICY_FILE_HOST" ]] && (( $(jq length "$INDEX_POLICY_FILE_HOST") > 0 )); then
        # user has provided a file for index management, use it
        cp "$INDEX_POLICY_FILE_HOST" "$INDEX_POLICY_FILE"
        INDEX_POLICY_NAME="$(cat "$INDEX_POLICY_FILE" | jq '..|objects|.policy_id//empty' | tr -d '"')"

      else
        # need to generate index management file based on environment variables
        /data/elastic_index_policy_create.py \
          --policy "$INDEX_POLICY_NAME" \
          --snapshot ${ISM_SNAPSHOT_AGE:-"0"} \
          --cold ${ISM_COLD_AGE:-"0"} \
          --close ${ISM_CLOSE_AGE:-"0"} \
          --delete ${ISM_DELETE_AGE:-"0"} \
        > "$INDEX_POLICY_FILE"
      fi

      if [[ -r "$INDEX_POLICY_FILE" ]]; then
        # make API call to define index management policy
        # https://opendistro.github.io/for-elasticsearch-docs/docs/ism/api/#create-policy
        curl -L --silent --output /dev/null --show-error -XPUT -H "Content-Type: application/json" "$ES_URL/_opendistro/_ism/policies/$INDEX_POLICY_NAME" -d "@$INDEX_POLICY_FILE"

        if [[ -r "$ZEEK_TEMPLATE_FILE_ORIG" ]]; then
          # insert opendistro.index_state_management.policy_id into index template settings: will be
          # imported by kibana-create-moloch-sessions-index.sh
          cat "$ZEEK_TEMPLATE_FILE_ORIG" | jq ".settings += {\"opendistro.index_state_management.policy_id\": \"$INDEX_POLICY_NAME\"}" > "$ZEEK_TEMPLATE_FILE"
        fi
      fi

      echo "Importing Kibana saved objects..."

      # load zeek_template containing zeek field type mappings (merged from /data/zeek_template.json to /data/init/zeek_template.json in kibana_helpers.sh on startup)
      curl -L --silent --output /dev/null --show-error -XPOST -H "Content-Type: application/json" "$ES_URL/_template/zeek_template?include_type_name=true" -d "@$ZEEK_TEMPLATE_FILE"

      # From https://github.com/elastic/kibana/issues/3709
      # Create index pattern
      curl -L --silent --output /dev/null --show-error --fail -XPOST -H "Content-Type: application/json" -H "kbn-xsrf: anything" \
        "$KIB_URL/api/saved_objects/index-pattern/$INDEX_PATTERN_ID" \
        -d"{\"attributes\":{\"title\":\"$INDEX_PATTERN\",\"timeFieldName\":\"$INDEX_TIME_FIELD\"}}"

      # Make it the default index
      curl -L --silent --output /dev/null --show-error -XPOST -H "Content-Type: application/json" -H "kbn-xsrf: anything" \
        "$KIB_URL/api/kibana/settings/defaultIndex" \
        -d"{\"value\":\"$INDEX_PATTERN_ID\"}"

      # install default dashboards, index patterns, etc.
      for i in /opt/kibana/dashboards/*.json; do
        curl -L --silent --output /dev/null --show-error -XPOST "$KIB_URL/api/kibana/dashboards/import?force=true" -H 'kbn-xsrf:true' -H 'Content-type:application/json' -d "@$i"
      done

      # set dark theme
      curl -L --silent --output /dev/null --show-error -XPOST "$KIB_URL/api/kibana/settings/theme:darkMode" -H 'kbn-xsrf:true' -H 'Content-type:application/json' -d '{"value":true}'

      # set default query time range
      curl -L --silent --output /dev/null --show-error -XPOST "$KIB_URL/api/kibana/settings" -H 'kbn-xsrf:true' -H 'Content-type:application/json' -d \
        '{"changes":{"timepicker:timeDefaults":"{\n  \"from\": \"now-24h\",\n  \"to\": \"now\",\n  \"mode\": \"quick\"}"}}'

      # turn off telemetry
      curl -L --silent --output /dev/null --show-error -XPOST "$KIB_URL/api/telemetry/v2/optIn" -H 'kbn-xsrf:true' -H 'Content-type:application/json' -d '{"enabled":false}'

      # pin filters by default
      curl -L --silent --output /dev/null --show-error -XPOST "$KIB_URL/api/kibana/settings/filters:pinnedByDefault" -H 'kbn-xsrf:true' -H 'Content-type:application/json' -d '{"value":true}'

      echo "Kibana saved objects import complete!"
    fi
  fi
fi
