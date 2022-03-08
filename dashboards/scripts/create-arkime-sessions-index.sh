#!/bin/bash

# Copyright (c) 2022 Battelle Energy Alliance, LLC.  All rights reserved.

set -euo pipefail
shopt -s nocasematch

if [[ -n $OPENSEARCH_URL ]]; then
  OS_URL="$OPENSEARCH_URL"
elif [[ -n $OS_HOST ]] && [[ -n $OS_PORT ]]; then
  OS_URL="http://$OS_HOST:$OS_PORT"
else
  OS_URL="http://opensearch:9200"
fi

if [[ -n $DASHBOARDS_URL ]]; then
  DASHB_URL="$DASHBOARDS_URL"
elif [[ -n $DASHBOARDS_HOST ]] && [[ -n $DASHBOARDS_PORT ]]; then
  DASHB_URL="http://$DASHBOARDS_HOST:$DASHBOARDS_PORT"
else
  DASHB_URL="http://dashboards:5601/dashboards"
fi

INDEX_PATTERN=${ARKIME_INDEX_PATTERN:-"arkime_sessions3-*"}
INDEX_PATTERN_ID=${ARKIME_INDEX_PATTERN_ID:-"arkime_sessions3-*"}
INDEX_TIME_FIELD=${ARKIME_INDEX_TIME_FIELD:-"firstPacket"}
DUMMY_DETECTOR_NAME=${DUMMY_DETECTOR_NAME:-"malcolm_init_dummy"}
ALERTING_EXAMPLE_DESTINATION_NAME=${ALERTING_EXAMPLE_DESTINATION_NAME:-"Malcolm API Loopback Webhook"}

OTHER_INDEX_PATTERNS=(
  "filebeat-*;filebeat-*;@timestamp"
  "metricbeat-*;metricbeat-*;@timestamp"
  "auditbeat-*;auditbeat-*;@timestamp"
  "packetbeat-*;packetbeat-*;@timestamp"
)

INDEX_POLICY_FILE="/data/init/index-management-policy.json"
INDEX_POLICY_FILE_HOST="/data/index-management-policy.json"
MALCOLM_TEMPLATE_FILE="/data/init/malcolm_template.json"
MALCOLM_TEMPLATE_FILE_ORIG="/data/malcolm_template.json"
INDEX_POLICY_NAME=${ISM_POLICY_NAME:-"session_index_policy"}
DEFAULT_DASHBOARD=${OPENSEARCH_DEFAULT_DASHBOARD:-"0ad3d7c2-3441-485e-9dfe-dbb22e84e576"}

# is the argument to automatically create this index enabled?
if [[ "$CREATE_OS_ARKIME_SESSION_INDEX" = "true" ]] ; then

  # give OpenSearch time to start before configuring dashboards
  /data/opensearch_status.sh >/dev/null 2>&1

  # is the Dashboards process server up and responding to requests?
  if curl -L --silent --output /dev/null --fail -XGET "$DASHB_URL/api/status" ; then

    # have we not not already created the index pattern?
    if ! curl -L --silent --output /dev/null --fail -XGET "$DASHB_URL/api/saved_objects/index-pattern/$INDEX_PATTERN_ID" ; then

      echo "OpenSearch is running! Setting up index management policies..."

      # register the repo location for opensearch snapshots
      /data/register-opensearch-snapshot-repo.sh

      # tweak the sessions template (arkime_sessions3-* template file) to use the index management policy
      if [[ -f "$INDEX_POLICY_FILE_HOST" ]] && (( $(jq length "$INDEX_POLICY_FILE_HOST") > 0 )); then
        # user has provided a file for index management, use it
        cp "$INDEX_POLICY_FILE_HOST" "$INDEX_POLICY_FILE"
        INDEX_POLICY_NAME="$(cat "$INDEX_POLICY_FILE" | jq '..|objects|.policy_id//empty' | tr -d '"')"

      else
        # need to generate index management file based on environment variables
        /data/opensearch_index_policy_create.py \
          --policy "$INDEX_POLICY_NAME" \
          --index-pattern "$INDEX_PATTERN" \
          --priority 100 \
          --snapshot ${ISM_SNAPSHOT_AGE:-"0"} \
          --cold ${ISM_COLD_AGE:-"0"} \
          --close ${ISM_CLOSE_AGE:-"0"} \
          --delete ${ISM_DELETE_AGE:-"0"} \
        > "$INDEX_POLICY_FILE"
      fi

      if [[ -f "$INDEX_POLICY_FILE" ]]; then
        # make API call to define index management policy
        # https://opensearch.org/docs/latest/im-plugin/ism/api/#create-policy
        curl -w "\n" -L --silent --output /dev/null --show-error -XPUT -H "Content-Type: application/json" "$OS_URL/_plugins/_ism/policies/$INDEX_POLICY_NAME" -d "@$INDEX_POLICY_FILE"

        if [[ -f "$MALCOLM_TEMPLATE_FILE_ORIG" ]]; then
          # insert OpenSearch ISM stuff into index template settings
          cat "$MALCOLM_TEMPLATE_FILE_ORIG" | jq ".settings += {\"index.plugins.index_state_management.policy_id\": \"$INDEX_POLICY_NAME\"}" > "$MALCOLM_TEMPLATE_FILE"
        fi
      fi

      echo "Importing malcolm_template..."

      if [[ -f "$MALCOLM_TEMPLATE_FILE_ORIG" ]] && [[ ! -f "$MALCOLM_TEMPLATE_FILE" ]]; then
        cp "$MALCOLM_TEMPLATE_FILE_ORIG" "$MALCOLM_TEMPLATE_FILE"
      fi

      # load malcolm_template containing malcolm data source field type mappings (merged from /data/malcolm_template.json to /data/init/malcolm_template.json in dashboard-helpers on startup)
      curl -w "\n" -sSL --fail -XPOST -H "Content-Type: application/json" \
        "$OS_URL/_template/malcolm_template?include_type_name=true" -d "@$MALCOLM_TEMPLATE_FILE" 2>&1

      echo "Importing index pattern..."

      # From https://github.com/elastic/kibana/issues/3709
      # Create index pattern
      curl -w "\n" -sSL --fail -XPOST -H "Content-Type: application/json" -H "osd-xsrf: anything" \
        "$DASHB_URL/api/saved_objects/index-pattern/$INDEX_PATTERN_ID" \
        -d"{\"attributes\":{\"title\":\"$INDEX_PATTERN\",\"timeFieldName\":\"$INDEX_TIME_FIELD\"}}" 2>&1

      echo "Setting default index pattern..."

      # Make it the default index
      curl -w "\n" -sSL -XPOST -H "Content-Type: application/json" -H "osd-xsrf: anything" \
        "$DASHB_URL/api/opensearch-dashboards/settings/defaultIndex" \
        -d"{\"value\":\"$INDEX_PATTERN_ID\"}"

      echo "Creating other index patterns..."
      for i in ${OTHER_INDEX_PATTERNS[@]}; do
        IDX_ID="$(echo "$i" | cut -d';' -f1)"
        IDX_NAME="$(echo "$i" | cut -d';' -f2)"
        IDX_TIME_FIELD="$(echo "$i" | cut -d';' -f3)"
        curl -w "\n" -sSL --fail -XPOST -H "Content-Type: application/json" -H "osd-xsrf: anything" \
          "$DASHB_URL/api/saved_objects/index-pattern/$IDX_ID" \
          -d"{\"attributes\":{\"title\":\"$IDX_NAME\",\"timeFieldName\":\"$IDX_TIME_FIELD\"}}" 2>&1
      done

      echo "Importing OpenSearch Dashboards saved objects..."

      # install default dashboards, index patterns, etc.
      for i in /opt/dashboards/*.json; do
        curl -L --silent --output /dev/null --show-error -XPOST "$DASHB_URL/api/opensearch-dashboards/dashboards/import?force=true" -H 'osd-xsrf:true' -H 'Content-type:application/json' -d "@$i"
      done
      # At the moment Beats won't import dashboards into OpenSearch dashboards
      # (see opensearch-project/OpenSearch-Dashboards#656 and
      # opensearch-project/OpenSearch-Dashboards#831). As such, we're going to
      # manually add load those dashboards in /opt/dashboards/beats as well.
      for i in /opt/dashboards/beats/*.json; do
        curl -L --silent --output /dev/null --show-error -XPOST "$DASHB_URL/api/opensearch-dashboards/dashboards/import?force=true" -H 'osd-xsrf:true' -H 'Content-type:application/json' -d "@$i"
      done

      # set dark theme
      curl -L --silent --output /dev/null --show-error -XPOST "$DASHB_URL/api/opensearch-dashboards/settings/theme:darkMode" -H 'osd-xsrf:true' -H 'Content-type:application/json' -d '{"value":true}'

      # set default dashboard
      curl -L --silent --output /dev/null --show-error -XPOST "$DASHB_URL/api/opensearch-dashboards/settings/defaultRoute" -H 'osd-xsrf:true' -H 'Content-type:application/json' -d "{\"value\":\"/app/dashboards#/view/${DEFAULT_DASHBOARD}\"}"

      # set default query time range
      curl -L --silent --output /dev/null --show-error -XPOST "$DASHB_URL/api/opensearch-dashboards/settings" -H 'osd-xsrf:true' -H 'Content-type:application/json' -d \
        '{"changes":{"timepicker:timeDefaults":"{\n  \"from\": \"now-24h\",\n  \"to\": \"now\",\n  \"mode\": \"quick\"}"}}'

      # turn off telemetry
      curl -L --silent --output /dev/null --show-error -XPOST "$DASHB_URL/api/telemetry/v2/optIn" -H 'osd-xsrf:true' -H 'Content-type:application/json' -d '{"enabled":false}'

      # pin filters by default
      curl -L --silent --output /dev/null --show-error -XPOST "$DASHB_URL/api/opensearch-dashboards/settings/filters:pinnedByDefault" -H 'osd-xsrf:true' -H 'Content-type:application/json' -d '{"value":true}'

      echo "OpenSearch Dashboards saved objects import complete!"

      # before we go on to create the anomaly detectors, we need to wait for actual arkime_sessions3-* documents
      /data/opensearch_status.sh -w >/dev/null 2>&1
      sleep 60

      echo "Creating OpenSearch anomaly detectors..."

      # Create anomaly detectors here
      for i in /opt/anomaly_detectors/*.json; do
        curl -L --silent --output /dev/null --show-error -XPOST "$OS_URL/_plugins/_anomaly_detection/detectors" -H 'osd-xsrf:true' -H 'Content-type:application/json' -d "@$i"
      done

      # trigger a start/stop for the dummy detector to make sure the .opendistro-anomaly-detection-state index gets created
      # see:
      # - https://github.com/opensearch-project/anomaly-detection-dashboards-plugin/issues/109
      # - https://github.com/opensearch-project/anomaly-detection-dashboards-plugin/issues/155
      # - https://github.com/opensearch-project/anomaly-detection-dashboards-plugin/issues/156
      # - https://discuss.opendistrocommunity.dev/t/errors-opening-anomaly-detection-plugin-for-dashboards-after-creation-via-api/7711
      set +e
      DUMMY_DETECTOR_ID=""
      until [[ -n "$DUMMY_DETECTOR_ID" ]]; do
        sleep 5
        DUMMY_DETECTOR_ID="$(curl -L --fail --silent --show-error -XPOST "$OS_URL/_plugins/_anomaly_detection/detectors/_search" -H 'osd-xsrf:true' -H 'Content-type:application/json' -d "{ \"query\": { \"match\": { \"name\": \"$DUMMY_DETECTOR_NAME\" } } }" | jq '.. | ._id? // empty' 2>/dev/null | head -n 1 | tr -d '"')"
      done
      set -e
      if [[ -n "$DUMMY_DETECTOR_ID" ]]; then
        curl -L --silent --output /dev/null --show-error -XPOST "$OS_URL/_plugins/_anomaly_detection/detectors/$DUMMY_DETECTOR_ID/_start" -H 'osd-xsrf:true' -H 'Content-type:application/json'
        sleep 10
        curl -L --silent --output /dev/null --show-error -XPOST "$OS_URL/_plugins/_anomaly_detection/detectors/$DUMMY_DETECTOR_ID/_stop" -H 'osd-xsrf:true' -H 'Content-type:application/json'
        sleep 10
        curl -L --silent --output /dev/null --show-error -XDELETE "$OS_URL/_plugins/_anomaly_detection/detectors/$DUMMY_DETECTOR_ID" -H 'osd-xsrf:true' -H 'Content-type:application/json'
      fi

      echo "OpenSearch anomaly detectors creation complete!"

      echo "Creating OpenSearch alerting objects..."

      # Create alerting objects here

      # destinations
      for i in /opt/alerting/destinations/*.json; do
        curl -L --silent --output /dev/null --show-error -XPOST "$OS_URL/_plugins/_alerting/destinations" -H 'osd-xsrf:true' -H 'Content-type:application/json' -d "@$i"
      done
      # get example destination ID
      ALERTING_EXAMPLE_DESTINATION_ID=$(curl -L --silent --show-error -XGET -H 'osd-xsrf:true' -H 'Content-type:application/json' \
          "$OS_URL/_plugins/_alerting/destinations" | \
            jq -r ".destinations[] | select(.name == \"$ALERTING_EXAMPLE_DESTINATION_NAME\").id" | \
            head -n 1)

      # monitors
      for i in /opt/alerting/monitors/*.json; do
        if [[ -n "$ALERTING_EXAMPLE_DESTINATION_ID" ]] && \
           grep -q ALERTING_EXAMPLE_DESTINATION_ID "$i"; then
          # replace example destination ID in monitor definition
          TMP_MONITOR_FILENAME="$(mktemp)"
          sed "s/ALERTING_EXAMPLE_DESTINATION_ID/$ALERTING_EXAMPLE_DESTINATION_ID/g" "$i" > "$TMP_MONITOR_FILENAME"
          curl -L --silent --output /dev/null --show-error -XPOST "$OS_URL/_plugins/_alerting/monitors" -H 'osd-xsrf:true' -H 'Content-type:application/json' -d "@$TMP_MONITOR_FILENAME"
          rm -f "$TMP_MONITOR_FILENAME"
        else
          # insert monitor as defined
          curl -L --silent --output /dev/null --show-error -XPOST "$OS_URL/_plugins/_alerting/monitors" -H 'osd-xsrf:true' -H 'Content-type:application/json' -d "@$i"
        fi
      done

      echo "OpenSearch alerting objects creation complete!"

    fi
  fi
fi
