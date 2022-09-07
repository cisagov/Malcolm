#!/bin/bash

# Copyright (c) 2022 Battelle Energy Alliance, LLC.  All rights reserved.

set -euo pipefail
shopt -s nocasematch

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

MALCOLM_TEMPLATES_DIR="/opt/templates"
MALCOLM_TEMPLATE_FILE_ORIG="$MALCOLM_TEMPLATES_DIR/malcolm_template.json"
MALCOLM_TEMPLATE_FILE="/data/init/malcolm_template.json"
DEFAULT_DASHBOARD=${OPENSEARCH_DEFAULT_DASHBOARD:-"0ad3d7c2-3441-485e-9dfe-dbb22e84e576"}

ISM_SNAPSHOT_REPO=${ISM_SNAPSHOT_REPO:-"logs"}
ISM_SNAPSHOT_COMPRESSED=${ISM_SNAPSHOT_COMPRESSED:-"false"}

# is the argument to automatically create this index enabled?
if [[ "$CREATE_OS_ARKIME_SESSION_INDEX" = "true" ]] ; then

  # give OpenSearch time to start before configuring dashboards
  /data/opensearch_status.sh >/dev/null 2>&1

  for LOOP in primary secondary; do

    if [[ "$LOOP" == "primary" ]]; then
      OPENSEARCH_URL_TO_USE=${OPENSEARCH_URL:-"http://opensearch:9200"}
      OPENSEARCH_LOCAL=${OPENSEARCH_LOCAL:-"true"}
      OPENSEARCH_CREDS_CONFIG_FILE_TO_USE=${OPENSEARCH_CREDS_CONFIG_FILE:-"/var/local/opensearch.primary.curlrc"}
      if [[ "$OPENSEARCH_LOCAL" == "false" ]] && [[ -r "$OPENSEARCH_CREDS_CONFIG_FILE_TO_USE" ]]; then
        CURL_CONFIG_PARAMS=(
          --config
          "$OPENSEARCH_CREDS_CONFIG_FILE_TO_USE"
          )
      else
        CURL_CONFIG_PARAMS=()
      fi

    elif [[ "$LOOP" == "secondary" ]] && [[ "${OPENSEARCH_SECONDARY:-"false"}" == "true" ]] && [[ -n "${OPENSEARCH_SECONDARY_URL:-""}" ]]; then
      OPENSEARCH_URL_TO_USE=$OPENSEARCH_SECONDARY_URL
      OPENSEARCH_LOCAL=false
      OPENSEARCH_CREDS_CONFIG_FILE_TO_USE=${OPENSEARCH_SECONDARY_CREDS_CONFIG_FILE:-"/var/local/opensearch.secondary.curlrc"}
      if [[ -r "$OPENSEARCH_CREDS_CONFIG_FILE_TO_USE" ]]; then
        CURL_CONFIG_PARAMS=(
          --config
          "$OPENSEARCH_CREDS_CONFIG_FILE_TO_USE"
          )
      else
        CURL_CONFIG_PARAMS=()
      fi

    else
      continue
    fi

    # is the Dashboards process server up and responding to requests?
    if [[ "$LOOP" != "primary" ]] || curl "${CURL_CONFIG_PARAMS[@]}" -L --silent --output /dev/null --fail -XGET "$DASHB_URL/api/status" ; then

      # have we not not already created the index pattern?
      if [[ "$LOOP" != "primary" ]] || ! curl "${CURL_CONFIG_PARAMS[@]}" -L --silent --output /dev/null --fail -XGET "$DASHB_URL/api/saved_objects/index-pattern/$INDEX_PATTERN_ID" ; then

        echo "OpenSearch ($LOOP) is running at \"${OPENSEARCH_URL_TO_USE}\"!"

        # register the repo name/path for opensearch snapshots (but don't count this an unrecoverable failure)
        if [[ "$LOOP" == "primary" ]] && [[ "$OPENSEARCH_LOCAL" == "true" ]]; then
          echo "Registering index snapshot repository..."
          curl "${CURL_CONFIG_PARAMS[@]}" -w "\n" -H "Accept: application/json" \
            -H "Content-type: application/json" \
            -XPUT -fsSL "$OPENSEARCH_URL_TO_USE/_snapshot/$ISM_SNAPSHOT_REPO" \
            -d "{ \"type\": \"fs\", \"settings\": { \"location\": \"$ISM_SNAPSHOT_REPO\", \"compress\": $ISM_SNAPSHOT_COMPRESSED } }" \
            || true
        fi

        if [[ -d /opt/ecs-templates/composable/component ]]; then
          echo "Importing ECS composable templates..."
          for i in /opt/ecs-templates/composable/component/*.json; do
            TEMP_BASENAME="$(basename "$i")"
            TEMP_FILENAME="${TEMP_BASENAME%.*}"
            echo "Importing ECS composable template $TEMP_FILENAME ..."
            curl "${CURL_CONFIG_PARAMS[@]}" -w "\n" -sSL --fail -XPOST -H "Content-Type: application/json" "$OPENSEARCH_URL_TO_USE/_component_template/ecs_$TEMP_FILENAME" -d "@$i" 2>&1 || true
          done
        fi

        if [[ -d "$MALCOLM_TEMPLATES_DIR"/composable/component ]]; then
          echo "Importing custom ECS composable templates..."
          for i in "$MALCOLM_TEMPLATES_DIR"/composable/component/*.json; do
            TEMP_BASENAME="$(basename "$i")"
            TEMP_FILENAME="${TEMP_BASENAME%.*}"
            echo "Importing custom ECS composable template $TEMP_FILENAME ..."
            curl "${CURL_CONFIG_PARAMS[@]}" -w "\n" -sSL --fail -XPOST -H "Content-Type: application/json" "$OPENSEARCH_URL_TO_USE/_component_template/custom_$TEMP_FILENAME" -d "@$i" 2>&1 || true
          done
        fi

        echo "Importing malcolm_template..."

        if [[ -f "$MALCOLM_TEMPLATE_FILE_ORIG" ]] && [[ ! -f "$MALCOLM_TEMPLATE_FILE" ]]; then
          cp "$MALCOLM_TEMPLATE_FILE_ORIG" "$MALCOLM_TEMPLATE_FILE"
        fi

        # load malcolm_template containing malcolm data source field type mappings (merged from /opt/templates/malcolm_template.json to /data/init/malcolm_template.json in dashboard-helpers on startup)
        curl "${CURL_CONFIG_PARAMS[@]}" -w "\n" -sSL --fail -XPOST -H "Content-Type: application/json" \
          "$OPENSEARCH_URL_TO_USE/_index_template/malcolm_template" -d "@$MALCOLM_TEMPLATE_FILE" 2>&1

        # import other templates as well (and get info for creating their index patterns)
        OTHER_INDEX_PATTERNS=()
        for i in "$MALCOLM_TEMPLATES_DIR"/*.json; do
          TEMP_BASENAME="$(basename "$i")"
          TEMP_FILENAME="${TEMP_BASENAME%.*}"
          if [[ "$TEMP_FILENAME" != "malcolm_template" ]]; then
            echo "Importing template \"$TEMP_FILENAME\"..."
            if curl "${CURL_CONFIG_PARAMS[@]}" -w "\n" -sSL --fail -XPOST -H "Content-Type: application/json" "$OPENSEARCH_URL_TO_USE/_index_template/$TEMP_FILENAME" -d "@$i" 2>&1; then
              for TEMPLATE_INDEX_PATTERN in $(jq '.index_patterns[]' "$i" | tr -d '"'); do
                OTHER_INDEX_PATTERNS+=("$TEMPLATE_INDEX_PATTERN;$TEMPLATE_INDEX_PATTERN;@timestamp")
              done
            fi
          fi
        done

        if [[ "$LOOP" == "primary" ]]; then
          echo "Importing index pattern..."

          # From https://github.com/elastic/kibana/issues/3709
          # Create index pattern
          curl "${CURL_CONFIG_PARAMS[@]}" -w "\n" -sSL --fail -XPOST -H "Content-Type: application/json" -H "osd-xsrf: anything" \
            "$DASHB_URL/api/saved_objects/index-pattern/$INDEX_PATTERN_ID" \
            -d"{\"attributes\":{\"title\":\"$INDEX_PATTERN\",\"timeFieldName\":\"$INDEX_TIME_FIELD\"}}" 2>&1 || true

          echo "Setting default index pattern..."

          # Make it the default index
          curl "${CURL_CONFIG_PARAMS[@]}" -w "\n" -sSL -XPOST -H "Content-Type: application/json" -H "osd-xsrf: anything" \
            "$DASHB_URL/api/opensearch-dashboards/settings/defaultIndex" \
            -d"{\"value\":\"$INDEX_PATTERN_ID\"}" || true

          for i in ${OTHER_INDEX_PATTERNS[@]}; do
            IDX_ID="$(echo "$i" | cut -d';' -f1)"
            IDX_NAME="$(echo "$i" | cut -d';' -f2)"
            IDX_TIME_FIELD="$(echo "$i" | cut -d';' -f3)"
            echo "Creating index pattern \"$IDX_NAME\"..."
            curl "${CURL_CONFIG_PARAMS[@]}" -w "\n" -sSL --fail -XPOST -H "Content-Type: application/json" -H "osd-xsrf: anything" \
              "$DASHB_URL/api/saved_objects/index-pattern/$IDX_ID" \
              -d"{\"attributes\":{\"title\":\"$IDX_NAME\",\"timeFieldName\":\"$IDX_TIME_FIELD\"}}" 2>&1 || true
          done

          echo "Importing OpenSearch Dashboards saved objects..."

          # install default dashboards
          for i in /opt/dashboards/*.json; do
            curl "${CURL_CONFIG_PARAMS[@]}" -L --silent --output /dev/null --show-error -XPOST "$DASHB_URL/api/opensearch-dashboards/dashboards/import?force=true" -H 'osd-xsrf:true' -H 'Content-type:application/json' -d "@$i"
          done

          # beats will no longer import its dashbaords into OpenSearch
          # (see opensearch-project/OpenSearch-Dashboards#656 and
          # opensearch-project/OpenSearch-Dashboards#831). As such, we're going to
          # manually add load our dashboards in /opt/dashboards/beats as well.
          for i in /opt/dashboards/beats/*.json; do
            curl "${CURL_CONFIG_PARAMS[@]}" -L --silent --output /dev/null --show-error -XPOST "$DASHB_URL/api/opensearch-dashboards/dashboards/import?force=true" -H 'osd-xsrf:true' -H 'Content-type:application/json' -d "@$i"
          done

          # set dark theme
          curl "${CURL_CONFIG_PARAMS[@]}" -L --silent --output /dev/null --show-error -XPOST "$DASHB_URL/api/opensearch-dashboards/settings/theme:darkMode" -H 'osd-xsrf:true' -H 'Content-type:application/json' -d '{"value":true}'

          # set default dashboard
          curl "${CURL_CONFIG_PARAMS[@]}" -L --silent --output /dev/null --show-error -XPOST "$DASHB_URL/api/opensearch-dashboards/settings/defaultRoute" -H 'osd-xsrf:true' -H 'Content-type:application/json' -d "{\"value\":\"/app/dashboards#/view/${DEFAULT_DASHBOARD}\"}"

          # set default query time range
          curl "${CURL_CONFIG_PARAMS[@]}" -L --silent --output /dev/null --show-error -XPOST "$DASHB_URL/api/opensearch-dashboards/settings" -H 'osd-xsrf:true' -H 'Content-type:application/json' -d \
            '{"changes":{"timepicker:timeDefaults":"{\n  \"from\": \"now-24h\",\n  \"to\": \"now\",\n  \"mode\": \"quick\"}"}}'

          # turn off telemetry
          curl "${CURL_CONFIG_PARAMS[@]}" -L --silent --output /dev/null --show-error -XPOST "$DASHB_URL/api/telemetry/v2/optIn" -H 'osd-xsrf:true' -H 'Content-type:application/json' -d '{"enabled":false}'

          # pin filters by default
          curl "${CURL_CONFIG_PARAMS[@]}" -L --silent --output /dev/null --show-error -XPOST "$DASHB_URL/api/opensearch-dashboards/settings/filters:pinnedByDefault" -H 'osd-xsrf:true' -H 'Content-type:application/json' -d '{"value":true}'

          echo "OpenSearch Dashboards saved objects import complete!"

          # before we go on to create the anomaly detectors, we need to wait for actual arkime_sessions3-* documents
          /data/opensearch_status.sh -w >/dev/null 2>&1
          sleep 60

          echo "Creating OpenSearch anomaly detectors..."

          # Create anomaly detectors here
          for i in /opt/anomaly_detectors/*.json; do
            curl "${CURL_CONFIG_PARAMS[@]}" -L --silent --output /dev/null --show-error -XPOST "$OPENSEARCH_URL_TO_USE/_plugins/_anomaly_detection/detectors" -H 'osd-xsrf:true' -H 'Content-type:application/json' -d "@$i"
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
            DUMMY_DETECTOR_ID="$(curl "${CURL_CONFIG_PARAMS[@]}" -L --fail --silent --show-error -XPOST "$OPENSEARCH_URL_TO_USE/_plugins/_anomaly_detection/detectors/_search" -H 'osd-xsrf:true' -H 'Content-type:application/json' -d "{ \"query\": { \"match\": { \"name\": \"$DUMMY_DETECTOR_NAME\" } } }" | jq '.. | ._id? // empty' 2>/dev/null | head -n 1 | tr -d '"')"
          done
          set -e
          if [[ -n "$DUMMY_DETECTOR_ID" ]]; then
            curl "${CURL_CONFIG_PARAMS[@]}" -L --silent --output /dev/null --show-error -XPOST "$OPENSEARCH_URL_TO_USE/_plugins/_anomaly_detection/detectors/$DUMMY_DETECTOR_ID/_start" -H 'osd-xsrf:true' -H 'Content-type:application/json'
            sleep 10
            curl "${CURL_CONFIG_PARAMS[@]}" -L --silent --output /dev/null --show-error -XPOST "$OPENSEARCH_URL_TO_USE/_plugins/_anomaly_detection/detectors/$DUMMY_DETECTOR_ID/_stop" -H 'osd-xsrf:true' -H 'Content-type:application/json'
            sleep 10
            curl "${CURL_CONFIG_PARAMS[@]}" -L --silent --output /dev/null --show-error -XDELETE "$OPENSEARCH_URL_TO_USE/_plugins/_anomaly_detection/detectors/$DUMMY_DETECTOR_ID" -H 'osd-xsrf:true' -H 'Content-type:application/json'
          fi

          echo "OpenSearch anomaly detectors creation complete!"

          echo "Creating OpenSearch alerting objects..."

          # Create notification/alerting objects here

          # notification channels
          for i in /opt/notifications/channels/*.json; do
            curl "${CURL_CONFIG_PARAMS[@]}" -L --silent --output /dev/null --show-error -XPOST "$OPENSEARCH_URL_TO_USE/_plugins/_notifications/configs" -H 'osd-xsrf:true' -H 'Content-type:application/json' -d "@$i"
          done

          # monitors
          for i in /opt/alerting/monitors/*.json; do
            curl "${CURL_CONFIG_PARAMS[@]}" -L --silent --output /dev/null --show-error -XPOST "$OPENSEARCH_URL_TO_USE/_plugins/_alerting/monitors" -H 'osd-xsrf:true' -H 'Content-type:application/json' -d "@$i"
          done

          echo "OpenSearch alerting objects creation complete!"

        fi # stuff to only do for primary
      fi # index pattern not already created check
    fi # dashboards is running
  done # primary vs. secondary
fi # CREATE_OS_ARKIME_SESSION_INDEX is true
