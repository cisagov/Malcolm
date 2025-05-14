#!/bin/bash

# Copyright (c) 2025 Battelle Energy Alliance, LLC.  All rights reserved.

set -euo pipefail
shopt -s nocasematch

DASHB_URL=${DASHBOARDS_URL:-"http://dashboards:5601/dashboards"}
INDEX_PATTERN=${MALCOLM_NETWORK_INDEX_PATTERN:-"arkime_sessions3-*"}
INDEX_ALIAS=${MALCOLM_NETWORK_INDEX_ALIAS:-}
INDEX_DEFAULT_PIPELINE=${MALCOLM_NETWORK_INDEX_DEFAULT_PIPELINE:-}
INDEX_LIFECYCLE_NAME=${MALCOLM_NETWORK_INDEX_LIFECYCLE_NAME:-}
INDEX_LIFECYCLE_ROLLOVER_ALIAS=${MALCOLM_NETWORK_INDEX_LIFECYCLE_ROLLOVER_ALIAS:-}
INDEX_TIME_FIELD=${MALCOLM_NETWORK_INDEX_TIME_FIELD:-"firstPacket"}
OTHER_INDEX_PATTERN=${MALCOLM_OTHER_INDEX_PATTERN:-"malcolm_beats_*"}
OTHER_INDEX_ALIAS=${MALCOLM_OTHER_INDEX_ALIAS:-}
OTHER_INDEX_DEFAULT_PIPELINE=${MALCOLM_OTHER_INDEX_DEFAULT_PIPELINE:-}
OTHER_INDEX_LIFECYCLE_NAME=${MALCOLM_OTHER_INDEX_LIFECYCLE_NAME:-}
OTHER_INDEX_LIFECYCLE_ROLLOVER_ALIAS=${MALCOLM_OTHER_INDEX_LIFECYCLE_ROLLOVER_ALIAS:-}
OTHER_INDEX_TIME_FIELD=${MALCOLM_OTHER_INDEX_TIME_FIELD:-"@timestamp"}
DUMMY_DETECTOR_NAME=${DUMMY_DETECTOR_NAME:-"malcolm_init_dummy"}
DARK_MODE=${DASHBOARDS_DARKMODE:-"true"}
DASHBOARDS_PREFIX=${DASHBOARDS_PREFIX:-}
# trim leading and trailing spaces and remove characters that need JSON-escaping from DASHBOARDS_PREFIX
DASHBOARDS_PREFIX="${DASHBOARDS_PREFIX#"${DASHBOARDS_PREFIX%%[![:space:]]*}"}"
DASHBOARDS_PREFIX="${DASHBOARDS_PREFIX%"${DASHBOARDS_PREFIX##*[![:space:]]}"}"
DASHBOARDS_PREFIX="$(echo "$DASHBOARDS_PREFIX" | tr -d '"\\')"

MALCOLM_TEMPLATES_DIR="/opt/templates"
MALCOLM_TEMPLATE_FILE_ORIG="$MALCOLM_TEMPLATES_DIR/malcolm_template.json"
MALCOLM_TEMPLATE_FILE="/data/init/malcolm_template.json"
DEFAULT_DASHBOARD=${OPENSEARCH_DEFAULT_DASHBOARD:-"0ad3d7c2-3441-485e-9dfe-dbb22e84e576"}

ISM_SNAPSHOT_REPO=${ISM_SNAPSHOT_REPO:-"logs"}
ISM_SNAPSHOT_COMPRESSED=${ISM_SNAPSHOT_COMPRESSED:-"false"}

OPENSEARCH_PRIMARY=${OPENSEARCH_PRIMARY:-"opensearch-local"}
OPENSEARCH_SECONDARY=${OPENSEARCH_SECONDARY:-""}

STARTUP_IMPORT_PERFORMED_FILE=/tmp/shared-objects-created

TMP_WORK_DIR="$(mktemp -d -t shared-object-creation-XXXXXX)"

function cleanup_work_dir {
  rm -rf "$TMP_WORK_DIR"
}

function get_tmp_output_filename {
  mktemp -p "$TMP_WORK_DIR" curl-XXXXXXX
}

function DoReplacersInFile() {
  # Index pattern and time field name may be specified via environment variable, but need
  #   to be reflected in dashboards, templates, anomaly detectors, etc.
  # This function takes a file and performs those and other replacements.
  REPLFILE="$1"
  DATASTORE_TYPE="$2"
  FILE_TYPE="$3"
  if [[ -n "$REPLFILE" ]] && [[ -f "$REPLFILE" ]]; then

    [[ "$FILE_TYPE" == "template" ]] && \
      [[ -n "$INDEX_ALIAS" ]] && \
      grep -q MALCOLM_NETWORK_INDEX_PATTERN_REPLACER "${REPLFILE}" && \
      jq --arg alias "$INDEX_ALIAS" 'if has("template") then .template.aliases = {($alias): {}} else . end' \
        "${REPLFILE}" | sponge "${REPLFILE}"

    [[ "$FILE_TYPE" == "template" ]] && \
      [[ -n "$OTHER_INDEX_ALIAS" ]] && \
      grep -q MALCOLM_OTHER_INDEX_PATTERN_REPLACER "${REPLFILE}" && \
      jq --arg alias "$OTHER_INDEX_ALIAS" 'if has("template") then .template.aliases = {($alias): {}} else . end' \
        "${REPLFILE}" | sponge "${REPLFILE}"

    [[ "$FILE_TYPE" == "template" ]] && \
      [[ -n "$INDEX_DEFAULT_PIPELINE" ]] && \
      grep -q MALCOLM_NETWORK_INDEX_PATTERN_REPLACER "${REPLFILE}" && \
      jq --arg pipeline "$INDEX_DEFAULT_PIPELINE" 'if has("template") then .template.settings.index.default_pipeline = $pipeline else . end' \
        "${REPLFILE}" | sponge "${REPLFILE}"

    [[ "$FILE_TYPE" == "template" ]] && \
      [[ -n "$OTHER_INDEX_DEFAULT_PIPELINE" ]] && \
      grep -q MALCOLM_OTHER_INDEX_PATTERN_REPLACER "${REPLFILE}" && \
      jq --arg pipeline "$OTHER_INDEX_DEFAULT_PIPELINE" 'if has("template") then .template.settings.index.default_pipeline = $pipeline else . end' \
        "${REPLFILE}" | sponge "${REPLFILE}"

    [[ "$DATASTORE_TYPE" == "elasticsearch" ]] && [[ "$FILE_TYPE" == "template" ]] && \
      [[ -n "$INDEX_LIFECYCLE_NAME" ]] && \
      grep -q MALCOLM_NETWORK_INDEX_PATTERN_REPLACER "${REPLFILE}" && \
      jq --arg lifecycle "$INDEX_LIFECYCLE_NAME" 'if has("template") then .template.settings.index["lifecycle.name"] = $lifecycle else . end' \
        "${REPLFILE}" | sponge "${REPLFILE}"

    [[ "$DATASTORE_TYPE" == "elasticsearch" ]] && [[ "$FILE_TYPE" == "template" ]] && \
      [[ -n "$OTHER_INDEX_LIFECYCLE_NAME" ]] && \
      grep -q MALCOLM_OTHER_INDEX_PATTERN_REPLACER "${REPLFILE}" && \
      jq --arg lifecycle "$OTHER_INDEX_LIFECYCLE_NAME" 'if has("template") then .template.settings.index["lifecycle.name"] = $lifecycle else . end' \
        "${REPLFILE}" | sponge "${REPLFILE}"

    [[ "$DATASTORE_TYPE" == "elasticsearch" ]] && [[ "$FILE_TYPE" == "template" ]] && \
      [[ -n "$INDEX_LIFECYCLE_ROLLOVER_ALIAS" ]] && \
      grep -q MALCOLM_NETWORK_INDEX_PATTERN_REPLACER "${REPLFILE}" && \
      jq --arg rollover "$INDEX_LIFECYCLE_ROLLOVER_ALIAS" 'if has("template") then .template.settings.index["lifecycle.rollover_alias"] = $rollover else . end' \
        "${REPLFILE}" | sponge "${REPLFILE}"

    [[ "$DATASTORE_TYPE" == "elasticsearch" ]] && [[ "$FILE_TYPE" == "template" ]] && \
      [[ -n "$OTHER_INDEX_LIFECYCLE_ROLLOVER_ALIAS" ]] && \
      grep -q MALCOLM_OTHER_INDEX_PATTERN_REPLACER "${REPLFILE}" && \
      jq --arg rollover "$OTHER_INDEX_LIFECYCLE_ROLLOVER_ALIAS" 'if has("template") then .template.settings.index["lifecycle.rollover_alias"] = $rollover else . end' \
        "${REPLFILE}" | sponge "${REPLFILE}"

    [[ "$FILE_TYPE" == "sa_mapping" ]] && \
      [[ -z "$INDEX_ALIAS" ]] && \
      grep -q MALCOLM_NETWORK_INDEX_ALIAS_REPLACER "${REPLFILE}" && \
      rm -f "${REPLFILE}"

    [[ "$FILE_TYPE" == "sa_mapping" ]] && \
      [[ -z "$OTHER_INDEX_ALIAS" ]] && \
      grep -q MALCOLM_OTHER_INDEX_ALIAS_REPLACER "${REPLFILE}" && \
      rm -f "${REPLFILE}"

    sed -i "s/MALCOLM_NETWORK_INDEX_PATTERN_REPLACER/${INDEX_PATTERN}/g" "${REPLFILE}" || true
    sed -i "s/MALCOLM_NETWORK_INDEX_TIME_FIELD_REPLACER/${INDEX_TIME_FIELD}/g" "${REPLFILE}" || true
    sed -i "s/MALCOLM_OTHER_INDEX_PATTERN_REPLACER/${OTHER_INDEX_PATTERN}/g" "${REPLFILE}" || true
    sed -i "s/MALCOLM_OTHER_INDEX_TIME_FIELD_REPLACER/${OTHER_INDEX_TIME_FIELD}/g" "${REPLFILE}" || true
    sed -i "s/MALCOLM_NETWORK_INDEX_ALIAS_REPLACER/${INDEX_ALIAS}/g" "${REPLFILE}" || true
    sed -i "s/MALCOLM_OTHER_INDEX_ALIAS_REPLACER/${OTHER_INDEX_ALIAS}/g" "${REPLFILE}" || true

    if [[ "$DATASTORE_TYPE" == "elasticsearch" ]] && [[ "$FILE_TYPE" == "template" ]]; then
      # OpenSearch - flat_object - https://opensearch.org/docs/latest/field-types/supported-field-types/flat-object/
      # Elasticsearch - flattened - https://www.elastic.co/guide/en/elasticsearch/reference/current/flattened.html
      sed -i "s/flat_object/flattened/g" "${REPLFILE}" || true
    fi
  fi
}

function DoReplacersForDir() {
  REPLDIR="$1"
  DATASTORE_TYPE="$2"
  FILE_TYPE="$3"
  if [[ -n "$REPLDIR" ]] && [[ -d "$REPLDIR" ]]; then
    while IFS= read -r fname; do
        DoReplacersInFile "$fname" "$DATASTORE_TYPE" "$FILE_TYPE"
    done < <( find "$REPLDIR"/ -type f 2>/dev/null )
  fi
}

# store in an associative array the id, title, and .updated_at timestamp of a JSON file representing a dashboard
#   arguments:
#     1 - the name of an associative array hash into which to insert the data
#     2 - the filename of the JSON file to check
#     3 - if the timestamp is not found, the fallback timestamp to use
function GetDashboardJsonInfo() {
  local -n RESULT_HASH=$1
  local JSON_FILE_TO_IMPORT="$2"
  local FALLBACK_TIMESTAMP="$3"

  DASHBOARD_TO_IMPORT_BASE="$(basename "$JSON_FILE_TO_IMPORT")"
  DASHBOARD_TO_IMPORT_ID=
  DASHBOARD_TO_IMPORT_TITLE=
  DASHBOARD_TO_IMPORT_TIMESTAMP=

  if [[ -f "$JSON_FILE_TO_IMPORT" ]]; then
    set +e
    DASHBOARD_TO_IMPORT_ID="$(jq -r '.objects[] | select(.type == "dashboard") | .id' < "$JSON_FILE_TO_IMPORT" 2>/dev/null | head -n 1)"
    DASHBOARD_TO_IMPORT_TITLE="$(jq -r '.objects[] | select(.type == "dashboard") | .attributes.title' < "$JSON_FILE_TO_IMPORT" 2>/dev/null | head -n 1)"
    DASHBOARD_TO_IMPORT_TIMESTAMP="$(jq -r '.objects[] | select(.type == "dashboard") | .updated_at' < "$JSON_FILE_TO_IMPORT" 2>/dev/null | sort | tail -n 1)"
    set -e
  fi

  ( [[ -z "${DASHBOARD_TO_IMPORT_ID}" ]] || [[ "${DASHBOARD_TO_IMPORT_ID}" == "null" ]] ) && DASHBOARD_TO_IMPORT_ID="${DASHBOARD_TO_IMPORT_BASE%.*}"
  ( [[ -z "${DASHBOARD_TO_IMPORT_TITLE}" ]] || [[ "${DASHBOARD_TO_IMPORT_TITLE}" == "null" ]] ) && DASHBOARD_TO_IMPORT_TITLE="${DASHBOARD_TO_IMPORT_BASE%.*}"
  ( [[ -z "${DASHBOARD_TO_IMPORT_TIMESTAMP}" ]] || [[ "${DASHBOARD_TO_IMPORT_TIMESTAMP}" == "null" ]] ) && DASHBOARD_TO_IMPORT_TIMESTAMP="$FALLBACK_TIMESTAMP"

  RESULT_HASH["id"]="${DASHBOARD_TO_IMPORT_ID}"
  RESULT_HASH["title"]="${DASHBOARD_TO_IMPORT_TITLE}"
  RESULT_HASH["timestamp"]="${DASHBOARD_TO_IMPORT_TIMESTAMP}"
}

trap cleanup_work_dir EXIT

# is the argument to automatically create this index enabled?
if [[ "${CREATE_OS_ARKIME_SESSION_INDEX:-true}" = "true" ]] ; then

  # give OpenSearch time to start and Arkime to get its own template created before configuring dashboards
  /usr/local/bin/opensearch_status.sh -l arkime_sessions3_template >/dev/null 2>&1

  CURRENT_ISO_UNIX_SECS="$(date -u +%s)"
  CURRENT_ISO_TIMESTAMP="$(date -u +"%Y-%m-%dT%H:%M:%SZ" -d@${CURRENT_ISO_UNIX_SECS} | sed "s/Z$/.000Z/")"
  EPOCH_ISO_TIMESTAMP="$(date -u +"%Y-%m-%dT%H:%M:%SZ" -d @0 | sed "s/Z$/.000Z/")"
  LAST_IMPORT_CHECK_TIME="$(stat -c %Y "${STARTUP_IMPORT_PERFORMED_FILE}" 2>/dev/null || echo '0')"

  for LOOP in primary secondary; do

    if [[ "$LOOP" == "primary" ]]; then
      OPENSEARCH_URL_TO_USE=${OPENSEARCH_URL:-"http://opensearch:9200"}
      OPENSEARCH_CREDS_CONFIG_FILE_TO_USE=${OPENSEARCH_CREDS_CONFIG_FILE:-"/var/local/curlrc/.opensearch.primary.curlrc"}
      if ( [[ "$OPENSEARCH_PRIMARY" == "opensearch-remote" ]] || [[ "$OPENSEARCH_PRIMARY" == "elasticsearch-remote" ]] ) && [[ -r "$OPENSEARCH_CREDS_CONFIG_FILE_TO_USE" ]]; then
        OPENSEARCH_LOCAL=false
        CURL_CONFIG_PARAMS=(
          --config
          "$OPENSEARCH_CREDS_CONFIG_FILE_TO_USE"
          )
      else
        OPENSEARCH_LOCAL=true
        CURL_CONFIG_PARAMS=()

      fi
      DATASTORE_TYPE="$(echo "$OPENSEARCH_PRIMARY" | cut -d- -f1)"

    elif [[ "$LOOP" == "secondary" ]] && ( [[ "$OPENSEARCH_SECONDARY" == "opensearch-remote" ]] || [[ "$OPENSEARCH_SECONDARY" == "elasticsearch-remote" ]] ) && [[ -n "${OPENSEARCH_SECONDARY_URL:-""}" ]]; then
      OPENSEARCH_URL_TO_USE=$OPENSEARCH_SECONDARY_URL
      OPENSEARCH_LOCAL=false
      OPENSEARCH_CREDS_CONFIG_FILE_TO_USE=${OPENSEARCH_SECONDARY_CREDS_CONFIG_FILE:-"/var/local/curlrc/.opensearch.secondary.curlrc"}
      if [[ -r "$OPENSEARCH_CREDS_CONFIG_FILE_TO_USE" ]]; then
        CURL_CONFIG_PARAMS=(
          --config
          "$OPENSEARCH_CREDS_CONFIG_FILE_TO_USE"
          )
      else
        CURL_CONFIG_PARAMS=()
      fi
      DATASTORE_TYPE="$(echo "$OPENSEARCH_SECONDARY" | cut -d- -f1)"

    else
      continue
    fi
    [[ -z "$DATASTORE_TYPE" ]] && DATASTORE_TYPE="opensearch"
    if [[ "$DATASTORE_TYPE" == "elasticsearch" ]]; then
      DASHBOARDS_URI_PATH="kibana"
      XSRF_HEADER="kbn-xsrf"
      ECS_TEMPLATES_DIR=/opt/ecs-templates
    else
      DASHBOARDS_URI_PATH="opensearch-dashboards"
      XSRF_HEADER="osd-xsrf"
      ECS_TEMPLATES_DIR=/opt/ecs-templates-os
    fi

    # is the Dashboards process server up and responding to requests?
    if [[ "$LOOP" != "primary" ]] || curl "${CURL_CONFIG_PARAMS[@]}" --location --silent --output /dev/null --fail -XGET "$DASHB_URL/api/status" ; then

      # has it been a while since we did a full import check (or have we never done one)?
      if [[ "$LOOP" != "primary" ]] || (( (${CURRENT_ISO_UNIX_SECS} - ${LAST_IMPORT_CHECK_TIME}) >= ${CREATE_OS_ARKIME_SESSION_INDEX_CHECK_INTERVAL_SEC:-86400} )); then

        echo "$DATASTORE_TYPE ($LOOP) is running at \"${OPENSEARCH_URL_TO_USE}\"!"

        # register the repo name/path for opensearch snapshots (but don't count this an unrecoverable failure)
        if [[ "$LOOP" == "primary" ]] && [[ "$OPENSEARCH_LOCAL" == "true" ]]; then
          echo "Registering index snapshot repository..."
          CURL_OUT=$(get_tmp_output_filename)
          curl "${CURL_CONFIG_PARAMS[@]}" -H "Accept: application/json" \
            -H "Content-type: application/json" \
            -XPUT --location --fail-with-body --output "$CURL_OUT" --silent "$OPENSEARCH_URL_TO_USE/_snapshot/$ISM_SNAPSHOT_REPO" \
            -d "{ \"type\": \"fs\", \"settings\": { \"location\": \"$ISM_SNAPSHOT_REPO\", \"compress\": $ISM_SNAPSHOT_COMPRESSED } }" \
            || ( cat "$CURL_OUT" && echo )

          # for single-cluster opensearch set cluster-wide default replicas to 0
          echo "Setting number_of_replicas for single-node $DATASTORE_TYPE..."
          CURL_OUT=$(get_tmp_output_filename)
          curl "${CURL_CONFIG_PARAMS[@]}" --location --fail-with-body --output "$CURL_OUT" --silent \
            -XPUT "$OPENSEARCH_URL_TO_USE/_settings" \
            -H "$XSRF_HEADER:true" -H 'Content-type:application/json' \
            -d '{ "index": { "number_of_replicas":0 } }' || ( cat "$CURL_OUT" && echo )
          curl "${CURL_CONFIG_PARAMS[@]}" --location --fail-with-body --output "$CURL_OUT" --silent \
            -XPUT "$OPENSEARCH_URL_TO_USE/_cluster/settings" \
            -H "$XSRF_HEADER:true" -H 'Content-type:application/json' \
            -d '{ "persistent": { "cluster.default_number_of_replicas":0 } }' || ( cat "$CURL_OUT" && echo )
        fi

        #############################################################################################################################
        # Templates
        #   - a sha256 sum of the combined templates is calculated and the templates are imported if the previously stored hash
        #     (if any) does not match the files we see currently.

        TEMPLATES_IMPORTED=false
        TEMPLATES_IMPORT_DIR="$(mktemp -p "$TMP_WORK_DIR" -d -t templates-XXXXXX)"
        rsync -a "$MALCOLM_TEMPLATES_DIR"/ "$TEMPLATES_IMPORT_DIR"/
        DoReplacersForDir "$TEMPLATES_IMPORT_DIR" "$DATASTORE_TYPE" template
        MALCOLM_TEMPLATE_FILE_ORIG_TMP="$(echo "$MALCOLM_TEMPLATE_FILE_ORIG" | sed "s@$MALCOLM_TEMPLATES_DIR@$TEMPLATES_IMPORT_DIR@")"

        # calculate combined SHA sum of all templates to save as _meta.hash to determine if
        # we need to do this import (mostly useful for the secondary loop)
        TEMPLATE_HASH="$(find "$ECS_TEMPLATES_DIR"/composable "$TEMPLATES_IMPORT_DIR" -type f -name "*.json" -size +2c 2>/dev/null | sort | xargs -r cat | sha256sum | awk '{print $1}')"

        # get the previous stored template hash (if any) to avoid importing if it's already been imported
        set +e
        TEMPLATE_HASH_OLD="$(curl "${CURL_CONFIG_PARAMS[@]}" --location --fail --silent -XGET -H "Content-Type: application/json" "$OPENSEARCH_URL_TO_USE/_index_template/malcolm_template" 2>/dev/null | jq --raw-output '.index_templates[]|select(.name=="malcolm_template")|.index_template._meta.hash' 2>/dev/null)"
        set -e

        # proceed only if the current template HASH doesn't match the previously imported one, or if there
        # was an error calculating or storing either
        if [[ "$TEMPLATE_HASH" != "$TEMPLATE_HASH_OLD" ]] || [[ -z "$TEMPLATE_HASH_OLD" ]] || [[ -z "$TEMPLATE_HASH" ]]; then

          if [[ -d "$ECS_TEMPLATES_DIR"/composable/component ]]; then
            echo "Importing ECS composable templates..."
            for i in "$ECS_TEMPLATES_DIR"/composable/component/*.json; do
              TEMP_BASENAME="$(basename "$i")"
              TEMP_FILENAME="${TEMP_BASENAME%.*}"
              echo "Importing ECS composable template $TEMP_FILENAME ..."
              CURL_OUT=$(get_tmp_output_filename)
              curl "${CURL_CONFIG_PARAMS[@]}" --location --fail-with-body --output "$CURL_OUT" --silent -XPOST -H "Content-Type: application/json" \
                "$OPENSEARCH_URL_TO_USE/_component_template/ecs_$TEMP_FILENAME" -d "@$i" || ( cat "$CURL_OUT" && echo )
            done
          fi

          if [[ -d "$TEMPLATES_IMPORT_DIR"/composable/component ]]; then
            echo "Importing custom ECS composable templates..."
            for i in "$TEMPLATES_IMPORT_DIR"/composable/component/*.json; do
              TEMP_BASENAME="$(basename "$i")"
              TEMP_FILENAME="${TEMP_BASENAME%.*}"
              echo "Importing custom ECS composable template $TEMP_FILENAME ..."
              CURL_OUT=$(get_tmp_output_filename)
              curl "${CURL_CONFIG_PARAMS[@]}" --location --fail-with-body --output "$CURL_OUT" --silent -XPOST -H "Content-Type: application/json" \
                "$OPENSEARCH_URL_TO_USE/_component_template/custom_$TEMP_FILENAME" -d "@$i" || ( cat "$CURL_OUT" && echo )
            done
          fi

          echo "Importing malcolm_template ($TEMPLATE_HASH)..."

          if [[ -f "$MALCOLM_TEMPLATE_FILE_ORIG_TMP" ]] && [[ ! -f "$MALCOLM_TEMPLATE_FILE" ]]; then
            cp "$MALCOLM_TEMPLATE_FILE_ORIG_TMP" "$MALCOLM_TEMPLATE_FILE"
          fi

          # store the TEMPLATE_HASH we calculated earlier as the _meta.hash for the malcolm template
          MALCOLM_TEMPLATE_FILE_TEMP="$(mktemp -p "$TMP_WORK_DIR")"
          ( jq "._meta.hash=\"$TEMPLATE_HASH\"" "$MALCOLM_TEMPLATE_FILE" >"$MALCOLM_TEMPLATE_FILE_TEMP" 2>/dev/null ) && \
            [[ -s "$MALCOLM_TEMPLATE_FILE_TEMP" ]] && \
            cp -f "$MALCOLM_TEMPLATE_FILE_TEMP" "$MALCOLM_TEMPLATE_FILE"

          # load malcolm_template containing malcolm data source field type mappings (merged from /opt/templates/malcolm_template.json to /data/init/malcolm_template.json in dashboard-helpers on startup)
          CURL_OUT=$(get_tmp_output_filename)
          curl "${CURL_CONFIG_PARAMS[@]}" --location --fail-with-body --output "$CURL_OUT" --silent -XPOST -H "Content-Type: application/json" \
            "$OPENSEARCH_URL_TO_USE/_index_template/malcolm_template" -d "@$MALCOLM_TEMPLATE_FILE" || ( cat "$CURL_OUT" && echo && false )

          # import other templates as well
          for i in "$TEMPLATES_IMPORT_DIR"/*.json; do
            TEMP_BASENAME="$(basename "$i")"
            TEMP_FILENAME="${TEMP_BASENAME%.*}"
            if [[ "$TEMP_FILENAME" != "malcolm_template" ]]; then
              echo "Importing template \"$TEMP_FILENAME\"..."
              CURL_OUT=$(get_tmp_output_filename)
              curl "${CURL_CONFIG_PARAMS[@]}" --location --fail-with-body --output "$CURL_OUT" --silent -XPOST -H "Content-Type: application/json" \
                "$OPENSEARCH_URL_TO_USE/_index_template/$TEMP_FILENAME" -d "@$i" || ( cat "$CURL_OUT" && echo )
            fi
          done

          TEMPLATES_IMPORTED=true

        else
          echo "malcolm_template ($TEMPLATE_HASH) already exists ($LOOP) at \"${OPENSEARCH_URL_TO_USE}\""
        fi # TEMPLATE_HASH check

        # get info for creating the index patterns of "other" templates
        OTHER_INDEX_PATTERNS=()
        for i in "$TEMPLATES_IMPORT_DIR"/*.json; do
          TEMP_BASENAME="$(basename "$i")"
          TEMP_FILENAME="${TEMP_BASENAME%.*}"
          if [[ "$TEMP_FILENAME" != "malcolm_template" ]]; then
            for TEMPLATE_INDEX_PATTERN in $(jq -r '.index_patterns[]' "$i"); do
              OTHER_INDEX_PATTERNS+=("$TEMPLATE_INDEX_PATTERN;$TEMPLATE_INDEX_PATTERN;@timestamp")
            done
          fi
        done

        # end Templates
        #############################################################################################################################

        if [[ "$LOOP" == "primary" ]]; then

          #############################################################################################################################
          # Index pattern(s)
          #   - Only set overwrite=true if we actually updated the templates above, otherwise overwrite=false and fail silently
          #     if they already exist (http result code 409)
          echo "Importing index pattern..."
          [[ "${TEMPLATES_IMPORTED}" == "true" ]] && SHOW_IMPORT_ERROR="--show-error" || SHOW_IMPORT_ERROR=

          # Save off any custom field formatting prior to an overwrite
          MALCOLM_FIELD_FORMAT_MAP_FILE_TEMP="$(mktemp -p "$TMP_WORK_DIR")"
          ( curl "${CURL_CONFIG_PARAMS[@]}" --silent --location --fail -XGET -H "Content-Type: application/json" -H "$XSRF_HEADER: anything" \
                 "$DASHB_URL/api/saved_objects/index-pattern/${INDEX_PATTERN}" 2>/dev/null | \
                 jq -r '.attributes.fieldFormatMap' 2>/dev/null | \
                 jq -c 'with_entries(.value.params.parsedUrl? = null | del(.value.params.parsedUrl))' 2>/dev/null | \
                 jq '@json' >"$MALCOLM_FIELD_FORMAT_MAP_FILE_TEMP" 2>/dev/null ) || true
          MALCOLM_FIELD_FORMAT_MAP_FILE_SIZE=$(stat -c%s "$MALCOLM_FIELD_FORMAT_MAP_FILE_TEMP")

          # Create index pattern (preserving custom field formatting)
          MALCOLM_INDEX_PATTERN_FILE_TEMP="$(mktemp -p "$TMP_WORK_DIR")"
          echo "{\"attributes\":{\"title\":\"$INDEX_PATTERN\",\"timeFieldName\":\"$INDEX_TIME_FIELD\"}}" > "$MALCOLM_INDEX_PATTERN_FILE_TEMP"
          if (( $MALCOLM_FIELD_FORMAT_MAP_FILE_SIZE > 64 )); then
            echo "Preserving existing field formatting for \"$INDEX_PATTERN\"..."
            jq --slurpfile fieldFormatMap "$MALCOLM_FIELD_FORMAT_MAP_FILE_TEMP" '.attributes.fieldFormatMap = $fieldFormatMap[0]' "$MALCOLM_INDEX_PATTERN_FILE_TEMP" | sponge "$MALCOLM_INDEX_PATTERN_FILE_TEMP"
          fi
          echo "Creating index pattern \"$INDEX_PATTERN\"..."
          CURL_OUT=$(get_tmp_output_filename)
          curl "${CURL_CONFIG_PARAMS[@]}" --location --fail-with-body --output "$CURL_OUT" --silent ${SHOW_IMPORT_ERROR} -XPOST -H "Content-Type: application/json" -H "$XSRF_HEADER: anything" \
            "$DASHB_URL/api/saved_objects/index-pattern/${INDEX_PATTERN}?overwrite=${TEMPLATES_IMPORTED}" \
            -d @"$MALCOLM_INDEX_PATTERN_FILE_TEMP" || ( cat "$CURL_OUT" && echo )

          echo "Setting default index pattern..."

          # Make it the default index
          CURL_OUT=$(get_tmp_output_filename)
          curl "${CURL_CONFIG_PARAMS[@]}" --location --fail-with-body --output "$CURL_OUT" --silent ${SHOW_IMPORT_ERROR} -XPOST -H "Content-Type: application/json" -H "$XSRF_HEADER: anything" \
            "$DASHB_URL/api/$DASHBOARDS_URI_PATH/settings/defaultIndex" \
            -d"{\"value\":\"$INDEX_PATTERN\"}" || ( cat "$CURL_OUT" && echo )

          # import other index patterns from other templates discovered above
          for i in ${OTHER_INDEX_PATTERNS[@]}; do
            IDX_ID="$(echo "$i" | cut -d';' -f1)"
            IDX_NAME="$(echo "$i" | cut -d';' -f2)"
            IDX_TIME_FIELD="$(echo "$i" | cut -d';' -f3)"

            # Save off any custom field formatting prior to an overwrite
            MALCOLM_FIELD_FORMAT_MAP_FILE_TEMP="$(mktemp -p "$TMP_WORK_DIR")"
            ( curl "${CURL_CONFIG_PARAMS[@]}" --silent --location --fail -XGET -H "Content-Type: application/json" -H "$XSRF_HEADER: anything" \
                   "$DASHB_URL/api/saved_objects/index-pattern/${IDX_ID}" 2>/dev/null | \
                   jq -r '.attributes.fieldFormatMap' 2>/dev/null | \
                   jq -c 'with_entries(.value.params.parsedUrl? = null | del(.value.params.parsedUrl))' 2>/dev/null | \
                   jq '@json' >"$MALCOLM_FIELD_FORMAT_MAP_FILE_TEMP" 2>/dev/null ) || true
            MALCOLM_FIELD_FORMAT_MAP_FILE_SIZE=$(stat -c%s "$MALCOLM_FIELD_FORMAT_MAP_FILE_TEMP")

            MALCOLM_INDEX_PATTERN_FILE_TEMP="$(mktemp -p "$TMP_WORK_DIR")"
            echo "{\"attributes\":{\"title\":\"$IDX_NAME\",\"timeFieldName\":\"$IDX_TIME_FIELD\"}}" > "$MALCOLM_INDEX_PATTERN_FILE_TEMP"
            if (( $MALCOLM_FIELD_FORMAT_MAP_FILE_SIZE > 64 )); then
              echo "Preserving existing field formatting for \"$IDX_NAME\"..."
              jq --slurpfile fieldFormatMap "$MALCOLM_FIELD_FORMAT_MAP_FILE_TEMP" '.attributes.fieldFormatMap = $fieldFormatMap[0]' "$MALCOLM_INDEX_PATTERN_FILE_TEMP" | sponge "$MALCOLM_INDEX_PATTERN_FILE_TEMP"
            fi

            echo "Creating index pattern \"$IDX_NAME\"..."
            CURL_OUT=$(get_tmp_output_filename)
            curl "${CURL_CONFIG_PARAMS[@]}" --location --fail-with-body --output "$CURL_OUT" --silent ${SHOW_IMPORT_ERROR} -XPOST -H "Content-Type: application/json" -H "$XSRF_HEADER: anything" \
              "$DASHB_URL/api/saved_objects/index-pattern/${IDX_ID}?overwrite=${TEMPLATES_IMPORTED}" \
              -d @"$MALCOLM_INDEX_PATTERN_FILE_TEMP" || ( cat "$CURL_OUT" && echo )
          done # i in OTHER_INDEX_PATTERNS

          # end Index pattern
          #############################################################################################################################

          echo "Importing $DATASTORE_TYPE Dashboards saved objects..."

          #############################################################################################################################
          # Dashboards
          #   - Dashboard JSON files have an .updated_at field with an ISO 8601-formatted date (e.g., "2024-04-29T15:49:16.000Z").
          #     For each dashboard, query to see if the object exists and get the .updated_at field for the .type == "dashboard"
          #     objects. If the dashboard doesn't already exist, or if the file-to-be-imported date is newer than the old one,
          #     then import the dashboard.

          DASHBOARDS_IMPORT_DIR="$(mktemp -p "$TMP_WORK_DIR" -d -t dashboards-XXXXXX)"
          rsync -a /opt/dashboards/ "$DASHBOARDS_IMPORT_DIR"/
          DoReplacersForDir "$DASHBOARDS_IMPORT_DIR" "$DATASTORE_TYPE" dashboard
          for i in "${DASHBOARDS_IMPORT_DIR}"/*.json; do

            # get info about the dashboard to be imported
            declare -A NEW_DASHBOARD_INFO
            GetDashboardJsonInfo NEW_DASHBOARD_INFO "$i" "$CURRENT_ISO_TIMESTAMP"

            # get the old dashboard JSON and its info
            curl "${CURL_CONFIG_PARAMS[@]}" --location --fail --silent --output "${i}_old" \
              -XGET "$DASHB_URL/api/$DASHBOARDS_URI_PATH/dashboards/export?dashboard=$DASHBOARD_TO_IMPORT_ID" \
              -H "$XSRF_HEADER:true" -H 'Content-type:application/json' || true
            declare -A OLD_DASHBOARD_INFO
            GetDashboardJsonInfo OLD_DASHBOARD_INFO "${i}_old" "$EPOCH_ISO_TIMESTAMP"
            rm -f "${i}_old"

            # compare the timestamps and import if it's newer
            if [[ "${NEW_DASHBOARD_INFO["timestamp"]}" > "${OLD_DASHBOARD_INFO["timestamp"]}" ]]; then
              if [[ "$DATASTORE_TYPE" == "elasticsearch" ]]; then
                # strip out Arkime and NetBox links from dashboards' navigation pane when doing Kibana import (idaholab/Malcolm#286)
                sed -i 's/  \\\\n\[↪ NetBox\](\/netbox\/)  \\\\n\[↪ Arkime\](\/arkime)//' "$i"
                # take care of a few other substitutions
                sed -i 's/opensearchDashboardsAddFilter/kibanaAddFilter/g' "$i"
              fi
              # prepend $DASHBOARDS_PREFIX to dashboards' titles
              [[ -n "$DASHBOARDS_PREFIX" ]] && jq ".objects |= map(if .type == \"dashboard\" then .attributes.title |= \"${DASHBOARDS_PREFIX} \" + . else . end)" < "$i" | sponge "$i"
              # import the dashboard
              echo "Importing dashboard \"${NEW_DASHBOARD_INFO["title"]}\" (${NEW_DASHBOARD_INFO["timestamp"]} > ${OLD_DASHBOARD_INFO["timestamp"]}) ..."
              CURL_OUT=$(get_tmp_output_filename)
              curl "${CURL_CONFIG_PARAMS[@]}" --location --fail-with-body --output "$CURL_OUT" --silent \
                -XPOST "$DASHB_URL/api/$DASHBOARDS_URI_PATH/dashboards/import?force=true" \
                -H "$XSRF_HEADER:true" -H 'Content-type:application/json' -d "@$i" || ( cat "$CURL_OUT" && echo )
            fi # timestamp check
          done

          # beats will no longer import its dashboards into OpenSearch
          # (see opensearch-project/OpenSearch-Dashboards#656 and
          # opensearch-project/OpenSearch-Dashboards#831). As such, we're going to
          # manually add load our dashboards in /opt/dashboards/beats as well.
          BEATS_DASHBOARDS_IMPORT_DIR="$(mktemp -p "$TMP_WORK_DIR" -d -t beats-XXXXXX)"
          rsync -a /opt/dashboards/beats/ "$BEATS_DASHBOARDS_IMPORT_DIR"/
          DoReplacersForDir "$BEATS_DASHBOARDS_IMPORT_DIR" "$DATASTORE_TYPE" dashboard
          for i in "${BEATS_DASHBOARDS_IMPORT_DIR}"/*.json; do

            # get info about the dashboard to be imported
            declare -A NEW_DASHBOARD_INFO
            GetDashboardJsonInfo NEW_DASHBOARD_INFO "$i" "$CURRENT_ISO_TIMESTAMP"

            # get the old dashboard JSON and its info
            curl "${CURL_CONFIG_PARAMS[@]}" --location --fail --silent --output "${i}_old" \
              -XGET "$DASHB_URL/api/$DASHBOARDS_URI_PATH/dashboards/export?dashboard=$DASHBOARD_TO_IMPORT_ID" \
              -H "$XSRF_HEADER:true" -H 'Content-type:application/json' || true
            declare -A OLD_DASHBOARD_INFO
            GetDashboardJsonInfo OLD_DASHBOARD_INFO "${i}_old" "$EPOCH_ISO_TIMESTAMP"
            rm -f "${i}_old"

            # compare the timestamps and import if it's newer
            if [[ "${NEW_DASHBOARD_INFO["timestamp"]}" > "${OLD_DASHBOARD_INFO["timestamp"]}" ]]; then
              # prepend $DASHBOARDS_PREFIX to dashboards' titles
              [[ -n "$DASHBOARDS_PREFIX" ]] && jq ".objects |= map(if .type == \"dashboard\" then .attributes.title |= \"${DASHBOARDS_PREFIX} \" + . else . end)" < "$i" | sponge "$i"
              # import the dashboard
              echo "Importing dashboard \"${NEW_DASHBOARD_INFO["title"]}\" (${NEW_DASHBOARD_INFO["timestamp"]} > ${OLD_DASHBOARD_INFO["timestamp"]}) ..."
              CURL_OUT=$(get_tmp_output_filename)
              curl "${CURL_CONFIG_PARAMS[@]}" --location --fail-with-body --output "$CURL_OUT" --silent \
                -XPOST "$DASHB_URL/api/$DASHBOARDS_URI_PATH/dashboards/import?force=true" \
                -H "$XSRF_HEADER:true" -H 'Content-type:application/json' -d "@$i" || ( cat "$CURL_OUT" && echo )
            fi # timestamp check
          done

          echo "$DATASTORE_TYPE Dashboards saved objects import complete!"

          # end Dashboards
          #############################################################################################################################

          if [[ "$DATASTORE_TYPE" == "opensearch" ]]; then
            # some features and tweaks like anomaly detection, alerting, etc. only exist in opensearch

            #############################################################################################################################
            # OpenSearch Tweaks

            # set dark theme (or not)
            echo "Setting $DATASTORE_TYPE dark mode ($DARK_MODE)..."
            [[ "$DARK_MODE" == "true" ]] && DARK_MODE_ARG='{"value":true}' || DARK_MODE_ARG='{"value":false}'
            CURL_OUT=$(get_tmp_output_filename)
            curl "${CURL_CONFIG_PARAMS[@]}" --location --fail-with-body --output "$CURL_OUT" --silent \
              -XPOST "$DASHB_URL/api/$DASHBOARDS_URI_PATH/settings/theme:darkMode" \
              -H "$XSRF_HEADER:true" -H 'Content-type:application/json' -d "$DARK_MODE_ARG" || ( cat "$CURL_OUT" && echo )

            # set default dashboard
            echo "Setting $DATASTORE_TYPE default dashboard ($DEFAULT_DASHBOARD)..."
            CURL_OUT=$(get_tmp_output_filename)
            curl "${CURL_CONFIG_PARAMS[@]}" --location --fail-with-body --output "$CURL_OUT" --silent \
              -XPOST "$DASHB_URL/api/$DASHBOARDS_URI_PATH/settings/defaultRoute" \
              -H "$XSRF_HEADER:true" -H 'Content-type:application/json' \
              -d "{\"value\":\"/app/dashboards#/view/${DEFAULT_DASHBOARD}\"}" || ( cat "$CURL_OUT" && echo )

            # pin filters by default
            echo "Setting $DATASTORE_TYPE to pin dashboard filters by default..."
            CURL_OUT=$(get_tmp_output_filename)
            curl "${CURL_CONFIG_PARAMS[@]}" --location --fail-with-body --output "$CURL_OUT" --silent \
              -XPOST "$DASHB_URL/api/$DASHBOARDS_URI_PATH/settings/filters:pinnedByDefault" \
                -H "$XSRF_HEADER:true" -H 'Content-type:application/json' \
                -d '{"value":true}' || ( cat "$CURL_OUT" && echo )

            # enable in-session storage
            echo "Enabled $DATASTORE_TYPE in-session storage for dashboards..."
            CURL_OUT=$(get_tmp_output_filename)
            curl "${CURL_CONFIG_PARAMS[@]}" --location --fail-with-body --output "$CURL_OUT" --silent \
              -XPOST "$DASHB_URL/api/$DASHBOARDS_URI_PATH/settings/state:storeInSessionStorage" \
              -H "$XSRF_HEADER:true" -H 'Content-type:application/json' \
              -d '{"value":true}' || ( cat "$CURL_OUT" && echo )

            # end OpenSearch Tweaks
            #############################################################################################################################
            
            # OpenSearch Create Initial Indices

            CURL_OUT=$(get_tmp_output_filename)
            curl "${CURL_CONFIG_PARAMS[@]}" --location --fail-with-body --output "$CURL_OUT" --silent \
              -XPUT "$OPENSEARCH_URL_TO_USE/${MALCOLM_NETWORK_INDEX_PATTERN%?}initial" \
              -H "$XSRF_HEADER:true" -H 'Content-type:application/json' || ( cat "$CURL_OUT" && echo )

            CURL_OUT=$(get_tmp_output_filename)
            curl "${CURL_CONFIG_PARAMS[@]}" --location --fail-with-body --output "$CURL_OUT" --silent \
              -XPUT "$OPENSEARCH_URL_TO_USE/${MALCOLM_OTHER_INDEX_PATTERN%?}initial" \
              -H "$XSRF_HEADER:true" -H 'Content-type:application/json' || ( cat "$CURL_OUT" && echo )

            # before we go on to create the anomaly detectors, we need to wait for actual network log documents
            /usr/local/bin/opensearch_status.sh -w >/dev/null 2>&1
            sleep 60

            #############################################################################################################################
            # OpenSearch anomaly detectors
            #   - the .anomaly_detector.last_update_time field in the anomaly detector definition JSON is used to check
            #     whether or not the anomaly detector needs to be updated

            echo "Creating $DATASTORE_TYPE anomaly detectors..."

            # If the detectors have never been started before, we need to import the "dummy" one,
            #   but only this first time, not on subsequent runs of this script. We can do that
            #   by checking for the existence of the .opendistro-anomaly-detection-state index.
            curl "${CURL_CONFIG_PARAMS[@]}" --head --location --fail --silent --output /dev/null \
              "$OPENSEARCH_URL_TO_USE"/.opendistro-anomaly-detection-state && \
              DETECTORS_STARTED=1 || \
              DETECTORS_STARTED=0

            # Create anomaly detectors here
            ANOMALY_IMPORT_DIR="$(mktemp -p "$TMP_WORK_DIR" -d -t anomaly-XXXXXX)"
            rsync -a /opt/anomaly_detectors/ "$ANOMALY_IMPORT_DIR"/
            DoReplacersForDir "$ANOMALY_IMPORT_DIR" "$DATASTORE_TYPE" anomaly_detector
            for i in "${ANOMALY_IMPORT_DIR}"/*.json; do
              # identify the name of the anomaly detector, and, if it already exists, its
              #   ID and previous update time, as well as the update time of the file to import
              set +e
              DETECTOR_NAME="$(jq -r '.name' 2>/dev/null < "$i")"

              DETECTOR_NEW_UPDATE_TIME="$(jq -r '.anomaly_detector.last_update_time' 2>/dev/null < "$i")"
              ( [[ -z "${DETECTOR_NEW_UPDATE_TIME}" ]] || [[ "${DETECTOR_NEW_UPDATE_TIME}" == "null" ]] ) && DETECTOR_NEW_UPDATE_TIME=$CURRENT_ISO_UNIX_SECS

              DETECTOR_EXISTING_UPDATE_TIME=0
              DETECTOR_EXISTING_ID="$(curl "${CURL_CONFIG_PARAMS[@]}" --location --fail --silent -XPOST "$OPENSEARCH_URL_TO_USE/_plugins/_anomaly_detection/detectors/_search" -H "$XSRF_HEADER:true" -H 'Content-type:application/json' -d "{ \"query\": { \"match\": { \"name\": \"$DETECTOR_NAME\" } } }" | jq '.. | ._id? // empty' 2>/dev/null | head -n 1 | tr -d '"')"
              if [[ -n "${DETECTOR_EXISTING_ID}" ]]; then
                DETECTOR_EXISTING_UPDATE_TIME="$(curl "${CURL_CONFIG_PARAMS[@]}" --location --fail --silent -XGET "$OPENSEARCH_URL_TO_USE/_plugins/_anomaly_detection/detectors/$DETECTOR_EXISTING_ID" -H "$XSRF_HEADER:true" -H 'Content-type:application/json' | jq -r '.anomaly_detector.last_update_time')"
                ( [[ -z "${DETECTOR_EXISTING_UPDATE_TIME}" ]] || [[ "${DETECTOR_EXISTING_UPDATE_TIME}" == "null" ]] ) && DETECTOR_EXISTING_UPDATE_TIME=0
              fi
              set -e

              # if the file to import is newer than the existing anomaly detector, then update it
              if (( $DETECTOR_NEW_UPDATE_TIME > $DETECTOR_EXISTING_UPDATE_TIME )); then

                # Import the anomaly detector
                ( [[ $DETECTORS_STARTED == 0 ]] || [[ "$DETECTOR_NAME" != "$DUMMY_DETECTOR_NAME" ]] ) && \
                  echo "Importing detector \"${DETECTOR_NAME}\" ($DETECTOR_NEW_UPDATE_TIME > $DETECTOR_EXISTING_UPDATE_TIME) ..." && \
                  CURL_OUT=$(get_tmp_output_filename)
                  curl "${CURL_CONFIG_PARAMS[@]}" --location --fail-with-body --output "$CURL_OUT" --silent \
                    -XPOST "$OPENSEARCH_URL_TO_USE/_plugins/_anomaly_detection/detectors" \
                    -H "$XSRF_HEADER:true" -H 'Content-type:application/json' \
                    -d "@$i" || ( cat "$CURL_OUT" && echo )
              fi
            done

            # Trigger a start/stop for the dummy detector to make sure the .opendistro-anomaly-detection-state index gets created
            # see:
            # - https://github.com/opensearch-project/anomaly-detection-dashboards-plugin/issues/109
            # - https://github.com/opensearch-project/anomaly-detection-dashboards-plugin/issues/155
            # - https://github.com/opensearch-project/anomaly-detection-dashboards-plugin/issues/156
            # - https://discuss.opendistrocommunity.dev/t/errors-opening-anomaly-detection-plugin-for-dashboards-after-creation-via-api/7711
            if [[ $DETECTORS_STARTED == 0 ]]; then
              set +e
              DUMMY_DETECTOR_ID=""
              until [[ -n "$DUMMY_DETECTOR_ID" ]]; do
                sleep 5
                DUMMY_DETECTOR_ID="$(curl "${CURL_CONFIG_PARAMS[@]}" --location --fail --silent -XPOST "$OPENSEARCH_URL_TO_USE/_plugins/_anomaly_detection/detectors/_search" -H "$XSRF_HEADER:true" -H 'Content-type:application/json' -d "{ \"query\": { \"match\": { \"name\": \"$DUMMY_DETECTOR_NAME\" } } }" | jq '.. | ._id? // empty' 2>/dev/null | head -n 1 | tr -d '"')"
              done
              set -e
              if [[ -n "$DUMMY_DETECTOR_ID" ]]; then
                echo "Starting $DUMMY_DETECTOR_NAME to initialize anomaly detector engine..."
                CURL_OUT=$(get_tmp_output_filename)
                curl "${CURL_CONFIG_PARAMS[@]}" --location --fail-with-body --output "$CURL_OUT" --silent -XPOST \
                  "$OPENSEARCH_URL_TO_USE/_plugins/_anomaly_detection/detectors/$DUMMY_DETECTOR_ID/_start" \
                  -H "$XSRF_HEADER:true" -H 'Content-type:application/json' || ( cat "$CURL_OUT" && echo )
                sleep 10
                CURL_OUT=$(get_tmp_output_filename)
                curl "${CURL_CONFIG_PARAMS[@]}" --location --fail-with-body --output "$CURL_OUT" --silent \
                  -XPOST "$OPENSEARCH_URL_TO_USE/_plugins/_anomaly_detection/detectors/$DUMMY_DETECTOR_ID/_stop" \
                  -H "$XSRF_HEADER:true" -H 'Content-type:application/json' || ( cat "$CURL_OUT" && echo )
                sleep 10
                CURL_OUT=$(get_tmp_output_filename)
                curl "${CURL_CONFIG_PARAMS[@]}" --location --fail-with-body --output "$CURL_OUT" --silent \
                  -XDELETE "$OPENSEARCH_URL_TO_USE/_plugins/_anomaly_detection/detectors/$DUMMY_DETECTOR_ID" \
                  -H "$XSRF_HEADER:true" -H 'Content-type:application/json' || ( cat "$CURL_OUT" && echo )
              fi
            fi

            echo "$DATASTORE_TYPE anomaly detectors creation complete!"

            # end OpenSearch anomaly detectors
            #############################################################################################################################

            #############################################################################################################################
            # OpenSearch security analytics fields mappings
            echo "Creating $DATASTORE_TYPE security analytics mappings..."

            SA_MAPPINGS_IMPORT_DIR="$(mktemp -p "$TMP_WORK_DIR" -d -t sa-mappings-XXXXXX)"
            rsync -a /opt/security_analytics_mappings/ "$SA_MAPPINGS_IMPORT_DIR"/
            DoReplacersForDir "$SA_MAPPINGS_IMPORT_DIR" "$DATASTORE_TYPE" sa_mapping
            for i in "${SA_MAPPINGS_IMPORT_DIR}"/*.json; do
              set +e
              RULE_TOPIC="$(jq -r '.rule_topic' 2>/dev/null < "$i")"
              INDEX_NAME="$(jq -r '.index_name' 2>/dev/null < "$i")"
              echo "Creating mappings for \"${INDEX_NAME}\" / \"${RULE_TOPIC}\" ..." && \
              CURL_OUT=$(get_tmp_output_filename)
              curl "${CURL_CONFIG_PARAMS[@]}" --location --fail-with-body --output "$CURL_OUT" --silent \
                -XPOST "$OPENSEARCH_URL_TO_USE/_plugins/_security_analytics/mappings" \
                -H "$XSRF_HEADER:true" -H 'Content-type:application/json' \
                -d "@$i" || ( cat "$CURL_OUT" && echo )
              set -e
            done

            # end OpenSearch security analytics
            #############################################################################################################################

            #############################################################################################################################
            # OpenSearch alerting
            #   - always attempt to write the default Malcolm alerting objects, regardless of whether they exist or not

            echo "Creating $DATASTORE_TYPE alerting objects..."

            # Create notification/alerting objects here

            # notification channels
            for i in /opt/notifications/channels/*.json; do
              CURL_OUT=$(get_tmp_output_filename)
              curl "${CURL_CONFIG_PARAMS[@]}" --location --fail-with-body --output "$CURL_OUT" --silent \
                -XPOST "$OPENSEARCH_URL_TO_USE/_plugins/_notifications/configs" \
                -H "$XSRF_HEADER:true" -H 'Content-type:application/json' \
                -d "@$i" || ( cat "$CURL_OUT" && echo )
            done

            # monitors
            ALERTING_IMPORT_DIR="$(mktemp -p "$TMP_WORK_DIR" -d -t alerting-XXXXXX)"
            rsync -a /opt/alerting/monitors/ "$ALERTING_IMPORT_DIR"/
            DoReplacersForDir "$ALERTING_IMPORT_DIR" "$DATASTORE_TYPE" monitor
            for i in "${ALERTING_IMPORT_DIR}"/*.json; do
              CURL_OUT=$(get_tmp_output_filename)
              curl "${CURL_CONFIG_PARAMS[@]}" --location --fail-with-body --output "$CURL_OUT" --silent \
                -XPOST "$OPENSEARCH_URL_TO_USE/_plugins/_alerting/monitors" \
                -H "$XSRF_HEADER:true" -H 'Content-type:application/json' \
                -d "@$i" || ( cat "$CURL_OUT" && echo )
            done

            echo "$DATASTORE_TYPE alerting objects creation complete!"

            # end OpenSearch alerting
            #############################################################################################################################

          fi # DATASTORE_TYPE == opensearch
        fi # stuff to only do for primary

        touch "${STARTUP_IMPORT_PERFORMED_FILE}"
      fi # LAST_IMPORT_CHECK_TIME interval check

    fi # dashboards is running
  done # primary vs. secondary
fi # CREATE_OS_ARKIME_SESSION_INDEX is true
