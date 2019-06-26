#!/usr/bin/env bash

# Copyright (c) 2019 Battelle Energy Alliance, LLC.  All rights reserved.

set -e

PIPELINES_CFG_IN="/usr/share/logstash/config/pipelines-default.yml"
PIPELINES_CFG_EXT_IN="/usr/share/logstash/config/pipelines-external.yml"
PIPELINES_CFG_FINAL="/usr/share/logstash/config/pipelines.yml"

PIPELINE_IN_DIR="/usr/share/logstash/pipeline-input"
PIPELINE_MAIN_DIR="/usr/share/logstash/pipeline-main"
PIPELINE_OUT_DIR="/usr/share/logstash/pipeline-output"
PIPELINE_EXT_DIR="/usr/share/logstash/pipeline-external"

HOST_PIPELINE_IN_DIR="/usr/share/logstash/pipeline-input.available"
HOST_PIPELINE_MAIN_DIR="/usr/share/logstash/pipeline-main.available"
HOST_PIPELINE_OUT_DIR="/usr/share/logstash/pipeline-output.available"
HOST_PIPELINE_EXT_DIR="/usr/share/logstash/pipeline-external.available"

INPUT_CIDR_MAP="/usr/share/logstash/config/cidr-map.txt"
INPUT_HOST_MAP="/usr/share/logstash/config/host-map.txt"
NETWORK_MAP_OUTPUT_FILTER="$PIPELINE_MAIN_DIR/16_host_segment_filters.conf"

MAIN_OUTPUT_FILTER="$PIPELINE_MAIN_DIR/19_main_forward.conf"
EXTERNAL_ES_PIPELINE_ADDRESS="external-es"

# copy over pipeline filters into their final resting places
[[ -d "$HOST_PIPELINE_IN_DIR" ]] && cp -f "$HOST_PIPELINE_IN_DIR"/* "$PIPELINE_IN_DIR"/
[[ -d "$HOST_PIPELINE_MAIN_DIR" ]] && cp -f "$HOST_PIPELINE_MAIN_DIR"/* "$PIPELINE_MAIN_DIR"/
[[ -d "$HOST_PIPELINE_OUT_DIR" ]] && cp -f "$HOST_PIPELINE_OUT_DIR"/* "$PIPELINE_OUT_DIR"/
[[ -d "$HOST_PIPELINE_EXT_DIR" ]] && cp -f "$HOST_PIPELINE_EXT_DIR"/* "$PIPELINE_EXT_DIR"/

# create filters for network segment and host mapping
/usr/local/bin/ip-to-segment-logstash.py --segment "$INPUT_CIDR_MAP" --host "$INPUT_HOST_MAP" -o "$NETWORK_MAP_OUTPUT_FILTER"

# combine the default and any external (if specified) pipeline configuration into pipelines.yml

# default configuration
cat "$PIPELINES_CFG_IN" > "$PIPELINES_CFG_FINAL"

# external ES destination configuration
if [[ -r "$PIPELINES_CFG_EXT_IN" ]] && [[ -n "$ES_EXTERNAL_HOSTS" ]]; then
  # external ES host is specified, include external destination in pipeline config
  echo "" >> "$PIPELINES_CFG_FINAL"
  cat "$PIPELINES_CFG_EXT_IN" >> "$PIPELINES_CFG_FINAL"

else
  # external ES host is not specified, remove external-es destination from main log processing pipeline
  sed -i "s/,[[:blank:]]*['\"]$EXTERNAL_ES_PIPELINE_ADDRESS['\"]//" "$MAIN_OUTPUT_FILTER"
fi

# experimental java execution engine (https://www.elastic.co/blog/meet-the-new-logstash-java-execution-engine)
if [[ "$LOGSTASH_JAVA_EXECUTION_ENGINE" == 'true' ]]; then
  LOGSTASH_JAVA_FLAG="--java-execution"
else
  LOGSTASH_JAVA_FLAG=""
fi

# start logstash
/usr/local/bin/docker-entrypoint $LOGSTASH_JAVA_FLAG
