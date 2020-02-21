#!/usr/bin/env bash

# Copyright (c) 2020 Battelle Energy Alliance, LLC.  All rights reserved.

set -e

# if any pipelines are volume-mounted inside this docker container, they should belong to subdirectories under this path
HOST_PIPELINES_DIR="/usr/share/logstash/malcolm-pipelines.available"

# runtime pipelines parent directory
export PIPELINES_DIR="/usr/share/logstash/malcolm-pipelines"

# runtime pipeliens configuration file
export PIPELINES_CFG="/usr/share/logstash/config/pipelines.yml"

# for each pipeline in /usr/share/logstash/malcolm-pipelines, append the contents of this file to the dynamically-generated
# pipeline section in pipelines.yml (then delete 00_config.conf before starting)
export PIPELINE_EXTRA_CONF_FILE="00_config.conf"

# files defining IP->host and MAC->host mapping
INPUT_CIDR_MAP="/usr/share/logstash/config/cidr-map.txt"
INPUT_HOST_MAP="/usr/share/logstash/config/host-map.txt"

# the name of the enrichment pipeline subdirectory under $PIPELINES_DIR
ENRICHMENT_PIPELINE=${LOGSTASH_ENRICHMENT_PIPELINE:-"enrichment"}

# the name of the pipeline(s) to which input will send logs for parsing (comma-separated list, no quotes)
PARSE_PIPELINE_ADDRESSES=${LOGSTASH_PARSE_PIPELINE_ADDRESSES:-"zeek-parse"}

# pipeline addresses for forwarding from Logstash to Elasticsearch (both "internal" and "external" pipelines)
export ELASTICSEARCH_PIPELINE_ADDRESS_INTERNAL=${LOGSTASH_ELASTICSEARCH_PIPELINE_ADDRESS_INTERNAL:-"internal-es"}
export ELASTICSEARCH_PIPELINE_ADDRESS_EXTERNAL=${LOGSTASH_ELASTICSEARCH_PIPELINE_ADDRESS_EXTERNAL:-"external-es"}
ELASTICSEARCH_OUTPUT_PIPELINE_ADDRESSES=${LOGSTASH_ELASTICSEARCH_OUTPUT_PIPELINE_ADDRESSES:-"$ELASTICSEARCH_PIPELINE_ADDRESS_INTERNAL,$ELASTICSEARCH_PIPELINE_ADDRESS_EXTERNAL"}

# ip-to-segment-logstash.py translate $INPUT_CIDR_MAP and $INPUT_HOST_MAP into this logstash filter file
NETWORK_MAP_OUTPUT_FILTER="$PIPELINES_DIR"/"$ENRICHMENT_PIPELINE"/16_host_segment_filters.conf

####################################################################################################################

# copy over pipeline filters from host-mapped volumes (if any) into their final resting places
find "$HOST_PIPELINES_DIR" -mindepth 1 -maxdepth 1 -type d -print0 2>/dev/null | sort -z | \
  xargs -0 -n 1 -I '{}' bash -c '
  PIPELINE_NAME="$(basename "{}")"
  PIPELINES_DEST_DIR="$PIPELINES_DIR"/"$PIPELINE_NAME"
  mkdir -p "$PIPELINES_DEST_DIR"
  cp -f "{}"/* "$PIPELINES_DEST_DIR"/
'

# dynamically generate final pipelines.yml configuration file from all of the pipeline directories
> "$PIPELINES_CFG"
find "$PIPELINES_DIR" -mindepth 1 -maxdepth 1 -type d -print0 2>/dev/null | sort -z | \
  xargs -0 -n 1 -I '{}' bash -c '
  PIPELINE_NAME="$(basename "{}")"
  PIPELINE_ADDRESS_NAME="$(cat "{}"/*.conf | sed -e "s/:[\}]*.*\(}\)/\1/" | envsubst | grep -P "\baddress\s*=>" | awk "{print \$3}" | sed "s/[\"'']//g" | head -n 1)"
  if [[ -n "$ES_EXTERNAL_HOSTS" ]] || [[ "$PIPELINE_ADDRESS_NAME" != "$ELASTICSEARCH_PIPELINE_ADDRESS_EXTERNAL" ]]; then
    echo "- pipeline.id: malcolm-$PIPELINE_NAME"       >> "$PIPELINES_CFG"
    echo "  path.config: "{}""                         >> "$PIPELINES_CFG"
    cat "{}"/"$PIPELINE_EXTRA_CONF_FILE" 2>/dev/null   >> "$PIPELINES_CFG"
    rm -f "{}"/"$PIPELINE_EXTRA_CONF_FILE"
    echo                                               >> "$PIPELINES_CFG"
    echo                                               >> "$PIPELINES_CFG"
  fi
'

# create filters for network segment and host mapping in the enrichment directory
/usr/local/bin/ip-to-segment-logstash.py --segment "$INPUT_CIDR_MAP" --host "$INPUT_HOST_MAP" -o "$NETWORK_MAP_OUTPUT_FILTER"

if [[ -z "$ES_EXTERNAL_HOSTS" ]]; then
  # external ES host destination is not specified, remove external destination from enrichment pipeline output
  ELASTICSEARCH_OUTPUT_PIPELINE_ADDRESSES="$(echo "$ELASTICSEARCH_OUTPUT_PIPELINE_ADDRESSES" | sed "s/,[[:blank:]]*$ELASTICSEARCH_PIPELINE_ADDRESS_EXTERNAL//")"
fi

# insert quotes around the elasticsearch parsing and output pipeline list
MALCOLM_PARSE_PIPELINE_ADDRESSES=$(printf '"%s"\n' "${PARSE_PIPELINE_ADDRESSES//,/\",\"}")
MALCOLM_ELASTICSEARCH_OUTPUT_PIPELINES=$(printf '"%s"\n' "${ELASTICSEARCH_OUTPUT_PIPELINE_ADDRESSES//,/\",\"}")

# do a manual global replace on these particular values in the config files, as Logstash doesn't like the environment variables with quotes in them
find "$PIPELINES_DIR" -type f -name "*.conf" -exec sed -i "s/_MALCOLM_ELASTICSEARCH_OUTPUT_PIPELINES_/${MALCOLM_ELASTICSEARCH_OUTPUT_PIPELINES}/g" "{}" \; 2>/dev/null
find "$PIPELINES_DIR" -type f -name "*.conf" -exec sed -i "s/_MALCOLM_PARSE_PIPELINE_ADDRESSES_/${MALCOLM_PARSE_PIPELINE_ADDRESSES}/g" "{}" \; 2>/dev/null

# experimental java execution engine (https://www.elastic.co/blog/meet-the-new-logstash-java-execution-engine)
if [[ "$LOGSTASH_JAVA_EXECUTION_ENGINE" == 'true' ]]; then
  LOGSTASH_JAVA_FLAG="--java-execution"
else
  LOGSTASH_JAVA_FLAG=""
fi

# start logstash
/usr/local/bin/docker-entrypoint $LOGSTASH_JAVA_FLAG
