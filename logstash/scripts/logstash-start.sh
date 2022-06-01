#!/usr/bin/env bash

# Copyright (c) 2022 Battelle Energy Alliance, LLC.  All rights reserved.

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
INPUT_MIXED_MAP="/usr/share/logstash/config/net-map.json"

# the name of the enrichment pipeline subdirectory under $PIPELINES_DIR
ENRICHMENT_PIPELINE=${LOGSTASH_ENRICHMENT_PIPELINE:-"enrichment"}

# the name of the pipeline(s) to which input will send logs for parsing (comma-separated list, no quotes)
PARSE_PIPELINE_ADDRESSES=${LOGSTASH_PARSE_PIPELINE_ADDRESSES:-"zeek-parse,suricata-parse,beats-parse"}

# pipeline addresses for forwarding from Logstash to OpenSearch (both "internal" and "external" pipelines)
export OPENSEARCH_PIPELINE_ADDRESS_INTERNAL=${LOGSTASH_OPENSEARCH_PIPELINE_ADDRESS_INTERNAL:-"internal-os"}
export OPENSEARCH_PIPELINE_ADDRESS_EXTERNAL=${LOGSTASH_OPENSEARCH_PIPELINE_ADDRESS_EXTERNAL:-"external-os"}
OPENSEARCH_OUTPUT_PIPELINE_ADDRESSES=${LOGSTASH_OPENSEARCH_OUTPUT_PIPELINE_ADDRESSES:-"$OPENSEARCH_PIPELINE_ADDRESS_INTERNAL,$OPENSEARCH_PIPELINE_ADDRESS_EXTERNAL"}

# ip-to-segment-logstash.py translate $INPUT_CIDR_MAP, $INPUT_HOST_MAP, $INPUT_MIXED_MAP into this logstash filter file
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
  if [[ -n "$OS_EXTERNAL_HOSTS" ]] || [[ "$PIPELINE_ADDRESS_NAME" != "$OPENSEARCH_PIPELINE_ADDRESS_EXTERNAL" ]]; then
    echo "- pipeline.id: malcolm-$PIPELINE_NAME"       >> "$PIPELINES_CFG"
    echo "  path.config: "{}""                         >> "$PIPELINES_CFG"
    echo "  pipeline.ecs_compatibility: disabled"      >> "$PIPELINES_CFG"
    cat "{}"/"$PIPELINE_EXTRA_CONF_FILE" 2>/dev/null   >> "$PIPELINES_CFG"
    rm -f "{}"/"$PIPELINE_EXTRA_CONF_FILE"
    echo                                               >> "$PIPELINES_CFG"
    echo                                               >> "$PIPELINES_CFG"
  fi
'

# create filters for network segment and host mapping in the enrichment directory
rm -f "$NETWORK_MAP_OUTPUT_FILTER"
/usr/local/bin/ip-to-segment-logstash.py --mixed "$INPUT_MIXED_MAP" --segment "$INPUT_CIDR_MAP" --host "$INPUT_HOST_MAP" -o "$NETWORK_MAP_OUTPUT_FILTER"

if [[ -z "$OS_EXTERNAL_HOSTS" ]]; then
  # external ES host destination is not specified, remove external destination from enrichment pipeline output
  OPENSEARCH_OUTPUT_PIPELINE_ADDRESSES="$(echo "$OPENSEARCH_OUTPUT_PIPELINE_ADDRESSES" | sed "s/,[[:blank:]]*$OPENSEARCH_PIPELINE_ADDRESS_EXTERNAL//")"
fi

# insert quotes around the OpenSearch parsing and output pipeline list
MALCOLM_PARSE_PIPELINE_ADDRESSES=$(printf '"%s"\n' "${PARSE_PIPELINE_ADDRESSES//,/\",\"}")
MALCOLM_OPENSEARCH_OUTPUT_PIPELINES=$(printf '"%s"\n' "${OPENSEARCH_OUTPUT_PIPELINE_ADDRESSES//,/\",\"}")

# do a manual global replace on these particular values in the config files, as Logstash doesn't like the environment variables with quotes in them
find "$PIPELINES_DIR" -type f -name "*.conf" -exec sed -i "s/_MALCOLM_OPENSEARCH_OUTPUT_PIPELINES_/${MALCOLM_OPENSEARCH_OUTPUT_PIPELINES}/g" "{}" \; 2>/dev/null
find "$PIPELINES_DIR" -type f -name "*.conf" -exec sed -i "s/_MALCOLM_PARSE_PIPELINE_ADDRESSES_/${MALCOLM_PARSE_PIPELINE_ADDRESSES}/g" "{}" \; 2>/dev/null

# import trusted CA certificates if necessary
/usr/local/bin/jdk-cacerts-auto-import.sh || true

# logstash may wish to modify logstash.yml based on some environment variables (e.g.,
# pipeline.workers), so copy the original onto from the image over the "working copy" before start
[[ -r /usr/share/logstash/config/logstash.orig.yml ]] && \
  cp /usr/share/logstash/config/logstash.orig.yml /usr/share/logstash/config/logstash.yml

# start logstash (adapted from docker-entrypoint)
env2yaml /usr/share/logstash/config/logstash.yml
export LS_JAVA_OPTS="-Dls.cgroup.cpuacct.path.override=/ -Dls.cgroup.cpu.path.override=/ $LS_JAVA_OPTS"
exec logstash
