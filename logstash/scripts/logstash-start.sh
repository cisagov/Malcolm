#!/usr/bin/env bash

# Copyright (c) 2023 Battelle Energy Alliance, LLC.  All rights reserved.

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

# the name of the enrichment pipeline subdirectory under $PIPELINES_DIR
ENRICHMENT_PIPELINE=${LOGSTASH_ENRICHMENT_PIPELINE:-"enrichment"}

# the name of the pipeline(s) to which input will send logs for parsing (comma-separated list, no quotes)
PARSE_PIPELINE_ADDRESSES=${LOGSTASH_PARSE_PIPELINE_ADDRESSES:-"zeek-parse,suricata-parse,beats-parse"}

# pipeline addresses for forwarding from Logstash to OpenSearch (both "internal" and "external" pipelines)
export OPENSEARCH_PIPELINE_ADDRESS_INTERNAL=${LOGSTASH_OPENSEARCH_PIPELINE_ADDRESS_INTERNAL:-"internal-os"}
export OPENSEARCH_PIPELINE_ADDRESS_EXTERNAL=${LOGSTASH_OPENSEARCH_PIPELINE_ADDRESS_EXTERNAL:-"external-os"}
OPENSEARCH_OUTPUT_PIPELINE_ADDRESSES=${LOGSTASH_OPENSEARCH_OUTPUT_PIPELINE_ADDRESSES:-"$OPENSEARCH_PIPELINE_ADDRESS_INTERNAL,$OPENSEARCH_PIPELINE_ADDRESS_EXTERNAL"}

# output plugin configuration for primary and secondary opensearch destinations
OPENSEARCH_LOCAL=${OPENSEARCH_LOCAL:-"true"}
OPENSEARCH_SECONDARY=${OPENSEARCH_SECONDARY:-"false"}

OPENSEARCH_SSL_CERTIFICATE_VERIFICATION=${OPENSEARCH_SSL_CERTIFICATE_VERIFICATION:-"false"}
OPENSEARCH_SECONDARY_SSL_CERTIFICATE_VERIFICATION=${OPENSEARCH_SECONDARY_SSL_CERTIFICATE_VERIFICATION:-"false"}

OPENSEARCH_CREDS_CONFIG_FILE=${OPENSEARCH_CREDS_CONFIG_FILE:-"/var/local/curlrc/.opensearch.primary.curlrc"}
OPENSEARCH_SECONDARY_CREDS_CONFIG_FILE=${OPENSEARCH_SECONDARY_CREDS_CONFIG_FILE:-"/var/local/curlrc/.opensearch.secondary.curlrc"}

[[ "$OPENSEARCH_SECONDARY" != "true" ]] && OPENSEARCH_SECONDARY_URL=
export OPENSEARCH_SECONDARY_URL

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
  if [[ -n "$OPENSEARCH_SECONDARY_URL" ]] || [[ "$PIPELINE_ADDRESS_NAME" != "$OPENSEARCH_PIPELINE_ADDRESS_EXTERNAL" ]]; then
    echo "- pipeline.id: malcolm-$PIPELINE_NAME"       >> "$PIPELINES_CFG"
    echo "  path.config: "{}""                         >> "$PIPELINES_CFG"
    echo "  pipeline.ecs_compatibility: disabled"      >> "$PIPELINES_CFG"
    cat "{}"/"$PIPELINE_EXTRA_CONF_FILE" 2>/dev/null   >> "$PIPELINES_CFG"
    rm -f "{}"/"$PIPELINE_EXTRA_CONF_FILE"
    echo                                               >> "$PIPELINES_CFG"
    echo                                               >> "$PIPELINES_CFG"
  fi
'

if [[ -z "$OPENSEARCH_SECONDARY_URL" ]]; then
  # external ES host destination is not specified, remove external destination from enrichment pipeline output
  OPENSEARCH_OUTPUT_PIPELINE_ADDRESSES="$(echo "$OPENSEARCH_OUTPUT_PIPELINE_ADDRESSES" | sed "s/,[[:blank:]]*$OPENSEARCH_PIPELINE_ADDRESS_EXTERNAL//")"
fi

# insert quotes around the OpenSearch parsing and output pipeline list
MALCOLM_PARSE_PIPELINE_ADDRESSES=$(printf '"%s"\n' "${PARSE_PIPELINE_ADDRESSES//,/\",\"}")
MALCOLM_OPENSEARCH_OUTPUT_PIPELINES=$(printf '"%s"\n' "${OPENSEARCH_OUTPUT_PIPELINE_ADDRESSES//,/\",\"}")

# get the username/password for opensearch from the curlrf file(s) for both primary and secondary outputs
# (I already wrote python code to do this, so sue me)
OPENSSL_USER=
OPENSSL_PASSWORD=
if [[ "$OPENSEARCH_LOCAL" == "false" ]] && [[ -r "$OPENSEARCH_CREDS_CONFIG_FILE" ]]; then
    pushd "$(dirname $(realpath -e "${BASH_SOURCE[0]}"))" >/dev/null 2>&1
    NEW_USER_PASSWORD="$(python3 -c "import malcolm_utils; result=malcolm_utils.ParseCurlFile('$OPENSEARCH_CREDS_CONFIG_FILE'); print(result['user']+'|'+result['password']);")"
    OPENSSL_USER="$(echo "$NEW_USER_PASSWORD" | cut -d'|' -f1)"
    OPENSSL_PASSWORD="$(echo "$NEW_USER_PASSWORD" | cut -d'|' -f2-)"
    popd >/dev/null 2>&1
fi

OPENSSL_SECONDARY_USER=
OPENSSL_SECONDARY_PASSWORD=
if [[ "$OPENSEARCH_SECONDARY" == "true" ]] && [[ -r "$OPENSEARCH_SECONDARY_CREDS_CONFIG_FILE" ]]; then
    pushd "$(dirname $(realpath -e "${BASH_SOURCE[0]}"))" >/dev/null 2>&1
    NEW_SECONDARY_USER_PASSWORD="$(python3 -c "import malcolm_utils; result=malcolm_utils.ParseCurlFile('$OPENSEARCH_SECONDARY_CREDS_CONFIG_FILE'); print(result['user']+'|'+result['password']);")"
    OPENSSL_SECONDARY_USER="$(echo "$NEW_SECONDARY_USER_PASSWORD" | cut -d'|' -f1)"
    OPENSSL_SECONDARY_PASSWORD="$(echo "$NEW_SECONDARY_USER_PASSWORD" | cut -d'|' -f2-)"
    popd >/dev/null 2>&1
fi

# set some permissions restrictions for conf files we're going to put passwords into
find "$PIPELINES_DIR" -type f -name "*.conf" -exec grep -H -P "_MALCOLM_LOGSTASH_OPENSEARCH\w*_PASSWORD_" "{}" \; | \
  cut -d: -f1 | \
  xargs -r -l chmod 600

# do a manual global replace on these particular values in the config files, as Logstash doesn't like the environment variables with quotes in them
find "$PIPELINES_DIR" -type f -name "*.conf" -exec sed -i "s/_MALCOLM_OPENSEARCH_OUTPUT_PIPELINES_/${MALCOLM_OPENSEARCH_OUTPUT_PIPELINES}/g" "{}" \; 2>/dev/null
find "$PIPELINES_DIR" -type f -name "*.conf" -exec sed -i "s/_MALCOLM_PARSE_PIPELINE_ADDRESSES_/${MALCOLM_PARSE_PIPELINE_ADDRESSES}/g" "{}" \; 2>/dev/null

find "$PIPELINES_DIR" -type f -name "*.conf" -exec sed -i "s/_MALCOLM_LOGSTASH_OPENSEARCH_SSL_VERIFICATION_/${OPENSEARCH_SSL_CERTIFICATE_VERIFICATION}/g" "{}" \; 2>/dev/null
find "$PIPELINES_DIR" -type f -name "*.conf" -exec sed -i "s/_MALCOLM_LOGSTASH_OPENSEARCH_USER_/${OPENSSL_USER}/g" "{}" \; 2>/dev/null
find "$PIPELINES_DIR" -type f -name "*.conf" -exec sed -i "s/_MALCOLM_LOGSTASH_OPENSEARCH_PASSWORD_/${OPENSSL_PASSWORD}/g" "{}" \; 2>/dev/null

find "$PIPELINES_DIR" -type f -name "*.conf" -exec sed -i "s/_MALCOLM_LOGSTASH_OPENSEARCH_SECONDARY_SSL_VERIFICATION_/${OPENSEARCH_SECONDARY_SSL_CERTIFICATE_VERIFICATION}/g" "{}" \; 2>/dev/null
find "$PIPELINES_DIR" -type f -name "*.conf" -exec sed -i "s/_MALCOLM_LOGSTASH_OPENSEARCH_SECONDARY_USER_/${OPENSSL_SECONDARY_USER}/g" "{}" \; 2>/dev/null
find "$PIPELINES_DIR" -type f -name "*.conf" -exec sed -i "s/_MALCOLM_LOGSTASH_OPENSEARCH_SECONDARY_PASSWORD_/${OPENSSL_SECONDARY_PASSWORD}/g" "{}" \; 2>/dev/null

# import trusted CA certificates if necessary
/usr/local/bin/jdk-cacerts-auto-import.sh || true

# bootstrap keystore file if necessary
/usr/local/bin/keystore-bootstrap.sh || true

# logstash may wish to modify logstash.yml based on some environment variables (e.g.,
# pipeline.workers), so copy the original onto from the image over the "working copy" before start
[[ -r /usr/share/logstash/config/logstash.orig.yml ]] && \
  cp /usr/share/logstash/config/logstash.orig.yml /usr/share/logstash/config/logstash.yml

# start logstash (adapted from docker-entrypoint)
env2yaml /usr/share/logstash/config/logstash.yml
export LS_JAVA_OPTS="-Dls.cgroup.cpuacct.path.override=/ -Dls.cgroup.cpu.path.override=/ $LS_JAVA_OPTS"
if [[ -z $1 ]] || [[ ${1:0:1} == '-' ]] ; then
  exec logstash "$@"
else
  exec "$@"
fi
