#!/bin/bash

# Copyright (c) 2025 Battelle Energy Alliance, LLC.  All rights reserved.

ARKIME_DIR=${ARKIME_DIR:-"/opt/arkime"}

[[ "$(uname -s)" = 'Darwin' ]] && REALPATH=grealpath || REALPATH=realpath
[[ "$(uname -s)" = 'Darwin' ]] && DIRNAME=gdirname || DIRNAME=dirname
if ! (type "$REALPATH" && type "$DIRNAME") > /dev/null; then
  echo "$(basename "${BASH_SOURCE[0]}") requires $REALPATH and $DIRNAME"
  exit 1
fi
SCRIPT_PATH="$($DIRNAME $($REALPATH -e "${BASH_SOURCE[0]}"))"

TAGS_ARGS=()
if [[ -n "${MALCOLM_EXTRA_TAGS}" ]]; then
  while read EXTRA_TAG; do
    TAGS_ARGS+=( -t )
    TAGS_ARGS+=( "${EXTRA_TAG}" )
  done < <(echo "${MALCOLM_EXTRA_TAGS}" | tr ',' '\n') # loop over ',' separated MALCOLM_EXTRA_TAGS values
fi

"${ARKIME_DIR}"/bin/capture ${ARKIME_HTTPS_FLAG:-} "${TAGS_ARGS[@]}" \
  -c "${SCRIPT_PATH}"/config.ini \
  -o pcapDir="${PCAP_PATH}" \
  -o bpf="${CAPTURE_FILTER}" \
  -o dropUser=sensor \
  -o dropGroup=netdev \
  -o geoLite2Country="${SCRIPT_PATH}"/GeoLite2-Country.mmdb \
  -o geoLite2ASN="${SCRIPT_PATH}"/GeoLite2-ASN.mmdb \
  -o rirFile="${SCRIPT_PATH}"/ipv4-address-space.csv \
  -o ouiFile="${SCRIPT_PATH}"/oui.txt \
  -o parsersDir="${ARKIME_DIR}"/parsers \
  -o pluginsDir="${ARKIME_DIR}"/plugins \
  -o ecsEventProvider="${ARKIME_ECS_PROVIDER:-arkime}" \
  -o ecsEventDataset="${ARKIME_ECS_DATASET:-session}" \
  --node "${ARKIME_NODE_NAME}" \
  --host "${ARKIME_NODE_HOST}"
