#!/bin/bash

# Copyright (c) 2024 Battelle Energy Alliance, LLC.  All rights reserved.

# force-navigate to script directory (containing config file)
[[ "$(uname -s)" = 'Darwin' ]] && REALPATH=grealpath || REALPATH=realpath
[[ "$(uname -s)" = 'Darwin' ]] && DIRNAME=gdirname || DIRNAME=dirname
if ! (type "$REALPATH" && type "$DIRNAME") > /dev/null; then
  echo "$(basename "${BASH_SOURCE[0]}") requires $REALPATH and $DIRNAME"
  exit 1
fi
SCRIPT_PATH="$($DIRNAME $($REALPATH -e "${BASH_SOURCE[0]}"))"
pushd "$SCRIPT_PATH" >/dev/null 2>&1

INSTANCE_UID="$(tr -dc A-Za-z0-9 </dev/urandom 2>/dev/null | head -c 16; echo)"
(( ${#INSTANCE_UID} == 16 )) || INSTANCE_UID=$RANDOM

TMP_CONFIG_FILE="$SCRIPT_PATH/filebeat.$INSTANCE_UID.yml"

function cleanup {
    rm -f "$TMP_CONFIG_FILE"
}

trap cleanup EXIT

mkdir -p "$SCRIPT_PATH/data"

if [[ -n "${MALCOLM_EXTRA_TAGS}" ]]; then
  readarray -td '' EXTRA_TAGS_ARRAY < <(awk '{ gsub(/,/,"\0"); print; }' <<<"$MALCOLM_EXTRA_TAGS,"); unset 'EXTRA_TAGS_ARRAY[-1]';
  yq -P eval "(.\"filebeat.inputs\"[] | select(.type == \"log\").tags) += $(jo -a "${EXTRA_TAGS_ARRAY[@]}")" "$SCRIPT_PATH/filebeat.yml" > "$TMP_CONFIG_FILE"
else
  cp "$SCRIPT_PATH/filebeat.yml" "$TMP_CONFIG_FILE"
fi

filebeat --path.home "$SCRIPT_PATH" --path.config "$SCRIPT_PATH" --path.data "$SCRIPT_PATH/data" -c "$TMP_CONFIG_FILE" -e

popd  >/dev/null 2>&1
