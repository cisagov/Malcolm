#!/bin/bash

# Copyright (c) 2022 Battelle Energy Alliance, LLC.  All rights reserved.

if [[ -z "$ZEEK_CAPTURE_PATH" ]]; then
  ZEEK_CAPTURE_PATH="$HOME/bro_logs"
fi
if [[ -z "$SURICATA_CAPTURE_PATH" ]]; then
  SURICATA_CAPTURE_PATH="$HOME/bro_logs/suricata"
fi
export ZEEK_CAPTURE_PATH
export SURICATA_CAPTURE_PATH
export BEAT_LOG_PATTERN="${ZEEK_CAPTURE_PATH}/*.log"
export BEAT_SURICATA_LOG_PATTERN="${SURICATA_CAPTURE_PATH}/eve*.json"
export BEAT_SCAN_FREQUENCY="10s"
export BEAT_CLEAN_INACTIVE="180m"
export BEAT_IGNORE_OLDER="120m"
export BEAT_CLOSE_INACTIVE="90m"
export BEAT_CLOSE_RENAMED="true"
export BEAT_CLOSE_REMOVED="true"
export BEAT_CLOSE_EOF="false"
export BEAT_CLEAN_RENAMED="true"
export BEAT_CLEAN_REMOVED="true"

SLEEP_SEC=0
while getopts s: opts; do
   case ${opts} in
      s) SLEEP_SEC=${OPTARG} ;;
   esac
done

# force-navigate to script directory (containing config file)
[[ "$(uname -s)" = 'Darwin' ]] && REALPATH=grealpath || REALPATH=realpath
[[ "$(uname -s)" = 'Darwin' ]] && DIRNAME=gdirname || DIRNAME=dirname
if ! (type "$REALPATH" && type "$DIRNAME") > /dev/null; then
  echo "$(basename "${BASH_SOURCE[0]}") requires $REALPATH and $DIRNAME"
  exit 1
fi
SCRIPT_PATH="$($DIRNAME $($REALPATH -e "${BASH_SOURCE[0]}"))"
pushd "$SCRIPT_PATH" >/dev/null 2>&1

mkdir -p "$SCRIPT_PATH/data"

sleep $SLEEP_SEC

filebeat --path.home "$SCRIPT_PATH" --path.config "$SCRIPT_PATH" --path.data "$SCRIPT_PATH/data" -c "$SCRIPT_PATH/filebeat.yml" -e

popd  >/dev/null 2>&1
