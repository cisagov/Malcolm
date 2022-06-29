#!/bin/bash

# Copyright (c) 2022 Battelle Energy Alliance, LLC.  All rights reserved.

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

filebeat --path.home "$SCRIPT_PATH" --path.config "$SCRIPT_PATH" --path.data "$SCRIPT_PATH/data" -c "$SCRIPT_PATH/filebeat.yml" -e

popd  >/dev/null 2>&1
