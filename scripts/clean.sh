#!/bin/bash

# Copyright (c) 2019 Battelle Energy Alliance, LLC.  All rights reserved.

if [ -z "$BASH_VERSION" ]; then
  echo "Wrong interpreter, please run \"$0\" with bash"
  exit 1
fi

set -x

if [ "$1" ]; then
  DOCKER_COMPOSE_COMMAND="docker-compose -f "$1""
else
  DOCKER_COMPOSE_COMMAND="docker-compose"
fi

# force-navigate to Malcolm base directory (parent of scripts/ directory)
[[ "$(uname -s)" = 'Darwin' ]] && REALPATH=grealpath || REALPATH=realpath
[[ "$(uname -s)" = 'Darwin' ]] && DIRNAME=gdirname || DIRNAME=dirname
if ! (type "$REALPATH" && type "$DIRNAME") > /dev/null; then
  echo "$(basename "${BASH_SOURCE[0]}") requires $REALPATH and $DIRNAME"
  exit 1
fi
SCRIPT_PATH="$($DIRNAME $($REALPATH -e "${BASH_SOURCE[0]}"))"
pushd "$SCRIPT_PATH/.." >/dev/null 2>&1

$DOCKER_COMPOSE_COMMAND down
sudo chown -R $USER:$USER ./*
rm -rf ./elasticsearch/nodes/*
find ./zeek-logs -type f ! -iname ".*" -delete
find ./zeek-logs -type l -delete
find ./pcap -type f ! -iname ".*" -delete
find ./moloch-logs -type f ! -iname ".*" -delete

popd >/dev/null 2>&1
