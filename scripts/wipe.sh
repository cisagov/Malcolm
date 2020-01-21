#!/bin/bash

# Copyright (c) 2019 Battelle Energy Alliance, LLC.  All rights reserved.

if [ -z "$BASH_VERSION" ]; then
  echo "Wrong interpreter, please run \"$0\" with bash"
  exit 1
fi

[[ "$(uname -s)" = 'Darwin' ]] && REALPATH=grealpath || REALPATH=realpath
[[ "$(uname -s)" = 'Darwin' ]] && DIRNAME=gdirname || DIRNAME=dirname
[[ "$(uname -s)" = 'Darwin' ]] && FIND=gfind || FIND=find
if ! (type "$REALPATH" && type "$DIRNAME" && type "$FIND") > /dev/null; then
  echo "$(basename "${BASH_SOURCE[0]}") requires $REALPATH and $DIRNAME and $FIND"
  exit 1
fi

if docker-compose version >/dev/null 2>&1; then
  DOCKER_COMPOSE_BIN=docker-compose
elif grep -q Microsoft /proc/version && docker-compose.exe version >/dev/null 2>&1; then
  DOCKER_COMPOSE_BIN=docker-compose.exe
fi

# if the docker-compose config file was specified, use it, otherwise
# let docker-compose figure it out
if [ "$1" ]; then
  CONFIG_FILE="$1"
  DOCKER_COMPOSE_COMMAND="$DOCKER_COMPOSE_BIN -f "$CONFIG_FILE""
else
  CONFIG_FILE="docker-compose.yml"
  DOCKER_COMPOSE_COMMAND="$DOCKER_COMPOSE_BIN"
fi

# force-navigate to Malcolm base directory (parent of scripts/ directory)
SCRIPT_PATH="$($DIRNAME $($REALPATH -e "${BASH_SOURCE[0]}"))"
pushd "$SCRIPT_PATH/.." >/dev/null 2>&1

# attempt to DELETE _template/zeek_template in Elasticsearch
$DOCKER_COMPOSE_COMMAND exec moloch bash -c 'curl -fs --output /dev/null -H"Content-Type: application/json" -XDELETE "http://$ES_HOST:$ES_PORT/_template/zeek_template"' >/dev/null 2>&1

# stop Malcolm and remove volumes if needed
$SCRIPT_PATH/stop.sh "$CONFIG_FILE" wipe

# completely clean out elasticsearch database and local files
rm -rf ./elasticsearch/nodes 2>/dev/null
$FIND ./elasticsearch-backup/ ./zeek-logs/ ./moloch-logs/ ./pcap/ ./moloch-raw/ \( \( -type f -o -type l \) -a ! -name ".gitignore" \) -delete 2>/dev/null
$FIND ./elasticsearch-backup/logs/ ./zeek-logs/processed/ ./zeek-logs/current/ -mindepth 1 -type d -delete 2>/dev/null

echo "Malcolm has been stopped and its data cleared."
echo ""

popd >/dev/null 2>&1
