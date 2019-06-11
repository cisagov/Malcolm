#!/bin/bash

# Copyright (c) 2019 Battelle Energy Alliance, LLC.  All rights reserved.

if [ -z "$BASH_VERSION" ]; then
  echo "Wrong interpreter, please run \"$0\" with bash"
  exit 1
fi

# if the docker-compose config file was specified, use it, otherwise
# let docker-compose figure it out
if [ "$1" ]; then
  CONFIG_FILE="$1"
  DOCKER_COMPOSE_COMMAND="docker-compose -f "$CONFIG_FILE""
else
  CONFIG_FILE="docker-compose.yml"
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

# stop Malcolm if needed
$SCRIPT_PATH/stop.sh "$CONFIG_FILE"

# completely clean out elasticsearch database and local files
rm -rf ./elasticsearch/nodes 2>/dev/null
find ./zeek-logs/ ./moloch-logs/ ./pcap/ ./moloch-raw/ \( \( -type f -o -type l \) -a ! -name ".gitignore" \) -delete 2>/dev/null
find ./zeek-logs/processed/ ./zeek-logs/current/ -mindepth 1 -type d -delete 2>/dev/null

echo "Malcolm has been stopped and its data cleared."
echo ""

# set INITIALIZEDB=true to reinitialize database on subsequent startup
echo "setting \"INITIALIZEDB=true\" in \"$CONFIG_FILE\" for subsequent Malcolm runs."
sed -i "s/\(INITIALIZEDB[[:space:]]*:[[:space:]]\)'false'/\1'true'/" "$CONFIG_FILE"
echo ""

popd >/dev/null 2>&1
