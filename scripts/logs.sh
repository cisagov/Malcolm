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
BASE_PATH=`pwd`;

# tail logs
$DOCKER_COMPOSE_COMMAND ps
echo ""
IGNORE_LOG_TEXT="(deprecated|eshealth|update_mapping|throttling index|but no there are no living connections|saved_objects|\b(d|es)?stats\.json|esindices\/list|_cat\/indices|use_field_mapping|reaped unknown pid|Successfully handled GET request for '/'|GET /api/status 200|POST /_bulk HTTP/[\d\.].+\b200\b.+(Go-http-client|Manticore)|POST\s+/server/php/\s+HTTP/\d+\.\d+\"\s+\d+\s+\d+.*:8443/)"

$DOCKER_COMPOSE_COMMAND logs -f | grep --line-buffered -Piv "$IGNORE_LOG_TEXT"

echo ""

popd >/dev/null 2>&1
