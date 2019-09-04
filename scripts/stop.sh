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

# if stop.sh is being called with wipe.sh (after the docker-compose file)
# then also remove named and anonymous volumes (not external volumes, of course)
if [ "$2" == "wipe" ]; then
  VOLUMES_FLAG="--volumes"
else
  VOLUMES_FLAG=""
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

# stop docker
if $DOCKER_COMPOSE_COMMAND down $VOLUMES_FLAG ; then
  echo "Stopped Malcolm"
  echo ""
else
  DOCKER_ERROR=$?
  echo "Malcolm failed to stop"
  echo ""
  $DOCKER_COMPOSE_COMMAND ps
  exit $DOCKER_ERROR
fi

popd >/dev/null 2>&1
