#!/bin/bash

# Copyright (c) 2019 Battelle Energy Alliance, LLC.  All rights reserved.

if [ -z "$BASH_VERSION" ]; then
  echo "Wrong interpreter, please run \"$0\" with bash"
  exit 1
fi

if [ "$1" ]; then
  CONFIG_FILE="$1"
  DOCKER_COMPOSE_COMMAND="docker-compose -f "$CONFIG_FILE""
  shift # use remainder of arguments for services
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

# make sure docker is installed, at this point it's required
if ! docker info >/dev/null 2>&1 ; then
  echo "Docker is not installed, or not runable as this user."
  echo "Install docker (install.py may help with that) and try again later."
  exit 1
fi

# make sure docker-compose is installed, at this point it's required
if ! docker-compose version >/dev/null 2>&1 ; then
  echo "Docker Compose is not installed, or not runable as this user."
  echo "Install docker-compose (install.py may help with that) and try again later."
  exit 1
fi

unset CONFIRMATION
read -p "Malcolm Docker images will now be built and/or pulled, force full clean (non-cached) rebuild [y/N]? " CONFIRMATION
CONFIRMATION=${CONFIRMATION:-N}
if [[ $CONFIRMATION =~ ^[Yy] ]]; then
  $DOCKER_COMPOSE_COMMAND build --force-rm --no-cache "$@"
else
  $DOCKER_COMPOSE_COMMAND build "$@"
fi
