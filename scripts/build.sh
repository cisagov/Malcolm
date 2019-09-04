#!/bin/bash

# Copyright (c) 2019 Battelle Energy Alliance, LLC.  All rights reserved.


function filesize_in_image() {
  FILESPEC="$2"
  IMAGE="$(grep -P "^\s+image:.*$1" docker-compose-standalone.yml | awk '{print $2}')"
  docker run --rm --entrypoint /bin/sh "$IMAGE" -c "stat --printf='%s' \"$FILESPEC\""
}


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

# we're going to do some validation that some things got pulled/built correctly
FILES_IN_IMAGES=(
  "/var/lib/clamav/main.cvd;file-monitor"
  "/var/lib/clamav/daily.cvd;file-monitor"
  "/var/lib/clamav/bytecode.cvd;file-monitor"
  "/usr/share/logstash/config/oui-logstash.txt;logstash"
  "/etc/ip_protocol_numbers.yaml;logstash"
  "/etc/ja3.yaml;logstash"
  "/data/moloch/etc/GeoLite2-ASN.mmdb;moloch"
  "/data/moloch/etc/GeoLite2-Country.mmdb;moloch"
  "/data/moloch/etc/ipv4-address-space.csv;moloch"
  "/data/moloch/etc/oui.txt;moloch"
  "/opt/bro/bin/bro;moloch"
  "/opt/bro/share/bro/site/ja3/ja3.bro;moloch"
  "/data/moloch/bin/moloch-capture;moloch"
)
for i in ${FILES_IN_IMAGES[@]}; do
  FILE="$(echo "$i" | cut -d';' -f1)"
  IMAGE="$(echo "$i" | cut -d';' -f2)"
  (( "$(filesize_in_image $IMAGE "$FILE")" > 0 )) || { echo "Failed to create \"$FILE\" in \"$IMAGE\""; exit 1; }
done
