#!/bin/bash

# Copyright (c) 2023 Battelle Energy Alliance, LLC.  All rights reserved.

if [ -z "$BASH_VERSION" ]; then
  echo "Wrong interpreter, please run \"$0\" with bash"
  exit 1
fi

[[ "$(uname -s)" = 'Darwin' ]] && REALPATH=grealpath || REALPATH=realpath
[[ "$(uname -s)" = 'Darwin' ]] && DIRNAME=gdirname || DIRNAME=dirname
[[ "$(uname -s)" = 'Darwin' ]] && GREP=ggrep || GREP=grep
if ! (type "$REALPATH" && type "$DIRNAME" && type "$GREP") > /dev/null; then
  echo "$(basename "${BASH_SOURCE[0]}") requires $REALPATH and $DIRNAME and $GREP"
  exit 1
fi

if docker-compose version >/dev/null 2>&1; then
  DOCKER_COMPOSE_BIN=docker-compose
  DOCKER_BIN=docker
elif $GREP -q Microsoft /proc/version && docker-compose.exe version >/dev/null 2>&1; then
  DOCKER_COMPOSE_BIN=docker-compose.exe
  DOCKER_BIN=docker.exe
fi

if [[ -f "$1" ]]; then
  CONFIG_FILE="$1"
  DOCKER_COMPOSE_COMMAND="$DOCKER_COMPOSE_BIN -f "$CONFIG_FILE""
  shift # use remainder of arguments for services
else
  CONFIG_FILE="docker-compose.yml"
  DOCKER_COMPOSE_COMMAND="$DOCKER_COMPOSE_BIN"
fi

function filesize_in_image() {
  FILESPEC="$2"
  IMAGE="$($GREP -P "^\s+image:.*$1" docker-compose-standalone.yml | awk '{print $2}' | sort -u)"
  $DOCKER_BIN run --rm --pull never --entrypoint /bin/sh "$IMAGE" -c "stat --printf='%s' \"$FILESPEC\" 2>/dev/null || stat -c '%s' \"$FILESPEC\" 2>/dev/null"
}

function dirsize_in_image() {
  FILESPEC="$2"
  IMAGE="$($GREP -P "^\s+image:.*$1" docker-compose-standalone.yml | awk '{print $2}' | sort -u)"
  KBYTES="$($DOCKER_BIN run --rm --pull never --entrypoint /bin/sh "$IMAGE" -c "du -sk \"$FILESPEC\" 2>/dev/null | cut -f1")"
  echo $(($KBYTES * 1024))
}

# force-navigate to Malcolm base directory (parent of scripts/ directory)
SCRIPT_PATH="$($DIRNAME $($REALPATH -e "${BASH_SOURCE[0]}"))"
pushd "$SCRIPT_PATH/.." >/dev/null 2>&1

# make sure docker is installed, at this point it's required
if ! $DOCKER_BIN info >/dev/null 2>&1 ; then
  echo "Docker is not installed, or not runable as this user."
  echo "Install docker (install.py may help with that) and try again later."
  exit 1
fi

# make sure docker-compose is installed, at this point it's required
if ! $DOCKER_COMPOSE_BIN version >/dev/null 2>&1 ; then
  echo "Docker Compose is not installed, or not runable as this user."
  echo "Install docker-compose (install.py may help with that) and try again later."
  exit 1
fi

unset CONFIRMATION
read -p "Malcolm Docker images will now be built and/or pulled, force full clean (non-cached) rebuild [y/N]? " CONFIRMATION
CONFIRMATION=${CONFIRMATION:-N}

BUILD_DATE="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
MALCOLM_VERSION="$($GREP -P "^\s+image:\s*malcolm" "$CONFIG_FILE" | awk '{print $2}' | cut -d':' -f2 | uniq -c | sort -nr | awk '{print $2}' | head -n 1)"
VCS_REVISION="$(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
GITHUB_API_TOKEN="${GITHUB_TOKEN:-}"

mkdir -p ./config

# MaxMind now requires a (free) license key to download the free versions of their GeoIP databases.
if [ ${#MAXMIND_GEOIP_DB_LICENSE_KEY} -gt 1 ]; then
  # prefer a local environment variable
  MAXMIND_API_KEY="$MAXMIND_GEOIP_DB_LICENSE_KEY"
else
  # but default to what they have saved in the docker-compose YML file
  MAXMIND_API_KEY="$($GREP -P "^\s*MAXMIND_GEOIP_DB_LICENSE_KEY\s*:\s" "$CONFIG_FILE" | cut -d: -f2 | tr -d '[:space:]'\'\" | head -n 1)"
fi

# build the image(s)
if [[ $CONFIRMATION =~ ^[Yy] ]]; then
  $DOCKER_COMPOSE_COMMAND --progress=plain build --force-rm --no-cache --build-arg GITHUB_TOKEN="$GITHUB_API_TOKEN" --build-arg MAXMIND_GEOIP_DB_LICENSE_KEY="$MAXMIND_API_KEY" --build-arg BUILD_DATE="$BUILD_DATE" --build-arg MALCOLM_VERSION="$MALCOLM_VERSION" --build-arg VCS_REVISION="$VCS_REVISION" "$@"
else
  $DOCKER_COMPOSE_COMMAND --progress=plain build --build-arg GITHUB_TOKEN="$GITHUB_API_TOKEN" --build-arg MAXMIND_GEOIP_DB_LICENSE_KEY="$MAXMIND_API_KEY" --build-arg BUILD_DATE="$BUILD_DATE" --build-arg MALCOLM_VERSION="$MALCOLM_VERSION" --build-arg VCS_REVISION="$VCS_REVISION" "$@"
fi

# we're going to do some validation that some things got pulled/built correctly
FILES_IN_IMAGES=(
  "/usr/share/filebeat/filebeat.yml;filebeat-oss"
  "/var/www/upload/filepond/dist/filepond.js;file-upload"
  "/opt/freq_server/freq_server.py;freq"
  "/var/www/htadmin/htadmin.php;htadmin"
  "/etc/ip_protocol_name_to_number.yaml;logstash"
  "/etc/ja3.yaml;logstash"
  "/etc/vendor_macs.yaml;logstash"
  "/opt/arkime/etc/GeoLite2-ASN.mmdb;arkime"
  "/opt/arkime/etc/GeoLite2-Country.mmdb;arkime"
  "/opt/arkime/etc/ipv4-address-space.csv;arkime"
  "/opt/arkime/etc/oui.txt;arkime"
  "/opt/arkime/bin/capture;arkime"
  "/opt/netbox-devicetype-library/schema/components.json;netbox"
  "/opt/zeek/bin/zeek;zeek"
  "/opt/zeek/bin/spicyz;zeek"
  "/usr/share/nginx/html/index.html;nginx-proxy"
)
for i in ${FILES_IN_IMAGES[@]}; do
  FILE="$(echo "$i" | cut -d';' -f1)"
  IMAGE="$(echo "$i" | cut -d';' -f2)"
  (( "$(filesize_in_image $IMAGE "$FILE")" > 0 )) || { echo "Failed to create \"$FILE\" in \"$IMAGE\""; exit 1; }
done

DIRS_IN_IMAGES=(
  "/var/lib/clamav;file-monitor;200000000"
)
for i in ${DIRS_IN_IMAGES[@]}; do
  DIR="$(echo "$i" | cut -d';' -f1)"
  IMAGE="$(echo "$i" | cut -d';' -f2)"
  MINSIZE="$(echo "$i" | cut -d';' -f3)"
  (( "$(dirsize_in_image $IMAGE "$DIR")" > $MINSIZE )) || { echo "Failed to create \"$DIR\" in \"$IMAGE\""; exit 1; }
done
