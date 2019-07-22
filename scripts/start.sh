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

# if we are in an interactive shell and we're missing any of the auth files, prompt to create them now
# ( another way to check this: [[ "${-}" =~ 'i' ]] )
if [[ -t 1 ]] && \
   ( [[ ! -f ./nginx/htpasswd ]] || [[ ! -f ./htadmin/config.ini ]] || [[ ! -f ./nginx/certs/cert.pem ]] || [[ ! -f ./nginx/certs/key.pem ]] || [[ ! -r ./auth.env ]] )
then
  echo "Malcolm authentication files are missing, running ./scripts/auth_setup.sh..."
  ./scripts/auth_setup.sh
fi
# still missing? sorry charlie
if [[ ! -f ./nginx/htpasswd ]] || [[ ! -f ./htadmin/config.ini ]] || [[ ! -f ./nginx/certs/cert.pem ]] || [[ ! -f ./nginx/certs/key.pem ]] || [[ ! -r ./auth.env ]]; then
  echo "Malcolm authentication files are missing, please run ./scripts/auth_setup.sh to generate them"
  exit 1
fi

[[ -f ./htadmin/metadata ]] || touch ./htadmin/metadata

# make sure a read permission is set correctly for the nginx worker processes
chmod 644 ./nginx/htpasswd ./htadmin/config.ini ./htadmin/metadata >/dev/null 2>&1

# make sure some directories exist before we start
mkdir -p ./elasticsearch/
mkdir -p ./elasticsearch-backup/
mkdir -p ./pcap/upload/
mkdir -p ./pcap/processed/
mkdir -p ./pcap/autozeek/
mkdir -p ./zeek-logs/current/
mkdir -p ./zeek-logs/upload/
mkdir -p ./zeek-logs/processed/
mkdir -p ./zeek-logs/extract_files/

# start docker
if $DOCKER_COMPOSE_COMMAND up --detach ; then
  echo ""

  # set INITIALIZEDB=false to prevent wipe of database on subsequent startup
  echo "Malcolm started, setting \"INITIALIZEDB=false\" in \"$CONFIG_FILE\" for subsequent runs."
  sed -i "s/\(INITIALIZEDB[[:space:]]*:[[:space:]]\)'true'/\1'false'/" "$CONFIG_FILE"
  echo ""

  echo "In a few minutes, Malcolm services will be accessible via the following URLs:"
  echo "------------------------------------------------------------------------------"
  echo "  - Moloch: https://localhost/"
  echo "  - Kibana: https://localhost:5601/"
  echo "  - PCAP Upload (web): https://localhost:8443/"
  echo "  - PCAP Upload (sftp): sftp://username@127.0.0.1:8022/files/"
  echo ""

  $SCRIPT_PATH/logs.sh "$CONFIG_FILE"

else
  DOCKER_ERROR=$?
  echo "Malcolm failed to start"
  exit $DOCKER_ERROR
fi

popd >/dev/null 2>&1
