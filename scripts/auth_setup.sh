#!/bin/bash

# Copyright (c) 2019 Battelle Energy Alliance, LLC.  All rights reserved.

if [ -z "$BASH_VERSION" ]; then
  echo "Wrong interpreter, please run \"$0\" with bash"
  exit 1
fi

set -e

if docker version >/dev/null 2>&1; then
  DOCKER_BIN=docker
elif grep -q Microsoft /proc/version && docker.exe version >/dev/null 2>&1; then
  DOCKER_BIN=docker.exe
fi

if [ "$1" ]; then
  CONFIG_FILE="$1"
else
  CONFIG_FILE="docker-compose.yml"
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

USERNAME=""
PASSWORD=""
PASSWORD_CONFIRM=""

read -p "Administrator username: " USERNAME
while true; do
    read -s -p "${USERNAME} password: " PASSWORD
    echo
    read -s -p "${USERNAME} password (again): " PASSWORD_CONFIRM
    echo
    [ "$PASSWORD" = "$PASSWORD_CONFIRM" ] && break
    echo "Passwords do not match"
done
PASSWORD_ENCRYPTED="$(echo $PASSWORD | openssl passwd -1 -stdin)"

# get previous admin username to remove from htpasswd file if it's changed
unset USERNAME_PREVIOUS
[[ -r auth.env ]] && source auth.env && USERNAME_PREVIOUS="$MALCOLM_USERNAME"

cat <<EOF > auth.env
# Malcolm Administrator username and encrypted password for nginx reverse proxy (and upload server's SFTP access)
MALCOLM_USERNAME=$USERNAME
MALCOLM_PASSWORD=$PASSWORD_ENCRYPTED
EOF
chmod 600 ./auth.env

pushd ./nginx/ >/dev/null 2>&1
# create or update the htpasswd file
[[ ! -f ./htpasswd ]] && HTPASSWD_CREATE_FLAG="-c" || HTPASSWD_CREATE_FLAG=""
htpasswd -b $HTPASSWD_CREATE_FLAG -B ./htpasswd "$USERNAME" "$PASSWORD" >/dev/null 2>&1

# if the admininstrator username has changed, remove the previous administrator username from htpasswd
[[ -n "$USERNAME_PREVIOUS" ]] && [ "$USERNAME" != "$USERNAME_PREVIOUS" ] && sed -i "/^$USERNAME_PREVIOUS:/d" ./htpasswd

popd >/dev/null 2>&1

pushd ./htadmin/ >/dev/null 2>&1
cat <<EOF > config.ini
; HTAdmin config file.

[application]
; Change this to customize your title:
app_title = Malcolm User Management

; htpasswd file
secure_path  = ./config/htpasswd
; metadata file
metadata_path  = ./config/metadata

; administrator user/password (htpasswd -b -c -B ...)
admin_user = $USERNAME

; username field quality checks
;
min_username_len = 4
max_username_len = 12

; Password field quality checks
;
min_password_len = 6
max_password_len = 20

EOF
touch metadata
popd >/dev/null 2>&1

if [[ ! -f ./elastalert/config/smtp-auth.yaml ]]; then
  # create a sample smtp-auth.yaml for if/when we want to do elastalert email
  pushd ./elastalert/config/ >/dev/null 2>&1
  cat <<EOF > smtp-auth.yaml
user: "user@gmail.com"
password: "abcdefg1234567"
EOF
  chmod 600 ./smtp-auth.yaml
  popd >/dev/null 2>&1
fi

unset CONFIRMATION
echo ""
read -p "(Re)generate self-signed certificates for HTTPS access [Y/n]? " CONFIRMATION
CONFIRMATION=${CONFIRMATION:-Y}
if [[ $CONFIRMATION =~ ^[Yy]$ ]]; then
  pushd ./nginx/certs >/dev/null 2>&1
  rm -f *.pem
  /bin/bash ./gen_self_signed_certs.sh >/dev/null 2>&1
  popd >/dev/null 2>&1
fi

unset CONFIRMATION
echo ""
read -p "(Re)generate self-signed certificates for a remote log forwarder [Y/n]? " CONFIRMATION
CONFIRMATION=${CONFIRMATION:-Y}
if [[ $CONFIRMATION =~ ^[Yy]$ ]]; then
  pushd ./logstash/certs/ >/dev/null 2>&1
  make clean >/dev/null 2>&1
  make >/dev/null 2>&1
  mkdir -p ../../filebeat/certs
  rm -f ../../filebeat/certs/*
  cp ca.crt ../../filebeat/certs
  mv client.key client.crt ../../filebeat/certs
  rm -f *.srl *.csr *.pem
  popd >/dev/null 2>&1
fi

unset CONFIRMATION
echo ""
read -p "Store username/password for forwarding Logstash events to a secondary, external Elasticsearch instance [y/N]? " CONFIRMATION
CONFIRMATION=${CONFIRMATION:-N}
if [[ $CONFIRMATION =~ ^[Yy]$ ]]; then

  EXT_USERNAME=""
  EXT_PASSWORD=""
  EXT_PASSWORD_CONFIRM=""
  read -p "External Elasticsearch username: " EXT_USERNAME
  while true; do
      read -s -p "${EXT_USERNAME} password: " EXT_PASSWORD
      echo
      read -s -p "${EXT_USERNAME} password (again): " EXT_PASSWORD_CONFIRM
      echo
      [ "$EXT_PASSWORD" = "$EXT_PASSWORD_CONFIRM" ] && break
      echo "Passwords do not match"
  done
  echo

  pushd ./logstash/certs/ >/dev/null 2>&1
  rm -f ./logstash.keystore
  $DOCKER_BIN run --rm --entrypoint /bin/bash \
    -v "$(pwd)":/usr/share/logstash/config:rw \
    -w /usr/share/logstash/config \
    -u logstash \
    -e EXT_USERNAME="$EXT_USERNAME" \
    -e EXT_PASSWORD="$EXT_PASSWORD" \
    "$(grep "image: malcolmnetsec/logstash" ../../"$CONFIG_FILE" | awk '{print $2}')" \
    /usr/local/bin/set_es_external_keystore.sh
  popd >/dev/null 2>&1
fi

popd >/dev/null 2>&1
