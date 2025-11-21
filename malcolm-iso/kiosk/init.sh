#!/bin/bash

function GetHostPath() {
    COMPOSE_FILE="$1"
    SERVICE="$2"
    TARGET_PATH="$3"
    pushd "$(dirname "$COMPOSE_FILE")" >/dev/null 2>&1
    yq -r ".services[\"$SERVICE\"].volumes[] | select(.target == \"$TARGET_PATH\") | .source" "$COMPOSE_FILE" | xargs -r -l realpath
    popd >/dev/null 2>&1
}

MALCOLM_COMPOSE_FILE="${MALCOLM_COMPOSE_FILE:-$(getent passwd $(id -nu 1000) | cut -d: -f6)/Malcolm/docker-compose.yml}"
if [[ -r "$MALCOLM_COMPOSE_FILE" ]]; then
    export MALCOLM_COMPOSE_FILE
    export PCAP_PATH="$(GetHostPath "$MALCOLM_COMPOSE_FILE" arkime-live /data/pcap)"
    export SURICATA_LOG_PATH="$(GetHostPath "$MALCOLM_COMPOSE_FILE" suricata-live /var/log/suricata)"
    export ZEEK_LOG_PATH="$(GetHostPath "$MALCOLM_COMPOSE_FILE" zeek-live /zeek/live)"
fi

SCRIPT_PATH="$( cd -P "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
pushd "$SCRIPT_PATH" >/dev/null 2>&1

[[ -e ./pyenv/bin/activate ]] && source ./pyenv/bin/activate

gunicorn --bind=127.0.0.1:5000 interface.routes:app

popd >/dev/null 2>&1
