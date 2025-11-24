#!/usr/bin/env bash

###############################################################################
if [ -z "$BASH_VERSION" ]; then
  echo "Wrong interpreter, please run \"$0\" with bash" >&2
  exit 1
fi

! command -v prune_files.sh >/dev/null 2>&1 && echo "Missing required prune_files.sh" >&2 && exit 1
! command -v yq >/dev/null 2>&1 && echo "Missing required tool yq" >&2 && exit 1

###############################################################################
set -euo pipefail
ENCODING="utf-8"

###############################################################################
function GetHostPath() {
    COMPOSE_FILE="$1"
    SERVICE="$2"
    TARGET_PATH="$3"
    pushd "$(dirname "$COMPOSE_FILE")" >/dev/null 2>&1
    yq -r ".services[\"$SERVICE\"].volumes[] | select(.target == \"$TARGET_PATH\") | .source" "$COMPOSE_FILE" | xargs -r -l realpath
    popd >/dev/null 2>&1
}

###############################################################################
THRESHOLD=90
MODE=
INTERVAL=60
VERBOSE=0
RECURSIVE_FLAG=
while getopts f:i:m:t:rv opts; do
   case ${opts} in
      f) MALCOLM_COMPOSE_FILE=${OPTARG} ;;
      i) INTERVAL=${OPTARG} ;;
      m) MODE=${OPTARG} ;;
      r) RECURSIVE_FLAG=-r ;;
      t) THRESHOLD=${OPTARG} ;;
      v) VERBOSE=1 ;;
   esac
done
(( $VERBOSE == 1 )) && VERBOSE_FLAG=-v || VERBOSE_FLAG=

case "$MODE" in
  "pcap")
    (( $VERBOSE == 1 )) && echo "PCAP pruning mode" >&2
    ;;
  "suricata")
    (( $VERBOSE == 1 )) && echo "Suricata alert pruning mode" >&2
    ;;
  "zeek")
    (( $VERBOSE == 1 )) && echo "Zeek log pruning mode" >&2
    ;;
  *)
    echo "Mode must be one of pcap, suricata, or zeek" >&2
    exit 1
    ;;
esac

###############################################################################
MALCOLM_COMPOSE_FILE="${MALCOLM_COMPOSE_FILE:-$(getent passwd $(id -nu) | cut -d: -f6)/Malcolm/docker-compose.yml}"
if [[ ! -r "$MALCOLM_COMPOSE_FILE" ]]; then
    echo "Could not determine Malcolm's docker-compose.yml" >&2
    exit 1
fi

PRUNE_PATH=
[[ "$MODE" == "pcap" ]] && PRUNE_PATH="$(GetHostPath "$MALCOLM_COMPOSE_FILE" arkime-live /data/pcap)"
[[ "$MODE" == "suricata" ]] && PRUNE_PATH="$(GetHostPath "$MALCOLM_COMPOSE_FILE" suricata-live /var/log/suricata)"
[[ "$MODE" == "zeek" ]] && PRUNE_PATH="$(GetHostPath "$MALCOLM_COMPOSE_FILE" filebeat /zeek)"
[[ ! -d "$PRUNE_PATH" ]] && echo "\"$PRUNE_PATH\" extracted from \"$MALCOLM_COMPOSE_FILE\" does not exist" >&2 && exit 1

###############################################################################
prune_files.sh $VERBOSE_FLAG -p "$PRUNE_PATH" -t $THRESHOLD -i $INTERVAL $RECURSIVE_FLAG
