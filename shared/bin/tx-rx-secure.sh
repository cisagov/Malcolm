#!/usr/bin/env bash

# use croc (https://github.com/schollz/croc) to securely send and receive file(s)
# via the use of single-use code phrase using a local-only relay by default

###############################################################################
# script options
set -o pipefail
shopt -s nocasematch
ENCODING="utf-8"

###############################################################################
# script variables
MODE=
SERVER=
PORTS="9009,9010,9011,9012,9013"
TOKEN=
LOCAL_RELAY=yes
RELAY_PID=
RELAY_OUTPUT_REDIR=/dev/null
OUTPUT_ARGS=()
VERBOSE_FLAG=
DEBUG_FLAG=

# don't let the environment variables croc normally uses get in our way
unset CROC_RELAY
unset CROC_RELAY6
unset CROC_PASS
unset SOCKS5_PROXY

###############################################################################
# show script usage
function help() {
    echo -e "$(basename $0)\n"
    echo -e "-v                              enable bash verbosity"
    echo -e "-d                              enable croc debugging"
    echo -e "-g                              \"global\" (don't use only local connections)"
    echo -e "-p value                        relay port(s) (default: \"${PORTS}\")"

    echo -e "\ntransmit mode:"
    echo -e "-t                              enable transmit mode"
    echo -e "-s value                        bind local IP"
    echo -e "<post-options arguments>        file(s) to transfer"

    echo -e "\nreceive mode:"
    echo -e "-s value                        local server IP or hostname"
    echo -e "-r value                        one-time receive token"
    echo -e "-o value                        output folder for file(s) received (default: .)"
    exit 1
}

###############################################################################
# parse command-line parameters
while getopts 'vdgo:r:s:tp:' OPTION; do
  case "$OPTION" in

    v)
      VERBOSE_FLAG="-v"
      RELAY_OUTPUT_REDIR=/dev/stderr
      set -x
      ;;

    d)
      DEBUG_FLAG="--debug"
      RELAY_OUTPUT_REDIR=/dev/stderr
      ;;

    g)
      LOCAL_RELAY=
      ;;

    o)
      OUTPUT_ARGS=(--out "$OPTARG")
      ;;

    r)
      MODE=rx
      TOKEN="$OPTARG"
      ;;

    s)
      SERVER="$OPTARG"
      ;;

    t)
      MODE=tx
      ;;

    p)
      PORTS="$OPTARG"
      ;;

    ?)
      help >&2
      exit 1;
      ;;

  esac
done
shift "$(($OPTIND -1))"

# without croc what are we even doing here
if ! command -v croc >/dev/null 2>&1; then
    echo "$(basename $0) requires croc (https://github.com/schollz/croc)" >&2
    exit 1
fi

###############################################################################
# cleanup: kill croc relay process on exit, if we started one
function cleanup {
    if [[ -n "${RELAY_PID}" ]] && kill -s 0 "${RELAY_PID}" >/dev/null 2>&1; then
        [[ -n "${VERBOSE_FLAG}" ]] && echo "killing relay process ${RELAY_PID}"
        kill "${RELAY_PID}" >/dev/null 2>&1
        sleep 1
        if kill -s 0 "${RELAY_PID}" >/dev/null 2>&1; then
            sleep 5
            [[ -n "${VERBOSE_FLAG}" ]] && echo "killing (-9) relay process ${RELAY_PID}"
            kill -s -9 "${RELAY_PID}" >/dev/null 2>&1
        fi
    fi
}

###############################################################################

trap "cleanup" EXIT

RELAY_ARGS=()
CURVE_ARGS=(--curve siec)
HASH_ARGS=(--hash xxhash)
FIRST_PORT="$(echo "${PORTS}" | cut -d, -f1)"

if [[ -n "${PORTS}" ]] && [[ "${MODE}" == "tx" ]] && (( $# > 0 )); then
    # we have ports defined, have requested transmit mode, and have been given file(s) to transmit

    if [[ -n "${LOCAL_RELAY}" ]]; then
        # we're using "local-only" mode, which means we need to be the relay ourselves
        if [[ -z "${SERVER}" ]]; then
            SERVER="0.0.0.0"
            command -v ip >/dev/null 2>&1 && SEND_RELAY_IP=$(ip route get 255.255.255.255 2>/dev/null | grep -Po '(?<=src )(\d{1,3}.){4}' | sed "s/ //g")
        else
            SEND_RELAY_IP="${SERVER}"
        fi
        croc ${DEBUG_FLAG} "${CURVE_ARGS[@]}" relay --host "${SERVER}" --ports "${PORTS}" >${RELAY_OUTPUT_REDIR} &
        RELAY_PID=$!
        sleep 5
        if [[ -n "${RELAY_PID}" ]] && kill -s 0 "${RELAY_PID}" >/dev/null 2>&1; then
            [[ -n "${VERBOSE_FLAG}" ]] && echo "relay running at ${RELAY_PID}"
        else
            echo "Failed to start relay process" >&2
            exit 1;
        fi

    elif [[ -n "${SERVER}" ]]; then
        # we're not using local-only mode, they *can* but don't have to define a relay
        SEND_RELAY_IP="${SERVER}"
    fi

    [[ -n "${SEND_RELAY_IP}" ]] && RELAY_ARGS=(--relay "${SEND_RELAY_IP}:${FIRST_PORT}")

    # run croc
    croc --yes --ignore-stdin --overwrite ${DEBUG_FLAG} "${CURVE_ARGS[@]}" "${RELAY_ARGS[@]}" send "${HASH_ARGS[@]}" "$@"

elif [[ -n "${PORTS}" ]] && ( [[ "${MODE}" == "rx" ]] && [[ -n "${TOKEN}" ]] && ( [[ -z "${LOCAL_RELAY}" ]] || [[ -n "${SERVER}" ]] ) ); then
    # we have ports defined, have requested receive mode, have been given a token, and either have a relay IP or are not using a local relay

    [[ -n "${SERVER}" ]] && RELAY_ARGS=(--relay "${SERVER}:${FIRST_PORT}")

    # run croc
    croc --yes --ignore-stdin --overwrite ${DEBUG_FLAG} "${CURVE_ARGS[@]}" "${RELAY_ARGS[@]}" "${OUTPUT_ARGS[@]}" "${TOKEN}"

else
    help >&2
    exit 1;
fi