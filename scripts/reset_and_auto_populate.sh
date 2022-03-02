#!/bin/bash

# Copyright (c) 2022 Battelle Energy Alliance, LLC.  All rights reserved.

###############################################################################
#
# This script can be used to automate a restart of Malcolm (with optional wipe),
# adjust a PCAP file for a new time offset, submit the PCAP into Malcolm for
# processing, wait until the data is processed, and (optionally) set the
# database into a read-only state. This could be used for testing, setting
# up a reproducible environment for an exercise or CTF, or for whatever other
# purpose you can devise.
#
# command-line parameters
# options
# -v        (verbose)
# -w        (wipe malcolm)
# -o        (set to read-only after processing)
# -n        (pause nginx-proxy for the duration)
# -l        (for multiple PCAP files, maintain offsets relative to each other)
# -m <malcolm docker-compose file>
# -d <PCAP start date or offset>
# -s <seconds after inserts become "idle" before we assume the data has been inserted>
# -x <maximum number of seconds to wait for idle state before continuing anyway>
# remaining parameters: PCAP file(s)

###############################################################################
# force bash
if [ -z "$BASH_VERSION" ]; then
  echo "Wrong interpreter, please run \"$0\" with bash" >&2
  exit 1
fi

###############################################################################
# determine OS
unset MACOS
unset LINUX
unset WINDOWS
if [ $(uname -s) = 'Darwin' ]; then
  export MACOS=0
elif grep -q Microsoft /proc/version; then
  export WINDOWS=0
else
  export LINUX=0
fi

NUMERIC_REGEX='^[0-9]+$'

###############################################################################
# get directory script is executing from
[[ -n $MACOS ]] && REALPATH=grealpath || REALPATH=realpath
[[ -n $MACOS ]] && DIRNAME=gdirname || DIRNAME=dirname
if ! (type "$REALPATH" && type "$DIRNAME") > /dev/null; then
  echo "$(basename "${BASH_SOURCE[0]}") requires $REALPATH and $DIRNAME" >&2
  exit 1
fi
SCRIPT_PATH="$($DIRNAME $($REALPATH -e "${BASH_SOURCE[0]}") | head -n 1)"
FULL_PWD="$($REALPATH "$(pwd)" | head -n 1)"

###############################################################################
# script options
set -e
set -u
set -o pipefail
ENCODING="utf-8"

# parse command-line options
VERBOSE_FLAG=""
WIPE="false"
RESTART="false"
READ_ONLY="false"
NGINX_DISABLE="false"
MALCOLM_DOCKER_COMPOSE="$FULL_PWD"/docker-compose.yml
PCAP_FILES=()
PCAP_ADJUST_SCRIPT=""
PCAP_DATE="two days ago"
PCAP_RELATIVE_ADJUST="false"
PCAP_PROCESS_PRE_WAIT=120
PCAP_PROCESS_IDLE_SECONDS=180
PCAP_PROCESS_IDLE_MAX_SECONDS=3600
while getopts 'vwronlm:x:s:d:' OPTION; do
  case "$OPTION" in
    v)
      VERBOSE_FLAG="-v"
      ;;

    w)
      WIPE="true"
      ;;

    r)
      RESTART="true"
      ;;

    o)
      READ_ONLY="true"
      ;;

    n)
      NGINX_DISABLE="true"
      ;;

    l)
      PCAP_RELATIVE_ADJUST="true"
      ;;

    m)
      MALCOLM_DOCKER_COMPOSE="$OPTARG"
      ;;

    s)
      if [[ $OPTARG =~ $NUMERIC_REGEX ]] ; then
         PCAP_PROCESS_IDLE_SECONDS=$OPTARG
      fi
      ;;

    x)
      if [[ $OPTARG =~ $NUMERIC_REGEX ]] ; then
         PCAP_PROCESS_IDLE_MAX_SECONDS=$OPTARG
      fi
      ;;

    d)
      PCAP_DATE="$OPTARG"
      ;;

    ?)
      echo -e "script usage: $(basename $0)\n\t[-v (verbose)]\n\t[-w (wipe)]\n\t[-r (restart)]\n\t[-o (read-only)]\n\t[-n (disable NGINX during setup)]\n\t[-m <Malcolm docker-compose file>]\n\t[-s <idle seconds>]\n\t[-x <max wait for idle seconds>]\n\t[-d <PCAP start date/time>]\n\t[-l (maintain relative offsets)]\n\t<PCAP file> [<PCAP file> ...]" >&2
      exit 1
      ;;
  esac
done
shift "$(($OPTIND -1))"
PCAP_FILES=("${@}")

if [[ -f "$FULL_PWD"/pcap_time_shift.py ]]; then
  PCAP_ADJUST_SCRIPT="$FULL_PWD"/pcap_time_shift.py
elif [[ -f "$SCRIPT_PATH"/pcap_time_shift.py ]]; then
  PCAP_ADJUST_SCRIPT="$SCRIPT_PATH"/pcap_time_shift.py
elif which "pcap_time_shift.py" >/dev/null 2>&1; then
  PCAP_ADJUST_SCRIPT=pcap_time_shift.py
else
  PCAP_ADJUST_SCRIPT=""
fi

[[ -n $VERBOSE_FLAG ]] && echo "$(basename "${BASH_SOURCE[0]}") in \"${SCRIPT_PATH}\" called from \"${FULL_PWD}\"" >&2 && set -x

###############################################################################
# clean-up code
WORKDIR="$(mktemp -d -t malcolm-reset-XXXXXX)"

function clean_up {
  [[ -n "$VERBOSE_FLAG" ]] && echo "Cleaning up..." >&2
  if [[ -d "$WORKDIR" ]] && ! rm $VERBOSE_FLAG -rf "$WORKDIR"; then
   echo "Failed to remove temporary directory '$WORKDIR'" >&2
  fi
}

###############################################################################
# url encode string
function urlencode() {
    local length="${#1}";
    for ((i = 0; i < length; i++ ))
    do
        local c="${1:i:1}";
        case $c in
            [a-zA-Z0-9.~_-])
                printf "$c"
            ;;
            *)
                printf '%%%02X' "'$c"
            ;;
        esac;
    done
}


###############################################################################
# "main"

trap clean_up EXIT

if [[ -f "$MALCOLM_DOCKER_COMPOSE" ]] && \
   (( ${#PCAP_FILES[@]} > 0 )) && \
   which docker-compose >/dev/null 2>&1 && \
   which jq >/dev/null 2>&1; then
  mkdir -p "$WORKDIR"

  # get paths of things we're working with
  MALCOLM_PATH="$($DIRNAME $($REALPATH -e "$MALCOLM_DOCKER_COMPOSE"))"
  MALCOLM_FILE="$(basename $($REALPATH -e "$MALCOLM_DOCKER_COMPOSE"))"

  # if possible, time shift a temporary copy of the PCAP file(s)
  # see https://github.com/mmguero-dev/Malcolm-PCAP/blob/main/tools/pcap_time_shift.py
  pushd "$WORKDIR" >/dev/null 2>&1

  PCAP_FILES_ADJUSTED=()

  for ((i = 0; i < ${#PCAP_FILES[@]}; i++)); do
    PCAP_FILE_ABSOLUTE="$($REALPATH -e "${PCAP_FILES[$i]}")"
    PCAP_FILE_ADJUSTED="$WORKDIR"/"$(basename "${PCAP_FILES[$i]}")"
    cp $VERBOSE_FLAG "$PCAP_FILE_ABSOLUTE" "$PCAP_FILE_ADJUSTED"
    [[ -f "$PCAP_FILE_ADJUSTED" ]] && \
      PCAP_FILES_ADJUSTED+=("$PCAP_FILE_ADJUSTED")
  done

  [[ -n "$PCAP_ADJUST_SCRIPT" ]] && \
    "$PCAP_ADJUST_SCRIPT" $VERBOSE_FLAG \
      --time "$PCAP_DATE" \
      --relative "$PCAP_RELATIVE_ADJUST" \
      --format pcap \
      --in-place \
      --pcap "${PCAP_FILES_ADJUSTED[@]}"

  if (( ${#PCAP_FILES_ADJUSTED[@]} > 0 )); then

    # do the Malcolm stuff
    pushd "$MALCOLM_PATH" >/dev/null 2>&1

    # wipe and/or restart the database as requested
    if [[ "$WIPE" == "true" ]]; then
      ./scripts/wipe $VERBOSE_FLAG -f "$MALCOLM_FILE"
      ./scripts/start $VERBOSE_FLAG -f "$MALCOLM_FILE" >/dev/null 2>&1 &
      START_PID=$!
    elif [[ "$RESTART" == "true" ]]; then
      ./scripts/restart $VERBOSE_FLAG -f "$MALCOLM_FILE" >/dev/null 2>&1 &
      START_PID=$!
    else
      START_PID=
    fi
    if [[ -n "$START_PID" ]]; then
      sleep 30
      kill $START_PID
      sleep 10
    fi

    if [[ "$NGINX_DISABLE" == "true" ]]; then
      docker-compose -f "$MALCOLM_FILE" pause nginx-proxy
    fi

    # wait for logstash to be ready for Zeek logs to be ingested
    until docker-compose -f "$MALCOLM_FILE" logs logstash 2>/dev/null | grep -q "Pipelines running"; do
      [[ -n $VERBOSE_FLAG ]] && echo "waiting for Malcolm to become ready for PCAP data..." >&2
      sleep 10
    done
    sleep 30

    # copy the adjusted PCAP file(s) to the Malcolm upload directory to be processed
    cp $VERBOSE_FLAG "${PCAP_FILES_ADJUSTED[@]}" ./pcap/upload/

    if (( $PCAP_PROCESS_IDLE_SECONDS > 0 )); then
      # wait for processing to finish out (count becomes "idle", no longer increasing)
      sleep $PCAP_PROCESS_PRE_WAIT
      LAST_LOG_COUNT=0
      LAST_LOG_COUNT_CHANGED_TIME=$(date -u +%s)
      FIRST_LOG_COUNT_TIME=$LAST_LOG_COUNT_CHANGED_TIME
      while true; do

        # if it's been more than the maximum wait time, bail
        CURRENT_TIME=$(date -u +%s)
        if (( ($CURRENT_TIME - $FIRST_LOG_COUNT_TIME) >= $PCAP_PROCESS_IDLE_MAX_SECONDS )); then
          [[ -n $VERBOSE_FLAG ]] && echo "Max wait time expired waiting for idle state" >&2
          break
        fi

        # get the total number of session records in the database
        NEW_LOG_COUNT=$(( docker-compose -f "$MALCOLM_FILE" exec -u $(id -u) -T api \
                          curl -sSL "http://localhost:5000/agg/event.provider?from=1970" | \
                          jq -r '.. | .buckets? // empty | .[] | objects | [.doc_count] | join ("")' | \
                          awk '{s+=$1} END {print s}') 2>/dev/null )
        if [[ $NEW_LOG_COUNT =~ $NUMERIC_REGEX ]] ; then
          [[ -n $VERBOSE_FLAG ]] && echo "Waiting for idle state ($NEW_LOG_COUNT logs) ..." >&2
          NEW_LOG_COUNT_TIME=$CURRENT_TIME

          if (( $LAST_LOG_COUNT == $NEW_LOG_COUNT )); then
            # the count hasn't changed, so compare against how long we've been idle
            if (( ($NEW_LOG_COUNT_TIME - $LAST_LOG_COUNT_CHANGED_TIME) >= $PCAP_PROCESS_IDLE_SECONDS )); then
              [[ -n $VERBOSE_FLAG ]] && echo "Idle state reached ($NEW_LOG_COUNT logs for at lease $PCAP_PROCESS_IDLE_SECONDS seconds)" >&2
              break
            fi

          else
            # the count has changed, no longer idle, reset the non-idle time counter
            LAST_LOG_COUNT=$NEW_LOG_COUNT
            LAST_LOG_COUNT_CHANGED_TIME=$NEW_LOG_COUNT_TIME
          fi

        else
          echo "Failed to get log count, will retry!" >&2
          sleep 30
        fi
        sleep 10
      done
    fi

    if [[ "$NGINX_DISABLE" == "true" ]]; then
      docker-compose -f "$MALCOLM_FILE" unpause nginx-proxy
      sleep 10
    fi

    if [[ "$READ_ONLY" == "true" ]]; then
      [[ -n $VERBOSE_FLAG ]] && echo "Ensuring creation of user accounts prior to setting to read-only" >&2
      for USER in \
        $(cat nginx/htpasswd | cut -d: -f1) \
        $(grep -q -P "NGINX_BASIC_AUTH\s*:\s*'no_authentication'" "$MALCOLM_FILE" && echo guest); do
        docker-compose -f "$MALCOLM_FILE" exec -T arkime curl -sSL -XGET \
          --header 'Content-type:application/json' \
          --header "http_auth_http_user:$USER" \
          --header "Authorization:" \
          "http://localhost:8005"
      done
      sleep 5
      [[ -n $VERBOSE_FLAG ]] && echo "Setting cluster to read-only" >&2
      docker-compose -f "$MALCOLM_FILE" exec -T nginx-proxy bash -c "cp /etc/nginx/nginx_readonly.conf /etc/nginx/nginx.conf && nginx -s reload"
      sleep 5
      docker-compose -f "$MALCOLM_FILE" exec -T dashboards-helper /data/opensearch_read_only.py -i _cluster
      sleep 5
      for CONTAINER in filebeat logstash upload pcap-monitor file-monitor zeek name-map-ui pcap-capture freq; do
        docker-compose -f "$MALCOLM_FILE" pause "$CONTAINER" || true
      done
      sleep 5
    fi

    popd >/dev/null 2>&1

    [[ -n $VERBOSE_FLAG ]] && echo "Finished" >&2
  else
    echo "failed to create time-shifted PCAP file(s)" >/dev/null 2>&1
    exit 1
  fi
else
  echo "must specify docker-compose.yml file with -m and PCAP file(s)" >&2
  echo "also, pcap_time_shift.py, docker-compose and jq must be available"
  exit 1
fi