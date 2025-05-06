#!/usr/bin/env bash

# Copyright (c) 2025 Battelle Energy Alliance, LLC.  All rights reserved.

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
# -b <backup of netbox database>
# -m <malcolm docker-compose file>
# -d <PCAP start date or offset>
# -s <seconds after inserts become "idle" before we assume the data has been inserted>
# -x <maximum number of seconds to wait for idle state before continuing anyway>
# remaining parameters: PCAP file(s)

# Those PCAP files with FILENAMES (not path) prepended with '=' will not be time-adjusted. eg.,
# /home/ec2-user/artifacts/current/Cyberville.pcap - will be time-adjusted
# /home/ec2-user/artifacts/ctf/=ctfd.pcap - will NOT be time-adjusted
# The file itself shouldn't be named with a '=', it's just an indicator.
# That character will be removed before processing.

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
[[ -n $MACOS ]] && GREP=ggrep || GREP=grep
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
ENCODING="utf-8"

# parse command-line options
VERBOSE_FLAG=""
WIPE="false"
RESTART="false"
READ_ONLY="false"
NGINX_DISABLE="false"
MALCOLM_DOCKER_COMPOSE="$FULL_PWD"/docker-compose.yml
MALCOLM_PROFILE=malcolm
NETBOX_BACKUP_FILE=""
PCAP_FILES=()
PCAP_ADJUST_SCRIPT=""
PCAP_DATE="two days ago"
PCAP_RELATIVE_ADJUST="false"
PCAP_PROCESS_PRE_WAIT=120
PCAP_PROCESS_IDLE_SECONDS=180
PCAP_PROCESS_IDLE_MAX_SECONDS=3600
READY_INIT_MAX_SECONDS=600
while getopts 'vwronlb:m:i:x:s:d:p:' OPTION; do
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

    b)
      NETBOX_BACKUP_FILE="$OPTARG"
      ;;

    m)
      MALCOLM_DOCKER_COMPOSE="$OPTARG"
      ;;

    p)
      MALCOLM_PROFILE="$OPTARG"
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

    i)
      if [[ $OPTARG =~ $NUMERIC_REGEX ]] ; then
         READY_INIT_MAX_SECONDS=$OPTARG
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

DOCKER_COMPOSE_BIN=()
if docker compose version >/dev/null 2>&1; then
  DOCKER_COMPOSE_BIN=(docker compose)
elif docker-compose version >/dev/null 2>&1; then
  DOCKER_COMPOSE_BIN=(docker-compose)
elif [[ -n $WINDOWS ]]; then
  if docker.exe compose version >/dev/null 2>&1; then
    DOCKER_COMPOSE_BIN=(docker.exe compose)
  elif docker-compose.exe version >/dev/null 2>&1; then
    DOCKER_COMPOSE_BIN=(docker-compose.exe)
  fi
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
   (( ${#DOCKER_COMPOSE_BIN[@]} > 0 )) && \
   which jq >/dev/null 2>&1 && \
   which yq >/dev/null 2>&1; then
  mkdir -p "$WORKDIR"

  # get paths of things we're working with
  MALCOLM_PATH="$($DIRNAME $($REALPATH -e "$MALCOLM_DOCKER_COMPOSE"))"
  MALCOLM_FILE="$(basename $($REALPATH -e "$MALCOLM_DOCKER_COMPOSE"))"

  # if possible, time shift a temporary copy of the PCAP file(s)
  # see https://raw.githubusercontent.com/idaholab/Malcolm-Test-Artifacts/refs/heads/main/tools/pcap_time_shift.py
  pushd "$WORKDIR" >/dev/null 2>&1

  PCAP_FILES_ADJUSTED=()
  PCAP_FILES_NOT_ADJUSTED=()

  if (( ${#PCAP_FILES[@]} > 0 )); then
    for ((i = 0; i < ${#PCAP_FILES[@]}; i++)); do
      PCAP_FILE_DIRNAME="$(dirname "${PCAP_FILES[$i]}")"
      PCAP_FILE_BASENAME="$(basename "${PCAP_FILES[$i]}")"
      if [[ "$PCAP_FILE_BASENAME" =~ ^= ]]; then
        # don't time-adjust files prepended with =, remove the = from the filename and insert as-is
        PCAP_FILE_BASENAME="${PCAP_FILE_BASENAME:1}"
        PCAP_ADJUST="false"
      else
        PCAP_ADJUST="true"
      fi
      PCAP_FILE_ABSOLUTE="$($REALPATH -e "$PCAP_FILE_DIRNAME"/"$PCAP_FILE_BASENAME")"
      PCAP_FILE_ADJUSTED="$WORKDIR"/"$PCAP_FILE_BASENAME"
      cp $VERBOSE_FLAG "$PCAP_FILE_ABSOLUTE" "$PCAP_FILE_ADJUSTED"
      if [[ -f "$PCAP_FILE_ADJUSTED" ]]; then
        if [[ "$PCAP_ADJUST" == "true" ]]; then
          PCAP_FILES_ADJUSTED+=("$PCAP_FILE_ADJUSTED")
        else
          PCAP_FILES_NOT_ADJUSTED+=("$PCAP_FILE_ADJUSTED")
        fi
      fi
    done

    [[ -n "$PCAP_ADJUST_SCRIPT" ]] && (( ${#PCAP_FILES_ADJUSTED[@]} > 0 )) && \
      "$PCAP_ADJUST_SCRIPT" $VERBOSE_FLAG \
        --time "$PCAP_DATE" \
        --relative "$PCAP_RELATIVE_ADJUST" \
        --format pcap \
        --in-place \
        --pcap "${PCAP_FILES_ADJUSTED[@]}"
  fi

  # do the Malcolm stuff
  pushd "$MALCOLM_PATH" >/dev/null 2>&1

  # wipe and/or restart the database as requested
  if [[ "$WIPE" == "true" ]]; then
    ./scripts/wipe $VERBOSE_FLAG -f "$MALCOLM_FILE" || true
    ./scripts/start --quiet -f "$MALCOLM_FILE"
  elif [[ "$RESTART" == "true" ]]; then
    ./scripts/restart --quiet -f "$MALCOLM_FILE"
  fi
  sleep 45

  if [[ "$NGINX_DISABLE" == "true" ]]; then
    ${DOCKER_COMPOSE_BIN[@]} --profile "$MALCOLM_PROFILE" -f "$MALCOLM_FILE" pause nginx-proxy
  fi

  # wait for Malcolm to become ready
  if [[ -n "$NETBOX_BACKUP_FILE" ]] && [[ -f "$NETBOX_BACKUP_FILE" ]]; then
    JQ_READY_FILTER='if (.arkime and .logstash_lumberjack and .logstash_pipelines and .netbox and .opensearch and .pcap_monitor and .zeek_extracted_file_logger and .zeek_extracted_file_monitor) then 1 else 0 end'
  else
    JQ_READY_FILTER='if (.arkime and .logstash_lumberjack and .logstash_pipelines and .opensearch and .pcap_monitor and .zeek_extracted_file_logger and .zeek_extracted_file_monitor) then 1 else 0 end'
  fi
  CURRENT_TIME=$(date -u +%s)
  FIRST_READY_INIT_CHECK_TIME=$CURRENT_TIME
  until [[ "$( ${DOCKER_COMPOSE_BIN[@]} \
           --profile "$MALCOLM_PROFILE" \
           -f "$MALCOLM_FILE" exec -u $(id -u) -T api \
           curl -sSL -XGET 'http://localhost:5000/mapi/ready' | jq "$JQ_READY_FILTER" )" == "1" ]]; do
    [[ -n $VERBOSE_FLAG ]] && echo "waiting for Malcolm to become ready data..." >&2
    sleep 10
    # if it's been more than the maximum wait time, bail
    CURRENT_TIME=$(date -u +%s)
    if (( ($CURRENT_TIME - $FIRST_READY_INIT_CHECK_TIME) >= $READY_INIT_MAX_SECONDS )); then
      [[ -n $VERBOSE_FLAG ]] && echo "Max wait time expired waiting for readiness, YOLO!" >&2
      break
    fi
  done
  sleep 30

  if [[ -n "$NETBOX_BACKUP_FILE" ]] && [[ -f "$NETBOX_BACKUP_FILE" ]]; then
    # restore the netbox backup
    ./scripts/netbox-restore $VERBOSE_FLAG -f "$MALCOLM_FILE" --netbox-restore "$NETBOX_BACKUP_FILE" || true
  fi

  PCAP_UPLOAD_DIR="$(yq '.services.upload.volumes[] | select(.target == "/var/www/upload/server/php/chroot/files") | .source' "$MALCOLM_FILE" 2>/dev/null)"
  ( [[ -z "$PCAP_UPLOAD_DIR" ]] || [[ ! -d "$PCAP_UPLOAD_DIR" ]] ) && PCAP_UPLOAD_DIR=./pcap/upload

  if (( ${#PCAP_FILES_ADJUSTED[@]} > 0 )) || (( ${#PCAP_FILES_NOT_ADJUSTED[@]} > 0 )); then
    # copy the PCAP file(s) to the Malcolm upload directory to be processed
    (( ${#PCAP_FILES_ADJUSTED[@]} > 0 )) && cp $VERBOSE_FLAG "${PCAP_FILES_ADJUSTED[@]}" "$PCAP_UPLOAD_DIR"/
    (( ${#PCAP_FILES_NOT_ADJUSTED[@]} > 0 )) && cp $VERBOSE_FLAG "${PCAP_FILES_NOT_ADJUSTED[@]}" "$PCAP_UPLOAD_DIR"/

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
        NEW_LOG_COUNT=$( ${DOCKER_COMPOSE_BIN[@]} --profile "$MALCOLM_PROFILE" -f "$MALCOLM_FILE" exec -u $(id -u) -T api \
                           curl -sSL -XGET "http://localhost:5000/mapi/agg/event.provider?from=0" 2>/dev/null | \
                           jq -r '.. | .buckets? // empty | .[] | objects | [.doc_count|tostring] | join ("")' 2>/dev/null | \
                           awk '{s+=$1} END {print s}' )
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
  fi

  if [[ "$NGINX_DISABLE" == "true" ]]; then
    ${DOCKER_COMPOSE_BIN[@]} --profile "$MALCOLM_PROFILE" -f "$MALCOLM_FILE" unpause nginx-proxy
    sleep 10
  fi

  if [[ "$READ_ONLY" == "true" ]]; then
    [[ -n $VERBOSE_FLAG ]] && echo "Ensuring creation of user accounts prior to setting to read-only" >&2
    for USER in \
      $(cat nginx/htpasswd | cut -d: -f1) \
      $($GREP -q -P "NGINX_AUTH_MODE\s*=s*no_authentication" "$MALCOLM_PATH"/config/auth-common.env && echo guest); do
      ${DOCKER_COMPOSE_BIN[@]} --profile "$MALCOLM_PROFILE" -f "$MALCOLM_FILE" exec -T arkime curl -ksSL -XGET \
        --header 'Content-type:application/json' \
        --header "http_auth_http_user:$USER" \
        --header "Authorization:" \
        "https://localhost:8005" || true
    done
    sleep 5
    [[ -n $VERBOSE_FLAG ]] && echo "Setting cluster to read-only" >&2
    ${DOCKER_COMPOSE_BIN[@]} --profile "$MALCOLM_PROFILE" -f "$MALCOLM_FILE" exec -T nginx-proxy bash -c "cp /etc/nginx/nginx_readonly.conf /etc/nginx/nginx.conf && nginx -s reload"
    sleep 5
    ${DOCKER_COMPOSE_BIN[@]} --profile "$MALCOLM_PROFILE" -f "$MALCOLM_FILE" exec -T dashboards-helper /usr/local/bin/opensearch_read_only.py -i _cluster
    sleep 5
    for CONTAINER in htadmin filebeat logstash upload pcap-monitor zeek zeek-live suricata suricata-live pcap-capture freq; do
      ${DOCKER_COMPOSE_BIN[@]} --profile "$MALCOLM_PROFILE" -f "$MALCOLM_FILE" pause "$CONTAINER" || true
    done
    sleep 5
  fi

  popd >/dev/null 2>&1

  [[ -n $VERBOSE_FLAG ]] && echo "Finished" >&2
else
  echo "must specify docker-compose.yml file with -m and PCAP file(s)" >&2
  echo "also, pcap_time_shift.py, docker compose, jq and yq must be available"
  exit 1
fi