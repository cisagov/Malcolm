#!/bin/bash

# Copyright (c) 2025 Battelle Energy Alliance, LLC.  All rights reserved.

# package up Zeek logs in a format more suitable for upload to Malcolm
#
# directory containing Zeek logs is a parent directory of directories/files named like smb_mapping.04/00/00-05/00/00.log.gz
#

set -e
set -u
set -o pipefail

ENCODING="utf-8"

# options
# -v      (verbose)
# -d dir  (base directory containing logs, e.g., the parent directory of smb_mapping.04/00/00-05/00/00.log.gz )

# parse command-line options
VERBOSE_FLAG=""
LOG_BASE_DIR=$(pwd)
while getopts 'vd:' OPTION; do
  case "$OPTION" in
    v)
      VERBOSE_FLAG="-v"
      ;;

    d)
      LOG_BASE_DIR="$OPTARG"
      ;;

    ?)
      echo "script usage: $(basename $0) [-v] [-d directory]" >&2
      exit 1
      ;;
  esac
done
shift "$(($OPTIND -1))"

# fsize - display byte sizes human readable
function fsize () {
  echo "$1" | awk 'function human(x) {
     s=" B   KiB MiB GiB TiB EiB PiB YiB ZiB"
     while (x>=1024 && length(s)>1)
           {x/=1024; s=substr(s,5)}
     s=substr(s,1,4)
     xf=(s==" B  ")?"%5d   ":"%0.2f"
     return sprintf( xf"%s", x, s)
  }
  {gsub(/^[0-9]+/, human($1)); print}'
}

function fdir () {
  [[ -f "$1" ]] && echo "$(dirname "$1")" || echo "$1"
}

# create a temporary directory to store our results in (make sure /tmp is big enough to extract all of these logs into!)
WORKDIR="$(mktemp -d -t malcolm-zeek-XXXXXX)"

# chdir to the base directory containing the logs
pushd "$LOG_BASE_DIR" >/dev/null 2>&1
FULL_PWD="$(realpath "$(pwd)")"

# cleanup - on exit ensure the temporary directory is removed
function cleanup {
  popd >/dev/null 2>&1
  if ! rm -rf "$WORKDIR"; then
    echo "Failed to remove temporary directory '$WORKDIR'" >&2
    exit 1
  fi
}

if [ -d "$WORKDIR" ]; then
  # ensure that if we "grabbed a lock", we release it (works for clean exit, SIGTERM, and SIGINT/Ctrl-C)
  trap "cleanup" EXIT

  #               year     month    day     type   hour.0   min.0    sec.0    hour.1   min.1    sec.1
  PATTERN='(\./)?([0-9]+)-([0-9]+)-([0-9]+)/(.+)\.([0-9]+):([0-9]+):([0-9]+)-([0-9]+):([0-9]+):([0-9]+)\.log\.gz$'

  # find and unzip the compressed zeek logs below this directory into temporary subdirectories that make sense
  for GZ_LOG_FILE in $(find . -type f -name "*.log.gz"); do
    GZ_LOG_FILE_SUBDIR="$(dirname "$GZ_LOG_FILE")"
    GZ_LOG_FILE_DESTDIR="$WORKDIR"/"$GZ_LOG_FILE_SUBDIR"
    mkdir -p "$GZ_LOG_FILE_DESTDIR"
    if [[ $GZ_LOG_FILE =~ $PATTERN ]]; then
      LOG_TYPE=${BASH_REMATCH[5]}
      DIR_DATE=${BASH_REMATCH[2]}_${BASH_REMATCH[3]}_${BASH_REMATCH[4]}_${BASH_REMATCH[6]}
      LOG_BASENAME="$(echo "$LOG_TYPE" | awk '{print tolower($0)}')".log
      DIR_COUNT=0
      while [[ true ]]; do
        DEST_DIR="$WORKDIR"/$DIR_DATE.$(printf %02d $DIR_COUNT)
        DEST_FILE="$DEST_DIR"/"$LOG_BASENAME"
        if [[ -e "$DEST_FILE" ]]; then
          DIR_COUNT=$((DIR_COUNT+1))
        else
          break
        fi
      done
      mkdir -p "$DEST_DIR"/
      gunzip --to-stdout "$GZ_LOG_FILE" > "$DEST_FILE"
      if [[ -n $VERBOSE_FLAG ]]; then
        FILE_TYPE="$(file -b "$DEST_FILE")"
        FILE_SIZE="$(fsize $(stat --printf="%s" "$DEST_FILE"))"
        echo "$DEST_FILE: $FILE_TYPE ($FILE_SIZE)"
      fi
    fi
  done

  # package up all of the log files in their respective directories under our temporary one
  REPACKAGED_LOGS_TARBALL="$FULL_PWD"/zeek-logs-compressed-$(date +'%Y%m%d_%H%M%S').tar.gz
  tar -c -z $VERBOSE_FLAG -C "$WORKDIR" -f $REPACKAGED_LOGS_TARBALL .
  if [[ -n $VERBOSE_FLAG ]]; then
    FILE_TYPE="$(file -b "$REPACKAGED_LOGS_TARBALL")"
    FILE_SIZE="$(fsize $(stat --printf="%s" "$REPACKAGED_LOGS_TARBALL"))"
    echo "$REPACKAGED_LOGS_TARBALL: $FILE_TYPE ($FILE_SIZE)"
  else
    echo "$REPACKAGED_LOGS_TARBALL"
  fi

fi