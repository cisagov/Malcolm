#!/bin/bash

# Copyright (c) 2022 Battelle Energy Alliance, LLC.  All rights reserved.


# for files (sort -V (natural)) under /zeek that:
#   - are not in processed/ or current/ or upload/ or extract_files/ or live/ (-prune)
#   - are archive files
#   - are not in use (fuser -s)
# 1. move file to processed/ (preserving original subdirectory heirarchy, if any)
# 2. calculate tags based on splitting the file path and filename (splitting on
#    on [, -/_])

FILEBEAT_PREPARE_PROCESS_COUNT=1

# ensure only one instance of this script can run at a time
LOCKDIR="/tmp/zeek-beats-process-folder"

export SCRIPT_DIR="$( cd -P "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

export ZEEK_LOG_FIELD_BITMAP_SCRIPT="$SCRIPT_DIR/zeek-log-field-bitmap.py"

export ZEEK_LOG_AUTO_TAG=${AUTO_TAG:-"true"}

ZEEK_LOGS_DIR=${FILEBEAT_ZEEK_DIR:-/zeek/}

# remove the lock directory on exit
function cleanup {
  if ! rmdir $LOCKDIR; then
    echo "Failed to remove lock directory '$LOCKDIR'"
    exit 1
  fi
}

if mkdir $LOCKDIR; then
  # ensure that if we "grabbed a lock", we release it (works for clean exit, SIGTERM, and SIGINT/Ctrl-C)
  trap "cleanup" EXIT

  # get new zeek logs ready for processing
  cd "$ZEEK_LOGS_DIR"
  find . -path ./processed -prune -o -path ./current -prune -o -path ./upload -prune -o -path ./extract_files -prune -o -path ./live -prune -o -type f -exec file --separator '|' --mime-type "{}" \; | grep -P "(application/gzip|application/x-gzip|application/x-7z-compressed|application/x-bzip2|application/x-cpio|application/x-lzip|application/x-lzma|application/x-rar-compressed|application/x-tar|application/x-xz|application/zip)" | awk -F'|' '{print $1}' | sort -V | \
    xargs -n 1 -P $FILEBEAT_PREPARE_PROCESS_COUNT -I '{}' bash -c '

    fuser -s "{}" 2>/dev/null
    if [[ $? -ne 0 ]]
    then
      . $SCRIPT_DIR/filebeat-process-zeek-folder-functions.sh

      PROCESS_TIME=$(date +%s%N)
      SOURCEDIR="$(dirname "{}")"
      DESTDIR="./processed/$SOURCEDIR"
      DESTNAME="$DESTDIR/$(basename "{}")"
      DESTDIR_EXTRACTED="${DESTNAME}_${PROCESS_TIME}"
      LINKDIR="./current"
      USERTAG=false

      TAGS=()
      IFS=",-/_." read -r -a SOURCESPLIT <<< $(echo "{}" | sed "s/\.[^.]*$//")
      echo "\"{}\" -> \"${DESTNAME}\""
      for index in "${!SOURCESPLIT[@]}"
      do
        TAG_CANDIDATE="${SOURCESPLIT[index]}"
        if ! in_array TAGS "$TAG_CANDIDATE"; then
          if [[ "$TAG_CANDIDATE" = "USERTAG" ]]; then
            USERTAG=true
          elif [[ -n $TAG_CANDIDATE && ! $TAG_CANDIDATE =~ ^[0-9-]+$ && $TAG_CANDIDATE != "tar" && $TAG_CANDIDATE != "AUTOZEEK" && ! $TAG_CANDIDATE =~ ^AUTOCARVE ]]; then
            TAGS+=("${TAG_CANDIDATE}")
          fi
        fi
      done

      if [[ "$ZEEK_LOG_AUTO_TAG" != "true" ]] && [[ "$USERTAG" != "true" ]]; then
        TAGS=()
      fi

      mkdir -p "$DESTDIR"
      mkdir -p "$DESTDIR_EXTRACTED"
      mv -v "{}" "$DESTNAME"
      python3 -m pyunpack.cli "$DESTNAME" "$DESTDIR_EXTRACTED"
      find "$DESTDIR_EXTRACTED" -type f -name "*.log" | while read LOGFILE
      do
        PROCESS_TIME=$(date +%s%N)
        TAGS_JOINED=$(printf "%s," "${TAGS[@]}")${PROCESS_TIME}
        FIELDS_BITMAP="$($ZEEK_LOG_FIELD_BITMAP_SCRIPT "$LOGFILE" | head -n 1)"
        LINKNAME_BASE="$(basename "$LOGFILE" .log)"
        if [[ -n $FIELDS_BITMAP ]]; then
          LINKNAME="${LINKNAME_BASE}(${TAGS_JOINED},${FIELDS_BITMAP}).log"
        else
          LINKNAME="${LINKNAME_BASE}(${TAGS_JOINED}).log"
        fi
        touch "$LOGFILE"
        ln -sfr "$LOGFILE" "$LINKDIR/$LINKNAME"
      done
    fi
  '

fi
