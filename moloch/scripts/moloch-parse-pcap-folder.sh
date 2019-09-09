#!/bin/bash

# Copyright (c) 2019 Battelle Energy Alliance, LLC.  All rights reserved.


# for files (sort -V (natural)) under /data/pcap that:
#   - are not in processed/ or upload/ (-prune)
#   - are "tcpdump capture" files (grep results of "file")
#   - are not in use (fuser -s)
# 1. move file to processed/ (preserving original subdirectory heirarchy, if any)
# 2. calculate tags based on splitting the file path and filename (splitting on
#    on [, -/_])
# 3. call "moloch-capture" on moved file

MOLOCH_CAPTURE_PROCESS_COUNT=${MOLOCH_ANALYZE_PCAP_THREADS:-1}

# ensure only one instance of this script can run at a time
LOCKDIR="/tmp/moloch-parse-pcap-folder"

export PCAP_AUTO_TAG=${AUTO_TAG:-"true"}
export AUTOZEEK_TXT_DIR="${AUTOZEEK_DIR:-/autozeek}"

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

  if [[ "$MANAGE_PCAP_FILES" = "true" ]] ; then
    export EXTRA_MOLOCH_CAPTURE_ARGS="--nolockpcap"
  else
    export EXTRA_MOLOCH_CAPTURE_ARGS=""
  fi

  cd /data/pcap/
  find . -path ./processed -prune -o -path ./upload -prune -o -type f -exec /bin/bash -c '(file --mime-type "{}" | grep -P "application/(vnd\.tcpdump\.pcap|x-pcapng)") || (file "{}" | grep "pcap-ng" )' \; | awk -F: '{print $1}' | sort -V | \
    xargs -n 1 -P $MOLOCH_CAPTURE_PROCESS_COUNT -I '{}' bash -c '
    shopt -s nocasematch
    fuser -s "{}" 2>/dev/null
    if [[ $? -ne 0 ]]
    then
      SOURCEDIR="$(dirname "{}")"
      DESTDIR="./processed/$SOURCEDIR"
      DESTNAME="$DESTDIR/$(basename "{}")"

      AUTO_ZEEK_BY_TAG=0
      AUTOZEEK_ARGS=( "$(realpath "$DESTNAME")" )
      TAGS_ARGS=()
      IFS=",-/_." read -r -a SOURCESPLIT <<< $(echo "{}" | sed "s/\.[^.]*$//")
      echo "\"{}\" -> \"${DESTNAME}\""
      for index in "${!SOURCESPLIT[@]}"
      do
        TAG_CANDIDATE="${SOURCESPLIT[index]}"
        if [[ ! -z $TAG_CANDIDATE ]] && [[ ! $TAG_CANDIDATE =~ ^([0-9-]+|pcap|dmp|log|bro|zeek|tcpdump|netsniff)s?$ ]] ; then
          if [[ "${TAG_CANDIDATE}" = "AUTOZEEK" ]] ; then
            AUTO_ZEEK_BY_TAG=1
          else
            AUTOZEEK_ARGS+=("${TAG_CANDIDATE}")
            if [[ ! $TAG_CANDIDATE =~ ^AUTOCARVE ]] && [[ "$PCAP_AUTO_TAG" = "true" ]]; then
              TAGS_ARGS+=("-t")
              TAGS_ARGS+=("${TAG_CANDIDATE}")
            fi
          fi
        fi
      done

      mkdir -p "$DESTDIR"
      mv -v "{}" "$DESTNAME"
      /data/moloch/bin/moloch-capture $EXTRA_MOLOCH_CAPTURE_ARGS -r "$DESTNAME" "${TAGS_ARGS[@]}"
      if [[ "$ZEEK_AUTO_ANALYZE_PCAP_FILES" = "true" ]] || [[ $AUTO_ZEEK_BY_TAG -ne 0 ]]; then
        printf "%s\0" "${AUTOZEEK_ARGS[@]}" > "$AUTOZEEK_TXT_DIR/autozeek_$(date +%s%N).txt"
      fi
    fi
  '
fi
