#!/bin/bash

# Copyright (c) 2025 Battelle Energy Alliance, LLC.  All rights reserved.


# for files (sort -V (natural)) under /zeek that:
#   - are not in processed/ or current/ or upload/ or extract_files/ or live/ (-prune)
#   - are archive files (or, application/x-ms-evtx, which are also handled here as we accept
#     Windows event log .evtx files which may be compressed and we don't know what's inside
#     the archvies prior to this)
#   - are not in use (fuser -s)
# 1. move file to processed/ (preserving original subdirectory heirarchy, if any)
# 2. calculate tags based on splitting the file path and filename (splitting on
#    on ",-/_.")

FILEBEAT_PREPARE_PROCESS_COUNT=${FILEBEAT_PREPARE_PROCESS_COUNT:-1}

# ensure only one instance of this script can run at a time
LOCKDIR="/tmp/zeek-beats-process-folder"

export SCRIPT_DIR="$( cd -P "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

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

  # get new logs ready for processing
  cd "$ZEEK_LOGS_DIR"
  find . -path ./processed -prune -o -path ./current -prune -o -path ./upload -prune -o -path ./extract_files -prune -o -path ./live -prune -o -type f -exec file --separator '|' --mime-type "{}" \; | grep -P "(application/gzip|application/x-gzip|application/x-7z-compressed|application/x-bzip2|application/x-cpio|application/x-lzip|application/x-lzma|application/x-rar-compressed|application/x-tar|application/x-xz|application/zip|application/x-ms-evtx|application/octet-stream)" | sort -V | \
    xargs -P $FILEBEAT_PREPARE_PROCESS_COUNT -I '{}' bash -c '

    # separate filename and mime type
    FILENAME="$( echo "{}" | awk -F"|" "{print \$1}" )"
    FILEMIME="$( echo "{}" | awk -F"|" "{print \$2}" )"
    # trim leading and trailing spaces
    FILENAME="${FILENAME#"${FILENAME%%[![:space:]]*}"}"
    FILENAME="${FILENAME%"${FILENAME##*[![:space:]]}"}"
    FILEMIME="${FILEMIME#"${FILEMIME%%[![:space:]]*}"}"
    FILEMIME="${FILEMIME%"${FILEMIME##*[![:space:]]}"}"

    # PITA... The version of the "file" utility in the filebeat container
    #   gives "application/octet-stream" instead of "application/x-ms-evtx"
    #   for Windows .evtx files.
    #   A similar check exists in filebeat-watch-zeeklogs-uploads-folder.py.
    if [[ "$FILEMIME" == "application/octet-stream" ]]; then
      if [[ "$(file --brief "${FILENAME}" 2>/dev/null)" == *"Windows"*"Event Log"* ]]; then
        # hard-code based on the non-mime file output
        FILEMIME="application/x-ms-evtx"
      else
        # ignore this file, we really do not want it
        FILEMIME=
      fi
    fi

    if [[ -f "$FILENAME" ]] && [[ -n "$FILEMIME" ]]; then
      fuser -s "$FILENAME" 2>/dev/null
      if [[ $? -ne 0 ]]
      then
        . $SCRIPT_DIR/filebeat-process-zeek-folder-functions.sh

        PROCESS_TIME=$(date +%s%N)
        SOURCEDIR="$(dirname "$FILENAME")"
        DESTDIR="./processed/$SOURCEDIR"
        DESTNAME="$DESTDIR/$(basename "$FILENAME")"
        DESTDIR_EXTRACTED="${DESTNAME}_${PROCESS_TIME}"
        LINKDIR="./current"
        USERTAG=false

        TAGS=()
        TAGS_PRESERVED=()
        IFS=",-/_." read -r -a SOURCESPLIT <<< $(echo "$FILENAME" | sed "s/\.[^.]*$//")
        echo "\"$FILENAME\" -> \"${DESTNAME}\""
        for index in "${!SOURCESPLIT[@]}"
        do
          TAG_CANDIDATE="${SOURCESPLIT[index]}"
          if ! in_array TAGS "$TAG_CANDIDATE"; then
            if [[ "$TAG_CANDIDATE" = "USERTAG" ]]; then
              USERTAG=true
            elif [[ -n "$TAG_CANDIDATE" && ! "$TAG_CANDIDATE" =~ ^[0-9-]+$ && "$TAG_CANDIDATE" != "tar" && "$TAG_CANDIDATE" != "AUTOZEEK" ]]; then
              TAGS+=("${TAG_CANDIDATE}")
              if [[ "$TAG_CANDIDATE" =~ ^NBSITEID ]]; then
                TAGS_PRESERVED+=("${TAG_CANDIDATE}")
              fi
            fi
          fi
        done

        if [[ "$ZEEK_LOG_AUTO_TAG" != "true" ]] && [[ "$USERTAG" != "true" ]]; then
          TAGS=("${TAGS_PRESERVED[@]}")
        fi

        mkdir -p "$DESTDIR"
        mkdir -p "$DESTDIR_EXTRACTED"

        if [[ "$FILEMIME" == "application/x-ms-evtx" ]]; then
          # special case for Windows event log files that are uploaded uncompressed
          mv -v "$FILENAME" "$DESTDIR_EXTRACTED"/"$(basename "$DESTNAME")"
        else
          # extract archive to DESTDIR_EXTRACTED
          mv -v "$FILENAME" "$DESTNAME"
          python3 -m pyunpack.cli "$DESTNAME" "$DESTDIR_EXTRACTED"
        fi

        ZEEK_LOG_EXT=log
        EVTX_LOG_EXT=evtx
        while IFS="" read -r -d "" LOGFILE; do
          PROCESS_TIME=$(date +%s%N)
          TAGS_JOINED=$(printf "%s," "${TAGS[@]}")${PROCESS_TIME}
          LOGFILE_EXT="${LOGFILE##*.}"
          if [[ "${LOGFILE_EXT}" == "${EVTX_LOG_EXT}" ]]; then
            # convert evtx file to one-event-per-line JSON file
            /usr/local/bin/evtx_to_jsonl.sh "$LOGFILE"
            LOGFILE+=.json
            LINKNAME_BASE="$(basename "$LOGFILE" ."${LOGFILE_EXT}".json)"
            LINKNAME="${LINKNAME_BASE}(${TAGS_JOINED}).${LOGFILE_EXT}.json"
          else
            LINKNAME_BASE="$(basename "$LOGFILE" ."${LOGFILE_EXT}")"
            LINKNAME="${LINKNAME_BASE}(${TAGS_JOINED}).${LOGFILE_EXT}"
          fi
          touch "$LOGFILE"
          ln -sfr "$LOGFILE" "$LINKDIR/$LINKNAME"
        done < <(find "${DESTDIR_EXTRACTED}" -type f "(" -name "*.${ZEEK_LOG_EXT}" -o -name "*.${EVTX_LOG_EXT}" ")" -printf "%p\0" 2>/dev/null)


      fi # fuser says the file is not in use
    fi # FILENAME and FILEMIME are good
  '

fi
