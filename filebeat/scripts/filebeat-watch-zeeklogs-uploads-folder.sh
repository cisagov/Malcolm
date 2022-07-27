#!/bin/bash

# Copyright (c) 2022 Battelle Energy Alliance, LLC.  All rights reserved.


PROCESS_DIR=${FILEBEAT_ZEEK_DIR:-/zeek/}
UPLOAD_DIR="${PROCESS_DIR}/upload"
mkdir -p "$UPLOAD_DIR"

# as new zeek log archives are closed for writing in /zeek/upload, move them to /zeek for processing
inotifywait -m -e close_write --format '%w%f' "${UPLOAD_DIR}" | while read NEWFILE
do
  FILEMIME=$(file -b --mime-type "$NEWFILE")
  if ( echo "$FILEMIME" | grep --quiet -P "(application/gzip|application/x-gzip|application/x-7z-compressed|application/x-bzip2|application/x-cpio|application/x-lzip|application/x-lzma|application/x-rar-compressed|application/x-tar|application/x-xz|application/zip)" ); then
    # looks like this is a compressed file, we're assuming it's a zeek log archive to be processed by filebeat
    sleep 0.1 && chown ${PUID:-${DEFAULT_UID}}:${PGID:-${DEFAULT_GID}} "$NEWFILE" && (>&2 mv -v "$NEWFILE" "$PROCESS_DIR/")
  else
    # unhandled file type uploaded, delete it
    sleep 0.1 && chown ${PUID:-${DEFAULT_UID}}:${PGID:-${DEFAULT_GID}} && (>&2 rm "$NEWFILE") && echo "Removed \"$NEWFILE\", unhandled file type \"$FILEMIME\""
  fi
done

