#!/bin/bash

# Copyright (c) 2020 Battelle Energy Alliance, LLC.  All rights reserved.

PCAP_BASE_PATH=${PCAP_PATH:-"/pcap"}
ZEEK_BASE_PATH=${ZEEK_PATH:-"/zeek"}

PROCESS_DIR="$PCAP_BASE_PATH/processed"
PCAP_UPLOAD_DIR="$PCAP_BASE_PATH/upload"
ZEEK_UPLOAD_DIR="$ZEEK_BASE_PATH/upload"
mkdir -p "$PCAP_UPLOAD_DIR"

# as new pcaps are closed for writing in /pcap/upload, move them to /pcap/processed for processing
inotifywait -m -e close_write --format '%w%f' "${PCAP_UPLOAD_DIR}" | while read NEWFILE
do
  FILEMAGIC=$(file -b "$NEWFILE")
  FILEMIME=$(file -b --mime-type "$NEWFILE")
  if [[ "$FILEMIME" == 'application/vnd.tcpdump.pcap' ]] || [[ "$FILEMIME" == 'application/x-pcapng' ]] || [[ "$FILEMAGIC" == *"pcap-ng"* ]]; then
    # a pcap file to be processed by dropping it into $PROCESS_DIR
    sleep 0.1 && chown 1000:1000 "$NEWFILE" && (>&2 mv -v "$NEWFILE" "$PROCESS_DIR/")

  elif [[ -d "$ZEEK_UPLOAD_DIR" ]] && ( echo "$FILEMIME" | grep --quiet -P "(application/gzip|application/x-gzip|application/x-7z-compressed|application/x-bzip2|application/x-cpio|application/x-lzip|application/x-lzma|application/x-rar-compressed|application/x-tar|application/x-xz|application/zip)" ); then
    # looks like this is a compressed file, we're assuming it's a zeek log archive to be processed by filebeat
    sleep 0.1 && chown 1000:1000 "$NEWFILE" && (>&2 mv -v "$NEWFILE" "$ZEEK_UPLOAD_DIR/")

  else
    # unhandled file type uploaded, delete it
    sleep 0.1 && (>&2 rm "$NEWFILE")
    echo "Removed \"$NEWFILE\", unhandled file type \"$FILEMIME\""

  fi
done
