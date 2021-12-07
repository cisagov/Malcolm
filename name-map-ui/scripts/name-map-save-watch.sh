#!/bin/bash

# Copyright (c) 2022 Battelle Energy Alliance, LLC.  All rights reserved.

PROCESS_DIR=${NAME_MAP_SAVE_DIR:-/var/www/html/upload/}
DEST_MAP=${NAME_MAP_JSON:-/var/www/html/maps/net-map.json}

inotifywait -m -e close_write --format '%w%f' "${PROCESS_DIR}" | while read NEWFILE
do
  sleep 0.1
  # verify that the file is json|txt and that it is valid JSON
  FILEMIME=$(file -b --mime-type "$NEWFILE")
  if ( echo "$FILEMIME" | grep -q -e "\(application/json\|text/plain\)" ) && ( python3 -mjson.tool "$NEWFILE" >/dev/null 2>&1 ); then
    # move the new net-map.json file into its final location
    # (done like this with "tee" since we may not be able to cp overwrite a volume-mounted file)
    (>/dev/null tee "$DEST_MAP" < "$NEWFILE") && echo "\"$NEWFILE\" -> \"$DEST_MAP\""
    rm -f "$NEWFILE"
  else
    # invalid or unhandled file type uploaded, delete it
    (>&2 rm -f "$NEWFILE") && echo "Removed \"$NEWFILE\" (\"$FILEMIME\"): invalid file type or format"
  fi
done
