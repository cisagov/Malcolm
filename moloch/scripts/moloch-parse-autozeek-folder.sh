#!/bin/bash

# Copyright (c) 2019 Battelle Energy Alliance, LLC.  All rights reserved.


MOLOCH_ZEEK_PROCESS_COUNT=${ZEEK_AUTO_ANALYZE_PCAP_THREADS:-1}

# ensure only one instance of this script can run at a time
LOCKDIR="/tmp/moloch-parse-autozeek-folder"

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

  cd /data/pcap/autozeek && (ls | grep "^autozeek_" | xargs -n 1 -P $MOLOCH_ZEEK_PROCESS_COUNT -I '{}' bash -c '
    fuser -s "{}" 2>/dev/null
    if [[ $? -ne 0 ]]
    then
      xargs --null --arg-file="{}" /data/zeek-process-pcap.py
      rm -f "{}"
    fi
  ')
fi
