#!/bin/bash

# Copyright (c) 2024 Battelle Energy Alliance, LLC.  All rights reserved.

[[ "${ARKIME_LIVE_CAPTURE:-false}" == "true" ]] && LIVE_NODE_FLAG=-live || LIVE_NODE_FLAG=

while true; do
  if [[ -f /var/run/arkime/initialized && "$VIEWER" == "on" ]]; then
    echo "Launch viewer..."
    rm -f $ARKIME_DIR/logs/viewer*
    pushd $ARKIME_DIR/viewer >/dev/null 2>&1
    $ARKIME_DIR/bin/node viewer.js --insecure -n "${PCAP_NODE_NAME:-malcolm}${LIVE_NODE_FLAG}" -c $ARKIME_DIR/etc/config.ini
    popd >/dev/null 2>&1
  fi
  sleep 5
done
