#!/bin/bash

# Copyright (c) 2025 Battelle Energy Alliance, LLC.  All rights reserved.

# note: when setting the node name, the docker_entrypoint.sh script around
#   MALCOLM_PCAP_NODE_NAME as it gets written into config.ini needs to match
[[ "${ARKIME_LIVE_CAPTURE:-false}" == "true" ]] && NODE_NAME_FLAG= || NODE_NAME_FLAG=-upload

while true; do
  if [[ -f /var/run/arkime/initialized && "$VIEWER" == "on" ]]; then
    echo "Launch viewer..."
    rm -f $ARKIME_DIR/logs/viewer*
    pushd $ARKIME_DIR/viewer >/dev/null 2>&1
    $ARKIME_DIR/bin/node viewer.js --insecure -n "${PCAP_NODE_NAME:-malcolm}${NODE_NAME_FLAG}" -c $ARKIME_DIR/etc/config.ini
    popd >/dev/null 2>&1
  fi
  sleep 5
done
