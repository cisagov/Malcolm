#!/bin/bash

# Copyright (c) 2025 Battelle Energy Alliance, LLC.  All rights reserved.

VIEWER=${VIEWER:-on}

# note: when setting the node name, the docker_entrypoint.sh script around
#   MALCOLM_PCAP_NODE_NAME as it gets written into config.ini needs to match
[[ "${ARKIME_LIVE_CAPTURE:-false}" == "true" ]] && NODE_NAME_FLAG= || NODE_NAME_FLAG=-upload

   # if this is the "hedgehog run profile"
if [[ "${MALCOLM_PROFILE:-malcolm}" == "hedgehog" ]] && \
   # and this is the "arkime offline" container (not "arkime live")
   [[ "${ARKIME_PCAP_PROCESSOR:-true}" == "true" ]] && \
   # and neither netsniff-ng or tcpdump is in charge of PCAP capture
   #   (meaning this container isn't in charge of running capture
   #    on the rolled-over PCAP)
   [[ "${PCAP_ENABLE_TCPDUMP:-false}" == "false" ]] && \
   [[ "${PCAP_ENABLE_NETSNIFF:-false}" == "false" ]]; then
    # then we don't need to run viewer in this container:
    #   arkime-live's viewer process is handling everything
    VIEWER=off
fi

while true; do
  if [[ "$VIEWER" == "on" ]] && [[ -f /var/run/arkime/initialized ]]; then
    echo "Launch viewer..."
    rm -f $ARKIME_DIR/logs/viewer*
    pushd $ARKIME_DIR/viewer >/dev/null 2>&1
    $ARKIME_DIR/bin/node viewer.js --insecure -n "${PCAP_NODE_NAME:-malcolm}${NODE_NAME_FLAG}" -c $ARKIME_DIR/etc/config.ini
    popd >/dev/null 2>&1
  fi
  sleep 5
done

