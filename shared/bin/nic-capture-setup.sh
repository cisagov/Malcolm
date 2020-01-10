#!/bin/bash

IFACE_NAME="$1"

if [[ -n "$IFACE_NAME" ]]; then
  # disable NIC feature offloading
  /sbin/ethtool -K "$IFACE_NAME" rx off tx off sg off tso off ufo off gso off gro off lro off

  # increase ring buffer sizes to maximum (may increase latency, but maximize throughput)
  MAX_BUFFER_SIZES=($(/sbin/ethtool -g "$IFACE_NAME" | grep -E "^(RX|TX):" | head -n 2 | awk '{print $2}'))
  if ((${#MAX_BUFFER_SIZES[@]} == 2)); then
    /sbin/ethtool -G "$IFACE_NAME" rx ${MAX_BUFFER_SIZES[0]} tx ${MAX_BUFFER_SIZES[1]}
  fi

fi
