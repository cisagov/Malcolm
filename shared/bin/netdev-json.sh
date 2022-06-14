#!/bin/bash

set -euo pipefail

# 1. get network interface statistics (/proc/net/dev)
# 2. remove leading spaces
# 3. ignore virtual/loopback/docker/etc. network interfaces
# 4. remove ':' after interface name
# 5. pipe through JQ (-R (read raw strings), -c (compact), -M (no colors), -s (slurp))
# 5-1. split on newlines
# 5-2. each line is an item in an array
# 5-3. each non-empty line is split on ' '
# 5-4. each item in the line is assigned to a key in a hash for that interface (converted to a number where appropriate)
# 5-5. convert the array to a hash indexed by 'interface'
# 5-6. remove statistics with 0 for a value
# 5-7. remove interfaces with no remaining values (i.e., nothing was non-zero)
#
# should produce something like:
# {"wlx687f747cef60":{"rx_bytes":27555146611,"rx_packets":22251062,"rx_drop":461763,"tx_bytes":2410464559,"tx_packets":13107298}}

INTERFACE_IGNORE_REGEX="^(lo:\s*|veth|virbr|vnet|docker)"

( tail -n +3 /proc/net/dev | sed "s/^[[:space:]]*//" | grep -Pv "$INTERFACE_IGNORE_REGEX" | tr -d ':' ) 2>/dev/null | \
  jq -R -c -M -s '
    {interfaces: [
      split("\n") |
      .[] |
      if length > 0 then
        gsub(" +"; " ") | split(" ") | {interface: .[0], rx_bytes: .[1]|tonumber, rx_packets: .[2]|tonumber, rx_errs: .[3]|tonumber, rx_drop: .[4]|tonumber, rx_fifo: .[5]|tonumber, rx_frame: .[6]|tonumber, rx_compressed: .[7]|tonumber, rx_multicast: .[8]|tonumber, tx_bytes: .[9]|tonumber, tx_packets: .[10]|tonumber, tx_errs: .[11]|tonumber, tx_drop: .[12]|tonumber, tx_fifo: .[13]|tonumber, tx_colls: .[14]|tonumber, tx_carrier: .[15]|tonumber, tx_compressed: .[16]|tonumber}
      else
        empty
      end
    ] | INDEX(.interface) | del(.. | .interface?) | del(..|select(. == 0)) | del(.. | select(. == {})) }'
