#!/bin/bash

ZEEK_DIR=${ZEEK_DIR:-"/opt/zeek"}

# ensure capabilities for capture
setcap 'CAP_NET_RAW+eip CAP_NET_ADMIN+eip' "${ZEEK_DIR}"/bin/zeek 2>/dev/null || true
setcap 'CAP_NET_RAW+eip CAP_NET_ADMIN+eip' "${ZEEK_DIR}"/bin/capstats 2>/dev/null || true

# start supervisor (which will spawn pcap-zeek, cron, etc.) or whatever the default command is
exec "$@"
