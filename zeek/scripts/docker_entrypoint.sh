#!/bin/bash

ZEEK_DIR=${ZEEK_DIR:-"/opt/zeek"}

# ensure capabilities for capture
setcap 'CAP_NET_RAW+eip CAP_NET_ADMIN+eip' /sbin/ethtool || true
setcap 'CAP_NET_RAW+eip CAP_NET_ADMIN+eip CAP_IPC_LOCK+eip' "${ZEEK_DIR}"/bin/zeek || true
setcap 'CAP_NET_RAW+eip CAP_NET_ADMIN+eip CAP_IPC_LOCK+eip' "${ZEEK_DIR}"/bin/capstats || true

if [[ "${ZEEK_LIVE_CAPTURE:-false}" != "true" ]] && [[ -x "${ZEEK_DIR}"/bin/zeek_intel_setup.sh ]]; then
    sleep 15 # give the "live" instance, if there is one, a chance to go first
    if [[ "$(id -u)" == "0" ]] && [[ -n "$PUSER" ]]; then
        su -s /bin/bash -p ${PUSER} << EOF
            "${ZEEK_DIR}"/bin/zeek_intel_setup.sh /bin/true
EOF
    else
        "${ZEEK_DIR}"/bin/zeek_intel_setup.sh /bin/true
    fi
fi

# start supervisor (which will spawn pcap-zeek, cron, etc.) or whatever the default command is
exec "$@"
