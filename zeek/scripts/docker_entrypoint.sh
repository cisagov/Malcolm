#!/bin/bash

ZEEK_DIR=${ZEEK_DIR:-"/opt/zeek"}

# ensure capabilities for capture
setcap 'CAP_NET_RAW+eip CAP_NET_ADMIN+eip' "${ZEEK_DIR}"/bin/zeek 2>/dev/null || true
setcap 'CAP_NET_RAW+eip CAP_NET_ADMIN+eip' "${ZEEK_DIR}"/bin/capstats 2>/dev/null || true

if [[ "${ZEEK_INTEL_REFRESH_ON_ENTRYPOINT:-false}" == "true" ]] && \
   [[ -x "${ZEEK_DIR}"/bin/zeek_intel_setup.sh ]]; then
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
