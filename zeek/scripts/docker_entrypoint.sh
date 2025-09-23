#!/bin/bash

ZEEK_DIR=${ZEEK_DIR:-"/opt/zeek"}

# ensure capabilities for capture
setcap 'CAP_NET_RAW+eip CAP_NET_ADMIN+eip' "${ZEEK_DIR}"/bin/zeek 2>/dev/null || true
setcap 'CAP_NET_RAW+eip CAP_NET_ADMIN+eip' "${ZEEK_DIR}"/bin/capstats 2>/dev/null || true

# generate packet statistics for network interfaces periodically
if [[ -d "${ZEEK_LOG_PATH}" ]] && [[ -n "${SUPERCRONIC_CRONTAB}" ]]; then

    touch "${SUPERCRONIC_CRONTAB}" 2>/dev/null || true
    sed -i -e "/netdev-json\.sh/d" "${SUPERCRONIC_CRONTAB}"

    [[ -n "${PCAP_IFACE_STATS_CRON_EXPRESSION}" ]] && \
      echo "${PCAP_IFACE_STATS_CRON_EXPRESSION} /usr/local/bin/netdev-json.sh >\"${ZEEK_LOG_PATH}\"/netdev-stats.json.tmp 2>/dev/null && mv -f \"${ZEEK_LOG_PATH}\"/netdev-stats.json.tmp \"${ZEEK_LOG_PATH}\"/netdev-stats.json" \
         >> "${SUPERCRONIC_CRONTAB}"
fi

# start supervisor (which will spawn pcap-zeek, cron, etc.) or whatever the default command is
exec "$@"
