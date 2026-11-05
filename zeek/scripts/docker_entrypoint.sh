#!/bin/bash

ZEEK_DIR=${ZEEK_DIR:-"/usr/local/zeek"}

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

ZEEK_DIR=${ZEEK_DIR:-"/usr/local/zeek"}

if [[ -z ${ZEEK_DISABLE_INTEL} ]]; then
  if [[ ${ZEEK_LIVE_CAPTURE} == "true" ]]; then
    [[ ${ZEEK_DISABLE_INTEL_LIVE} == "true" ]] && ZEEK_DISABLE_INTEL=true
  else
    [[ ${ZEEK_DISABLE_INTEL_OFFLINE} == "true" ]] && ZEEK_DISABLE_INTEL=true
  fi
fi
[[ -n ${ZEEK_DISABLE_INTEL} ]] && export ZEEK_DISABLE_INTEL

# warn (once, at container startup) if threat intelligence feeds will be pulled without TLS certificate verification
case "${ZEEK_INTEL_FEED_SSL_CERTIFICATE_VERIFICATION,,}" in
  true|t|yes|y|1) ;;
  *)
    echo "$(date '+%Y-%m-%d %H:%M:%S') WARNING: TLS certificate verification is disabled for threat intelligence feed retrieval" \
         "(ZEEK_INTEL_FEED_SSL_CERTIFICATE_VERIFICATION=${ZEEK_INTEL_FEED_SSL_CERTIFICATE_VERIFICATION:-false})." \
         "Credentials and indicators for any configured remote feeds (MISP, TAXII, Google Threat Intelligence) are not protected" \
         "against interception or tampering. Set ZEEK_INTEL_FEED_SSL_CERTIFICATE_VERIFICATION=true in zeek.env to require" \
         "certificate verification." >&2
    ;;
esac

# start supervisor (which will spawn pcap-zeek, cron, etc.) or whatever the default command is
exec "$@"
