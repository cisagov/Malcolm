#!/usr/bin/env bash

set -euo pipefail

if [[ "${SURICATA_LIVE_CAPTURE:-false}" == "true" ]]; then
    supervisorctl status live-suricata >/dev/null 2>&1
elif [[ "${SURICATA_PCAP_PROCESSOR:-true}" == "true" ]]; then
    supervisorctl status pcap-suricata $(seq -f "socket-suricata-%g" 1 "${SURICATA_AUTO_ANALYZE_PCAP_PROCESSES:-1}") >/dev/null 2>&1
else
    (( $(supervisorctl status 2>/dev/null | grep -cPv '(^INFO:|STARTING|RUNNING|Not started$)') == 0 )) && exit 0 || exit 1
fi
