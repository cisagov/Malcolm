#!/usr/bin/env bash

set -euo pipefail

if [[ "${SURICATA_LIVE_CAPTURE:-false}" == "true" ]]; then
    supervisorctl status live-suricata >/dev/null 2>&1
elif [[ "${SURICATA_PCAP_PROCESSOR:-true}" == "true" ]]; then
    supervisorctl status pcap-suricata socket-suricata >/dev/null 2>&1
else
    (( $(supervisorctl status 2>/dev/null | grep -cPv '(STARTING|RUNNING|Not started$)') == 0 )) && exit 0 || exit 1
fi
