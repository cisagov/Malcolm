#!/usr/bin/env bash

set -euo pipefail

if [[ "${ARKIME_LIVE_CAPTURE:-false}" == "true" ]]; then
    supervisorctl status live-arkime >/dev/null 2>&1
elif [[ "${ARKIME_PCAP_PROCESSOR:-true}" == "true" ]]; then
    curl --insecure --silent --output /dev/null --fail "https://localhost:8005/_ns_/nstest.html"
else
    (( $(supervisorctl status 2>/dev/null | grep -cPv '(STARTING|RUNNING|Not started$)') == 0 )) && exit 0 || exit 1
fi
