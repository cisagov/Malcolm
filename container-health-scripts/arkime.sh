#!/usr/bin/env bash

set -euo pipefail

if [[ "${ARKIME_LIVE_CAPTURE:-false}" == "true" ]]; then
    supervisorctl status live-arkime >/dev/null 2>&1
elif [[ "${ARKIME_PCAP_PROCESSOR:-true}" == "true" ]] && [[ "${MALCOLM_PROFILE:-malcolm}" == "malcolm" ]]; then
    [[ "${ARKIME_SSL:-true}" == "true" ]] && STATUS_PROTOCOL=https || STATUS_PROTOCOL=http
    curl --insecure --silent --output /dev/null --fail "${STATUS_PROTOCOL}://localhost:${ARKIME_VIEWER_PORT:-8005}/_ns_/nstest.html"
else
    (( $(supervisorctl status 2>/dev/null | grep -cPv '(^INFO:|STARTING|RUNNING|EXITED|Not started$)') == 0 )) && exit 0 || exit 1
fi
