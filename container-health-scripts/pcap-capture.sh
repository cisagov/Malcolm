#!/usr/bin/env bash

set -euo pipefail

[[ "${PCAP_CAPTURE_DISABLED:-false}" == 'true' ]] && exit 0

(( $(supervisorctl status 2>/dev/null | grep -cPv '(STARTING|RUNNING|Not started$)') == 0 )) && exit 0 || exit 1

