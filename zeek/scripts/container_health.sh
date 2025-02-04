#!/usr/bin/env bash

# the zeek container is considered "healthy" if the intel population script OR the (live|pcap)-zeek process is running

if [[ "${ZEEK_LIVE_CAPTURE:-false}" == "true" ]]; then
    supervisorctl status live-zeek >/dev/null 2>&1
elif [[ "${ZEEK_PCAP_PROCESSOR:-true}" == "true" ]]; then
    if [[ "${ZEEK_INTEL_REFRESH_ON_STARTUP:-false}" == "true" ]]; then
        ( ps a 2>/dev/null | grep -q '[z]eek_intel_from_threat_feed.py' ) || supervisorctl status pcap-zeek >/dev/null 2>&1
    else
        supervisorctl status pcap-zeek >/dev/null 2>&1
    fi
else
    (( $(supervisorctl status 2>/dev/null | grep -cPv '(STARTING|RUNNING|Not started$)') == 0 )) && exit 0 || exit 1
fi
