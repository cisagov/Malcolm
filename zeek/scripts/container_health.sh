#!/bin/bash

# the zeek container is considered "healthy" if the intel population script OR the (live|pcap)-zeek process is running

if [[ "${ZEEK_LIVE_CAPTURE:-false}" == "true" ]]; then
    supervisorctl status live-zeek >/dev/null 2>&1
else
    if [[ "${ZEEK_INTEL_REFRESH_ON_STARTUP:-false}" == "true" ]]; then
        ( ps a 2>/dev/null | grep -q '[z]eek_intel_from_threat_feed.py' ) || supervisorctl status pcap-zeek >/dev/null 2>&1
    else
        supervisorctl status pcap-zeek >/dev/null 2>&1
    fi
fi
