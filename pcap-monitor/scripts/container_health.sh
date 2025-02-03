#!/bin/bash

set -euo pipefail

# check if pcap-monitor process is running via supervisorctl
supervisorctl status watch-upload   | grep -q "RUNNING" || exit 1
supervisorctl status pcap-publisher | grep -q "RUNNING" || exit 1

# if we got here, everything is good
exit 0 