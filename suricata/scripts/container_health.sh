#!/bin/bash

set -euo pipefail

# check if suricata process is running via supervisorctl
supervisorctl status pcap-suricata | grep -q "RUNNING" || exit 1

# if we got here, everything is good
exit 0 