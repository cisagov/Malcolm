#!/usr/bin/env bash

set -euo pipefail

supervisorctl status pcap-suricata socket-suricata >/dev/null 2>&1
