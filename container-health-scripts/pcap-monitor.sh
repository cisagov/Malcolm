#!/usr/bin/env bash

set -euo pipefail

supervisorctl status pcap-publisher watch-upload >/dev/null 2>&1
