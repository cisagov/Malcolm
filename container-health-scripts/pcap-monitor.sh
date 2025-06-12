#!/usr/bin/env bash

set -euo pipefail

supervisorctl status pcap-publisher >/dev/null 2>&1