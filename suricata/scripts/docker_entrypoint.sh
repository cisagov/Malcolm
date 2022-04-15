#!/bin/bash
set -e

/usr/local/bin/suricata_config_populate.sh >&2

# start supervisor (which will spawn pcap-suricata, cron, etc.) or whatever the default command is
exec "$@"
