#!/bin/bash

# modify suricata.yaml according to environment variables
/usr/local/bin/suricata_config_populate.py ${SURICATA_TEST_CONFIG_VERBOSITY:-} >&2

# start supervisor (which will spawn pcap-suricata, cron, etc.) or whatever the default command is
exec "$@"
