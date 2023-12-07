#!/bin/bash

# ensure capabilities for capture
setcap 'CAP_NET_RAW+eip CAP_NET_ADMIN+eip' /sbin/ethtool || true
setcap 'CAP_NET_RAW+eip CAP_NET_ADMIN+eip CAP_IPC_LOCK+eip' /usr/bin/suricata || true

# modify suricata.yaml according to environment variables (as non-root)
if [[ "$(id -u)" == "0" ]] && [[ -n "$PUSER" ]]; then
    su -s /bin/bash -p ${PUSER} << EOF
        /usr/local/bin/suricata_config_populate.py ${SURICATA_TEST_CONFIG_VERBOSITY:-} >&2
EOF
else
    /usr/local/bin/suricata_config_populate.py ${SURICATA_TEST_CONFIG_VERBOSITY:-} >&2
fi

# start supervisor (which will spawn pcap-suricata, cron, etc.) or whatever the default command is
exec "$@"
