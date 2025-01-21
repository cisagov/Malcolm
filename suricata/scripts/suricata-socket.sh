#!/bin/bash

[[ -x /usr/bin/suricata-offline ]] && SURICATA_BIN=/usr/bin/suricata-offline || SURICATA_BIN=/usr/bin/suricata
SURICATA_CONFIG_FILE=${SURICATA_CONFIG_FILE:-/etc/suricata/suricata.yaml}
SURICATA_LOG_DIR=${SURICATA_LOG_DIR:-/var/log/suricata}
SURICATA_VERBOSE_FLAG=${PCAP_PIPELINE_VERBOSITY:-}

"${SURICATA_BIN}" "${SURICATA_VERBOSE_FLAG}" \
    --unix-socket \
    --set unix-command.enabled=true \
    -c "${SURICATA_CONFIG_FILE}" \
    -l "${SURICATA_LOG_DIR}"
