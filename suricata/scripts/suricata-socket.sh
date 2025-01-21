#!/bin/bash

[[ -x /usr/bin/suricata-offline ]] && SURICATA_BIN=/usr/bin/suricata-offline || SURICATA_BIN=/usr/bin/suricata
SURICATA_CONFIG_FILE=${SURICATA_CONFIG_FILE:-/etc/suricata/suricata.yaml}
SURICATA_LOG_DIR=${SURICATA_LOG_DIR:-/var/log/suricata}
[[ -z "$PCAP_PIPELINE_VERBOSITY" ]] && SURICATA_VERBOSE_FLAG= || SURICATA_VERBOSE_FLAG=-v

"${SURICATA_BIN}" "${SURICATA_VERBOSE_FLAG}" \
    --unix-socket \
    --set unix-command.enabled=true \
    -c "${SURICATA_CONFIG_FILE}" \
    -l "${SURICATA_LOG_DIR}"
