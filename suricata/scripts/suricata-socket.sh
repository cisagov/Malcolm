#!/bin/bash

set -e
set -u
set -o pipefail

ENCODING="utf-8"

[[ -x /usr/bin/suricata-offline ]] && SURICATA_BIN=/usr/bin/suricata-offline || SURICATA_BIN=/usr/bin/suricata
SURICATA_CONFIG_FILE=${SURICATA_CONFIG_FILE:-/etc/suricata/suricata.yaml}
SURICATA_LOG_DIR=${SURICATA_LOG_DIR:-/var/log/suricata}

"${SURICATA_BIN}" -v \
    --unix-socket \
    --set unix-command.enabled=true \
    -c "${SURICATA_CONFIG_FILE}" \
    -l "${SURICATA_LOG_DIR}"
