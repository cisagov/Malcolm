#!/bin/bash

# ensure capabilities for capture
setcap 'CAP_NET_RAW+eip CAP_NET_ADMIN+eip CAP_IPC_LOCK+eip' /usr/bin/suricata || true

[[ -x /usr/bin/suricata-offline ]] && export SURICATA_TEST_CONFIG_BIN=/usr/bin/suricata-offline || export SURICATA_TEST_CONFIG_BIN=/usr/bin/suricata


# - modify suricata.yaml according to environment variables (as non-root)
# - if SURICATA_DISABLE_SIDS contains entries for disable.conf, write it and run suricata-update to apply
if [[ "$(id -u)" == "0" ]] && [[ -n "$PUSER" ]]; then
    su -s /bin/bash -p ${PUSER} << 'EOF'
        /usr/local/bin/suricata_config_populate.py --suricata ${SURICATA_TEST_CONFIG_BIN} ${SURICATA_TEST_CONFIG_VERBOSITY:-} >&2
        if [[ -n "${SURICATA_DISABLE_SIDS}" ]]; then
            tr ',' '\n' <<<"${SURICATA_DISABLE_SIDS}" | awk '{ gsub(/^[[:space:]]+|[[:space:]]+$/, ""); if (length) print }' | \
                while IFS= read -r line; do
                    grep -qxF "$line" /etc/suricata/disable.conf 2>/dev/null || echo "$line"
                done >> /etc/suricata/disable.conf
            SURICATA_UPDATE_RULES=true SURICATA_UPDATE_SOURCES=false SURICATA_UPDATE_ETOPEN=false /usr/local/bin/suricata-update-rules.sh
        fi
EOF
else
    /usr/local/bin/suricata_config_populate.py --suricata ${SURICATA_TEST_CONFIG_BIN} ${SURICATA_TEST_CONFIG_VERBOSITY:-} >&2
    if [[ -n "${SURICATA_DISABLE_SIDS}" ]]; then
        tr ',' '\n' <<<"${SURICATA_DISABLE_SIDS}" | awk '{ gsub(/^[[:space:]]+|[[:space:]]+$/, ""); if (length) print }' | \
            while IFS= read -r line; do
                grep -qxF "$line" /etc/suricata/disable.conf 2>/dev/null || echo "$line"
            done >> /etc/suricata/disable.conf
        SURICATA_UPDATE_RULES=true SURICATA_UPDATE_SOURCES=false SURICATA_UPDATE_ETOPEN=false /usr/local/bin/suricata-update-rules.sh
    fi
fi

# generate 1..n suricata-offline socket instances
CONFIG_DIR="/etc/supervisor.d"
SURICATA_SOCKET_TEMPLATE_FILE="suricata-socket.template"
if [[ -d "$CONFIG_DIR" ]] && [[ -f "$CONFIG_DIR"/"$SURICATA_SOCKET_TEMPLATE_FILE" ]]; then
  rm -f "$CONFIG_DIR"/*.conf
  for INSTANCEID in $(seq 1 ${SURICATA_AUTO_ANALYZE_PCAP_PROCESSES:-1}); do
    export INSTANCEID
    mkdir -p "${SURICATA_LOG_DIR:-/var/log/suricata}/socket-$INSTANCEID" 2>/dev/null || true
    if [[ -d "${SURICATA_LOG_DIR:-/var/log/suricata}/socket-$INSTANCEID" ]]; then
        [[ -n ${PUID} ]] && chown -fR ${PUID} "${SURICATA_LOG_DIR:-/var/log/suricata}/socket-$INSTANCEID" || true
        [[ -n ${PGID} ]] && chown -fR :${PGID} "${SURICATA_LOG_DIR:-/var/log/suricata}/socket-$INSTANCEID" || true
    fi
    sed -e "s/[$]INSTANCEID/${INSTANCEID}/g" "$CONFIG_DIR"/"${SURICATA_SOCKET_TEMPLATE_FILE}" > "$CONFIG_DIR"/"${SURICATA_SOCKET_TEMPLATE_FILE%.*}-$INSTANCEID.conf"
  done
fi

# start supervisor (which will spawn pcap-suricata, cron, etc.) or whatever the default command is
exec "$@"
