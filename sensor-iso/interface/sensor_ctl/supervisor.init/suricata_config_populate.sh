#!/bin/bash

if [[ -n $SUPERVISOR_PATH ]] && [[ -r /usr/local/bin/suricata_config_populate.py ]]; then

    # if there's a previous eve.json file, rename it prior to starting up
    [[ -n $ZEEK_LOG_PATH ]] && [[ -f "$ZEEK_LOG_PATH"/suricata/eve.json ]] && \
        mv -f "$ZEEK_LOG_PATH/suricata/eve.json" \
              "$ZEEK_LOG_PATH/suricata/eve.json.$(date -d @$(stat -c%Y "$ZEEK_LOG_PATH/suricata/eve.json") +'%Y%m%d%H%M%S')"

    # if there's no configuration files to modify, start with the defaults
    [[ ! -f "$SUPERVISOR_PATH"/suricata/suricata.yaml ]] && cp /etc/suricata/suricata.yaml "$SUPERVISOR_PATH"/suricata/suricata.yaml
    [[ ! -f "$SUPERVISOR_PATH"/suricata/update.yaml ]] && cp "$(dpkg -L suricata-update | grep 'update\.yaml' | head -n 1)" "$SUPERVISOR_PATH"/suricata/update.yaml

    # specify the custom rules directory relative to the supervisor path
    SURICATA_CUSTOM_RULES_DIR="$SUPERVISOR_PATH"/suricata/rules
    [[ -d "$SURICATA_CUSTOM_RULES_DIR" ]] && export SURICATA_CUSTOM_RULES_DIR

    # all other arguments are controlled via environment variables sourced from control_vars.conf
    python3 /usr/local/bin/suricata_config_populate.py

fi
