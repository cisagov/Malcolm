#!/bin/bash

if [[ -n $SUPERVISOR_PATH ]] && [[ -r /usr/local/bin/suricata_config_populate.py ]]; then
    # all arguments are controlled via environment variables sourced from control_vars.conf
    SURICATA_CUSTOM_RULES_DIR="$SUPERVISOR_PATH"/suricata/rules
    [[ -d "$SURICATA_CUSTOM_RULES_DIR" ]] && export SURICATA_CUSTOM_RULES_DIR
    python3 /usr/local/bin/suricata_config_populate.py
fi
