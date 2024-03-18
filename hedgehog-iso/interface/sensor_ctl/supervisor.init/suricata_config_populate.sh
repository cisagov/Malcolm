#!/bin/bash

if [[ -n $SUPERVISOR_PATH ]] && [[ -r /usr/local/bin/suricata_config_populate.py ]]; then

    # if there's no configuration files to modify, start with the defaults
    [[ ! -f "$SUPERVISOR_PATH"/suricata/suricata.yaml ]] && cp /etc/suricata/suricata.yaml "$SUPERVISOR_PATH"/suricata/suricata.yaml
    [[ ! -f "$SUPERVISOR_PATH"/suricata/update.yaml ]] && cp "$(dpkg -L suricata-update | grep 'update\.yaml' | head -n 1)" "$SUPERVISOR_PATH"/suricata/update.yaml

    # specify the custom rules and configuration directories relative to the supervisor path
    SURICATA_DEFAULT_RULES_DIR="$SUPERVISOR_PATH"/suricata/rules-default
    SURICATA_CUSTOM_RULES_DIR="$SUPERVISOR_PATH"/suricata/rules
    SURICATA_CUSTOM_CONFIG_DIR="$SUPERVISOR_PATH"/suricata/include-configs
    [[ -d "$SURICATA_DEFAULT_RULES_DIR" ]] && export SURICATA_DEFAULT_RULES_DIR
    [[ -d "$SURICATA_CUSTOM_RULES_DIR" ]] && export SURICATA_CUSTOM_RULES_DIR
    [[ -d "$SURICATA_CUSTOM_CONFIG_DIR" ]] && export SURICATA_CUSTOM_CONFIG_DIR

    # all other arguments are controlled via environment variables sourced from control_vars.conf
    python3 /usr/local/bin/suricata_config_populate.py

fi
