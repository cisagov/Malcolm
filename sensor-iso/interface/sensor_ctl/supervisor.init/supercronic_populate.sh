#!/bin/bash

# Copyright (c) 2022 Battelle Energy Alliance, LLC.  All rights reserved.

if [[ -n $SUPERVISOR_PATH ]] && [[ -d "$SUPERVISOR_PATH"/supercronic ]]; then

    # clear out supercronic crontab and repopulate based on autostart variables
    CRONTAB_PATH="$SUPERVISOR_PATH"/supercronic/crontab
    > "$CRONTAB_PATH"

    # suricata updates
    if [[ "${AUTOSTART_SURICATA_UPDATES:-false}" == "true" ]] && \
       [[ -d "$SUPERVISOR_PATH"/suricata ]] && \
       [[ -r "$SUPERVISOR_PATH"/suricata/suricata.yaml ]] && \
       [[ -r "$SUPERVISOR_PATH"/suricata/update.yaml ]]; then

        SURICATA_DIR="$SUPERVISOR_PATH"/suricata
        SURICATA_CUSTOM_RULES_DIR="$SURICATA_DIR"/rules
        mkdir -p "$SURICATA_CUSTOM_RULES_DIR"
        SURICATA_CONFIG_FILE="$SURICATA_DIR"/suricata.yaml
        SURICATA_UPDATE_CONFIG_FILE="$SURICATA_DIR"/update.yaml

        /usr/bin/yq eval --inplace 'del(."disable-conf")' "$SURICATA_UPDATE_CONFIG_FILE"
        /usr/bin/yq eval --inplace 'del(."enable-conf")' "$SURICATA_UPDATE_CONFIG_FILE"
        /usr/bin/yq eval --inplace 'del(."drop-conf")' "$SURICATA_UPDATE_CONFIG_FILE"
        /usr/bin/yq eval --inplace 'del(."modify-conf")' "$SURICATA_UPDATE_CONFIG_FILE"
        /usr/bin/yq eval --inplace 'del(."reload-command")' "$SURICATA_UPDATE_CONFIG_FILE" 2>/dev/null || true

        /usr/bin/yq eval --inplace ".\"disable-conf\"=\"$SURICATA_DIR/disable.conf\"" "$SURICATA_UPDATE_CONFIG_FILE"
        /usr/bin/yq eval --inplace ".\"enable-conf\"=\"$SURICATA_DIR/enable.conf\"" "$SURICATA_UPDATE_CONFIG_FILE"
        /usr/bin/yq eval --inplace ".\"drop-conf\"=\"$SURICATA_DIR/drop.conf\"" "$SURICATA_UPDATE_CONFIG_FILE"
        /usr/bin/yq eval --inplace ".\"modify-conf\"=\"$SURICATA_DIR/modify.conf\"" "$SURICATA_UPDATE_CONFIG_FILE"
        /usr/bin/yq eval --inplace ".\"reload-command\"=\"kill -USR2 \$(pidof suricata)\"" "$SURICATA_UPDATE_CONFIG_FILE"

        /usr/bin/yq eval --inplace 'del(."sources")' "$SURICATA_UPDATE_CONFIG_FILE"
        if [[ "${SURICATA_REFRESH_ETOPEN:-true}" == "true" ]]; then
            ETOPEN_FLAG="--etopen"
            /usr/bin/yq eval --inplace ".\"sources\"=[\"https://rules.emergingthreats.net/open/suricata-%(__version__)s/emerging.rules.tar.gz\",\"https://sslbl.abuse.ch/blacklist/sslblacklist.rules\"]" "$SURICATA_UPDATE_CONFIG_FILE"
        else
            ETOPEN_FLAG=
        fi

        /usr/bin/yq eval --inplace 'del(."local")' "$SURICATA_UPDATE_CONFIG_FILE"
        /usr/bin/yq eval --inplace ".\"local\"=[\"/etc/suricata/rules\",\"$SURICATA_CUSTOM_RULES_DIR\"]" "$SURICATA_UPDATE_CONFIG_FILE"

        /usr/bin/yq --inplace -M '... comments=""' "$SURICATA_UPDATE_CONFIG_FILE"

        echo "${SURICATA_REFRESH_CRON_EXPRESSION:-15 2 * * *} /usr/bin/suricata-update --config \"$SURICATA_UPDATE_CONFIG_FILE\" --suricata-conf \"$SURICATA_CONFIG_FILE\" --data-dir \"${SURICATA_MANAGED_DIR:-/var/lib/suricata}\" $ETOPEN_FLAG" >> "$CRONTAB_PATH"
    fi # suricata updates
fi
