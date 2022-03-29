#!/bin/bash

# Copyright (c) 2022 Battelle Energy Alliance, LLC.  All rights reserved.

if [[ -n $SUPERVISOR_PATH ]] && [[ -d "$SUPERVISOR_PATH"/supercronic ]]; then

    # clear out supercronic crontab and repopulate based on autostart variables
    CRONTAB_PATH="$SUPERVISOR_PATH"/supercronic/crontab
    > "$CRONTAB_PATH"

    # suricata updates
    if [[ "${AUTOSTART_SURICATA_UPDATES:-false}" == "true" ]]; then
        [[ "${SURICATA_REFRESH_ETOPEN:-true}" == "true" ]] && ETOPEN_FLAG="--etopen" || ETOPEN_FLAG=
        echo "${SURICATA_REFRESH_CRON_EXPRESSION:-15 2 * * *} /usr/bin/suricata-update -v -D \"${SURICATA_MANAGED_DIR:-/var/lib/suricata}\" --local \"${SURICATA_CUSTOM_RULES_DIR:-/etc/suricata/rules/custom}\" $ETOPEN_FLAG --reload-command='kill -USR2 \$(pidof suricata)'" >> "$CRONTAB_PATH"
    fi
fi
