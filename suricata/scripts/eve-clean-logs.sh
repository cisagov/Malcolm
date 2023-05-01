#!/bin/bash

# Copyright (c) 2023 Battelle Energy Alliance, LLC.  All rights reserved.

# Clean up suricata log files that have reached a certain age. If we can
# verify they've been parsed and logged at least one event to the database,
# clean them up. If they haven't logged an event to the database, only clean
# them up if they're even older.

set -o pipefail

# for live traffic capture we don't need to do this check
if [[ "${SURICATA_LIVE_CAPTURE:-false}" != "true" ]]; then

    CURRENT_TIME="$(date -u +%s)"
    FILE_AGE_MIN=${LOG_CLEANUP_MINUTES:-30}
    FILE_AGE_MIN_UNKNOWN=$(( FILE_AGE_MIN * 2 ))

    if (( $FILE_AGE_MIN > 0 )); then
        find "${SURICATA_LOG_DIR:-/var/log/suricata}"/ -type f -name "*.json" -mmin +$FILE_AGE_MIN | while read LOGFILE
        do

            # query the database to see if any records exist from parsing this log file
            DOCUMENT_FOUND=$(
                curl -sSL -XPOST \
                    -H 'Content-Type: application/json' \
                    'http://api:5000/mapi/document' \
                    -d "{\"limit\":1,\"filter\":{\"log.file.path\":\"$(basename $LOGFILE)\"}}" 2>/dev/null \
                | jq '.results | length' 2>/dev/null || echo '0')

            if (( $DOCUMENT_FOUND > 0 )) || (( $(stat --printf='%s' "$LOGFILE" 2>/dev/null || echo -n '1') == 0 )); then
                # at least one log document exists in the database (or the file is empty), assume it's safe to clean up now
                rm -f "$LOGFILE"

            else
                # the document doesn't exist in the database. still clean it up, but only if it's quite a bit older
                MODIFY_TIME="$(stat -c %Y "$LOGFILE" 2>/dev/null || echo '0')"
                MODIFY_AGE_MINS=$(( (CURRENT_TIME - MODIFY_TIME) / 60))
                if (( $MODIFY_AGE_MINS >= $FILE_AGE_MIN_UNKNOWN )); then
                    rm -f "$LOGFILE"
                fi
            fi

        done # loop over found files at least FILE_AGE_MIN old
    fi # FILE_AGE_MIN is set (suricata log cleaning is enabled)

fi