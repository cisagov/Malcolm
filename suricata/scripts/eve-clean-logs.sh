#!/bin/bash

FILE_AGE_MIN=${LOG_CLEANUP_MINUTES:-30}

if (( $FILE_AGE_MIN > 0 )); then
    find "${SURICATA_LOG_DIR:-/var/log/suricata}"/ -type f -name "*.json" -mmin +$FILE_AGE_MIN -delete
fi
