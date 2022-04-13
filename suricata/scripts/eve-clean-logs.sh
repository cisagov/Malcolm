#!/bin/bash

find "${SURICATA_LOG_DIR:-/var/log/suricata}"/ -type f -name "*.json" -mmin +30 -delete