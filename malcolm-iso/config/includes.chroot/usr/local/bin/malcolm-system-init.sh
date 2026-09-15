#!/bin/bash

# Copyright (c) 2026 Battelle Energy Alliance, LLC. All rights reserved.

set -euo pipefail

CAPTURE_STORAGE_FORMAT_FILE=''
CAPTURE_STORAGE_ARGS=(-u)

if [[ -f /etc/capture_storage_format.crypt ]]; then
  CAPTURE_STORAGE_FORMAT_FILE='/etc/capture_storage_format.crypt'
  CAPTURE_STORAGE_ARGS+=(-c)
elif [[ -f /etc/capture_storage_format ]]; then
  CAPTURE_STORAGE_FORMAT_FILE='/etc/capture_storage_format'
fi

# On initial boot, format and configure capture-storage drives.
if [[ -n "$CAPTURE_STORAGE_FORMAT_FILE" ]]; then
  logger --tag malcolm-system-init 'Initializing disk(s) to store captured artifacts'

  {
    date
    /usr/bin/python3 \
      /usr/local/bin/os-disk-config.py \
      "${CAPTURE_STORAGE_ARGS[@]}"
  } >>/var/log/os-disk-config.log 2>&1

  rm -f "$CAPTURE_STORAGE_FORMAT_FILE"
fi

# Perform aggregator-specific initialization.
logger --tag malcolm-system-init 'Running Malcolm initialization'
/usr/local/bin/agg-init.sh

# Disable Ctrl+Alt+Delete.
systemctl mask ctrl-alt-del.target

# Initialize the AIDE database when needed.
if [[ -x /usr/sbin/aideinit ]] &&
   [[ ! -s /var/lib/aide/aide.db ]]; then
  : >/var/lib/aide/aide.db
  /usr/sbin/aideinit --yes --force
fi