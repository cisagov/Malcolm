#!/usr/bin/env bash

set -e
set -u
set -o pipefail

ENCODING="utf-8"

[[ "${SURICATA_UPDATE_RULES:-"false"}" == "true" ]] || exit 0

function finish {
  # nothing here at the moment
  true
}

if type suricata-update >/dev/null 2>&1; then
  trap finish EXIT

  [[ "${SURICATA_UPDATE_DEBUG:-"false"}" == "true" ]] && DEBUG_FLAG="--verbose" || DEBUG_FLAG="--quiet"
  [[ "${SURICATA_UPDATE_ETOPEN:-"true"}" == "true" ]] && ETOPEN_FLAG="--etopen" || ETOPEN_FLAG=""

  suricata-update update-sources \
    $DEBUG_FLAG \
    --data-dir "${SURICATA_MANAGED_DIR:-/var/lib/suricata}" \
    --config "${SURICATA_UPDATE_CONFIG_FILE:-/etc/suricata/update.yaml}" \
    --suricata-conf "${SURICATA_CONFIG_FILE:-/etc/suricata/suricata.yaml}"

  suricata-update update \
    $DEBUG_FLAG \
    $ETOPEN_FLAG \
    --data-dir "${SURICATA_MANAGED_DIR:-/var/lib/suricata}" \
    --config "${SURICATA_UPDATE_CONFIG_FILE:-/etc/suricata/update.yaml}" \
    --suricata-conf "${SURICATA_CONFIG_FILE:-/etc/suricata/suricata.yaml}" \
    --fail

else
  exit 1
fi
