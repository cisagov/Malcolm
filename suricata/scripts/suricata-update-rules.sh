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

  [[ "${SURICATA_UPDATE_ETOPEN:-"true"}" == "true" ]] && ETOPEN_FLAG="--etopen" || ETOPEN_FLAG=""
  if [[ "${SURICATA_UPDATE_DEBUG:-"false"}" == "true" ]]; then
    DEBUG_FLAG="--verbose"
    UPDATE_IGNORE_FLAG=
    UPDATE_IGNORE="."
  else
    DEBUG_FLAG="--quiet"
    UPDATE_IGNORE_FLAG="-v"
    UPDATE_IGNORE='with same revision, keeping the first rule seen'
  fi

  suricata-update update-sources \
    $DEBUG_FLAG \
    --data-dir "${SURICATA_MANAGED_DIR:-/var/lib/suricata}" \
    --config "${SURICATA_UPDATE_CONFIG_FILE:-/etc/suricata/update.yaml}" \
    --suricata-conf "${SURICATA_CONFIG_FILE:-/etc/suricata/suricata.yaml}" 2>&1

  suricata-update update \
    $DEBUG_FLAG \
    $ETOPEN_FLAG \
    --data-dir "${SURICATA_MANAGED_DIR:-/var/lib/suricata}" \
    --config "${SURICATA_UPDATE_CONFIG_FILE:-/etc/suricata/update.yaml}" \
    --suricata-conf "${SURICATA_CONFIG_FILE:-/etc/suricata/suricata.yaml}" \
    --fail 2>&1 | grep $UPDATE_IGNORE_FLAG "$UPDATE_IGNORE"

else
  exit 1
fi
