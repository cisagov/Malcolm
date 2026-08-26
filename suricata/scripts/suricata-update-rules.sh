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

  [[ "${SURICATA_UPDATE_SOURCES:-"true"}" == "true" ]] && \
    suricata-update update-sources \
      $DEBUG_FLAG \
      --suricata /usr/bin/suricata-offline \
      --data-dir "${SURICATA_MANAGED_DIR:-/var/lib/suricata}" \
      --config "${SURICATA_UPDATE_CONFIG_FILE:-/etc/suricata/update.yaml}" \
      --suricata-conf "${SURICATA_CONFIG_FILE:-/etc/suricata/suricata.yaml}" 2>&1

  # Enable indexed rule sources requested through the environment. Source specs are
  # comma-separated; optional source parameters are separated from the source name
  # with '|', for example: et/pro|secret-code=example.
  if [[ -n "${SURICATA_UPDATE_ENABLE_SOURCES:-}" ]]; then
    IFS=',' read -r -a SOURCE_SPECS <<< "${SURICATA_UPDATE_ENABLE_SOURCES}"
    for SOURCE_SPEC in "${SOURCE_SPECS[@]}"; do
      IFS='|' read -r -a SOURCE_PARTS <<< "${SOURCE_SPEC}"
      SOURCE_NAME="${SOURCE_PARTS[0]}"
      SOURCE_NAME="${SOURCE_NAME#"${SOURCE_NAME%%[![:space:]]*}"}"
      SOURCE_NAME="${SOURCE_NAME%"${SOURCE_NAME##*[![:space:]]}"}"
      [[ -n "${SOURCE_NAME}" ]] || continue

      SOURCE_PARAMS=()
      if [[ ${#SOURCE_PARTS[@]} -gt 1 ]]; then
        for SOURCE_PARAM in "${SOURCE_PARTS[@]:1}"; do
          SOURCE_PARAM="${SOURCE_PARAM#"${SOURCE_PARAM%%[![:space:]]*}"}"
          SOURCE_PARAM="${SOURCE_PARAM%"${SOURCE_PARAM##*[![:space:]]}"}"
          [[ -n "${SOURCE_PARAM}" ]] && SOURCE_PARAMS+=("${SOURCE_PARAM}")
        done
      fi

      suricata-update enable-source \
        "${SOURCE_NAME}" \
        "${SOURCE_PARAMS[@]}" \
        $DEBUG_FLAG \
        --suricata /usr/bin/suricata-offline \
        --data-dir "${SURICATA_MANAGED_DIR:-/var/lib/suricata}" \
        --config "${SURICATA_UPDATE_CONFIG_FILE:-/etc/suricata/update.yaml}" \
        --suricata-conf "${SURICATA_CONFIG_FILE:-/etc/suricata/suricata.yaml}" 2>&1
    done
  fi

  suricata-update update \
    $DEBUG_FLAG \
    $ETOPEN_FLAG \
    --suricata /usr/bin/suricata-offline \
    --data-dir "${SURICATA_MANAGED_DIR:-/var/lib/suricata}" \
    --config "${SURICATA_UPDATE_CONFIG_FILE:-/etc/suricata/update.yaml}" \
    --suricata-conf "${SURICATA_CONFIG_FILE:-/etc/suricata/suricata.yaml}" \
    --fail 2>&1 | grep $UPDATE_IGNORE_FLAG "$UPDATE_IGNORE"


    SURICATA_RUN_DIR="${SURICATA_RUN_DIR:-}"
    [[ -z "$SURICATA_RUN_DIR" ]] && SURICATA_RUN_DIR="${SUPERVISOR_PATH:-/var/run}/suricata"
    SURICATA_SOCKET="$SURICATA_RUN_DIR"/suricata-command.socket

    test -S "$SURICATA_SOCKET" >/dev/null 2>&1 && \
      suricatasc "$SURICATA_SOCKET" -c ruleset-reload-nonblocking >/dev/null 2>&1

else
  exit 1
fi
