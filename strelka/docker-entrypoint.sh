#!/usr/bin/env bash

set -euo pipefail

is_truthy() {
  [[ $# -eq 0 ]] && return 1

  case "${1,,}" in
    1|true|yes|t|y) return 0 ;;
  esac

  return 1
}

set_config() {
  local file="$1"
  local key="$2"
  local value="$3"

  # match lines like:
  #   Key value
  #   # Key value
  if grep -Eq "^[[:space:]]*#?[[:space:]]*${key}[[:space:]]+" "$file"; then
    sed -i \
      -E "s|^[[:space:]]*#?[[:space:]]*${key}[[:space:]]+.*$|${key} ${value}|" \
      "$file"
  else
    echo "${key} ${value}" >> "$file"
  fi
}

# expand REDIS environment variables into the appropriate config yaml files
FILES=(
  /etc/strelka/manager.yaml
  /etc/strelka/backend.yaml
  /etc/strelka/frontend.yaml
)

for FILE in "${FILES[@]}"; do
  if [[ -f "${FILE}" ]]; then
    yq -i '
      .coordinator.addr = strenv(REDIS_CACHE_HOST) + ":" + strenv(REDIS_CACHE_PORT) |
      .coordinator.db = (strenv(REDIS_STRELKA_COORDINATOR_CACHE_DATABASE) | tonumber) |
      .coordinator.password = strenv(REDIS_PASSWORD) |
      .gatekeeper.addr = strenv(REDIS_CACHE_HOST) + ":" + strenv(REDIS_CACHE_PORT) |
      .gatekeeper.db = (strenv(REDIS_STRELKA_GATEKEEPER_CACHE_DATABASE) | tonumber) |
      .gatekeeper.password = strenv(REDIS_PASSWORD)
    ' "${FILE}"
  fi
done

# special handling for strelka-backend
if [[ -f /etc/strelka/backend.yaml ]] && [[ -n "${CLAMD_SOCKET_FILE:-}" ]]; then
  yq eval -i '
  .scanners."ScanClamav"[0].options.clamd_socket = strenv(CLAMD_SOCKET_FILE)
    // .scanners."ScanClamav"[0].options.clamd_socket
  ' /etc/strelka/backend.yaml
fi

if [[ -f /etc/clamav/clamd.conf ]]; then
  # see https://manpages.debian.org/stable/clamav-daemon/clamd.conf.5.en.html

  [[ -n "${CLAMD_SOCKET_FILE:-}" ]] && \
    set_config /etc/clamav/clamd.conf LocalSocket "${CLAMD_SOCKET_FILE}"

  [[ -n "${EXTRACTED_FILE_MAX_BYTES:-}" ]] && \
    set_config /etc/clamav/clamd.conf MaxFileSize "${EXTRACTED_FILE_MAX_BYTES}" && \
    set_config /etc/clamav/clamd.conf MaxScanSize "$(( EXTRACTED_FILE_MAX_BYTES * 4 ))"

  [[ -n "${CLAMD_MAX_EMBEDDED_PE_SIZE:-}" ]] && \
    set_config /etc/clamav/clamd.conf MaxEmbeddedPE "${CLAMD_MAX_EMBEDDED_PE_SIZE}"

  [[ -n "${CLAMD_MAX_THREADS:-}" ]] && \
    set_config /etc/clamav/clamd.conf MaxThreads "${CLAMD_MAX_THREADS}"

  [[ -n "${CLAMD_MAX_RECURSION:-}" ]] && \
    set_config /etc/clamav/clamd.conf MaxRecursion "${CLAMD_MAX_RECURSION}"

  [[ -n "${CLAMD_MAX_DIR_RECURSION:-}" ]] && \
    set_config /etc/clamav/clamd.conf MaxDirectoryRecursion "${CLAMD_MAX_DIR_RECURSION}"

  [[ -n "${CLAMD_MAX_QUEUE:-}" ]] && \
    set_config /etc/clamav/clamd.conf MaxQueue "${CLAMD_MAX_QUEUE}"

  [[ -n "${CLAMD_MAX_CONN_QUEUE:-}" ]] && \
    set_config /etc/clamav/clamd.conf MaxConnectionQueueLength "${CLAMD_MAX_CONN_QUEUE}"

  [[ -n "${CLAMD_MAX_SCAN_MS:-}" ]] && \
    set_config /etc/clamav/clamd.conf MaxScanTime "${CLAMD_MAX_SCAN_MS}"

  if is_truthy "${CLAMD_ALERT_EXCEEDS_MAX:-false}"; then
    set_config /etc/clamav/clamd.conf AlertExceedsMax true
  else
    set_config /etc/clamav/clamd.conf AlertExceedsMax false
  fi
fi

[[ $# -gt 0 ]] && exec "$@"
