#!/usr/bin/env bash

set -euo pipefail
shopt -s nullglob

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

# expand VALKEY environment variables into the appropriate config yaml files
FILES=(
  /etc/strelka/manager.yaml
  /etc/strelka/backend.yaml
  /etc/strelka/frontend.yaml
)

for FILE in "${FILES[@]}"; do
  if [[ -f "${FILE}" ]]; then
    yq -i '
      select(has("coordinator")) |= (
        .coordinator.addr = strenv(VALKEY_CACHE_HOST) + ":" + strenv(VALKEY_CACHE_PORT) |
        .coordinator.db = (strenv(VALKEY_STRELKA_COORDINATOR_CACHE_DATABASE) | tonumber) |
        .coordinator.password = strenv(VALKEY_PASSWORD)
      ) |
      select(has("gatekeeper")) |= (
        .gatekeeper.addr = strenv(VALKEY_CACHE_HOST) + ":" + strenv(VALKEY_CACHE_PORT) |
        .gatekeeper.db = (strenv(VALKEY_STRELKA_GATEKEEPER_CACHE_DATABASE) | tonumber) |
        .gatekeeper.password = strenv(VALKEY_PASSWORD)
      )
    ' "${FILE}"
  fi
done

# special handling for strelka-backend
BACKEND_YAML_FILE=/etc/strelka/backend.yaml
BACKEND_SCANNERS_DIR=/etc/strelka/scanners
declare -A ENABLED_SCANNER_SET=()

scanner_enabled() {
  local scanner_name="${1}"
  [[ -n "${ENABLED_SCANNER_SET[${scanner_name}]:-}" ]]
}

if [[ -f "${BACKEND_YAML_FILE}" ]] && [[ -d "${BACKEND_SCANNERS_DIR}" ]] && [[ -n "${STRELKA_SCANNERS}" ]]; then
  # Include enabled scanners (based on STRELKA_SCANNERS) from /etc/strelka/scanners
  yq -i '.scanners = {}' "${BACKEND_YAML_FILE}"

  declare -a DEFAULT_STRELKA_SCANNERS=()

  DEFAULTS_FILE="$(mktemp)" || exit 1
  trap 'rm -f "$DEFAULTS_FILE"' EXIT

  if ! PYTHONPATH=/usr/local/bin python3 - <<'PY' >"$DEFAULTS_FILE"
import sys

from malcolm_constants import MALCOLM_STRELKA_SCANNERS_DEFAULT

if not isinstance(MALCOLM_STRELKA_SCANNERS_DEFAULT, (list, tuple)):
    raise TypeError("MALCOLM_STRELKA_SCANNERS_DEFAULT must be a list or tuple")

for scanner in MALCOLM_STRELKA_SCANNERS_DEFAULT:
    if not isinstance(scanner, str):
        raise TypeError(f"scanner name must be a string, got {type(scanner).__name__}")
    if "\0" in scanner:
        raise ValueError("scanner names cannot contain NUL characters")

    sys.stdout.buffer.write(scanner.encode("utf-8") + b"\0")
PY
  then
    echo "Unable to load default Strelka scanners from malcolm_constants.py" >&2
    exit 1
  fi

  mapfile -d '' -t DEFAULT_STRELKA_SCANNERS <"$DEFAULTS_FILE"
  rm -f "$DEFAULTS_FILE"
  trap - EXIT

  IFS=',' read -r -a RAW_ENABLED_SCANNERS <<< "${STRELKA_SCANNERS:-}"

  for RAW_SCANNER in "${RAW_ENABLED_SCANNERS[@]}"; do
    TRIMMED_SCANNER="${RAW_SCANNER#"${RAW_SCANNER%%[![:space:]]*}"}"
    TRIMMED_SCANNER="${TRIMMED_SCANNER%"${TRIMMED_SCANNER##*[![:space:]]}"}"

    [[ -z "$TRIMMED_SCANNER" ]] && continue

    if [[ "$TRIMMED_SCANNER" == "default" ]]; then
      SCANNERS_TO_ADD=("${DEFAULT_STRELKA_SCANNERS[@]}")
    else
      SCANNERS_TO_ADD=("$TRIMMED_SCANNER")
    fi

    for SCANNER in "${SCANNERS_TO_ADD[@]}"; do
      [[ -n "$SCANNER" ]] && ENABLED_SCANNER_SET["$SCANNER"]=1
    done
  done

  # Build a regex for exact top-level key matching inside yq
  ENABLED_SCANNERS_REGEX="$(
    printf '%s\n' "${!ENABLED_SCANNER_SET[@]}" |
      sort |
      paste -sd'|' -
  )"
  ENABLED_SCANNERS_REGEX="^(${ENABLED_SCANNERS_REGEX})$"

  # Process each scanner file
  for SCANNER_FILE in "${BACKEND_SCANNERS_DIR}"/*.yaml "${BACKEND_SCANNERS_DIR}"/*.yml; do
    # Ignore invalid files
    if ! grep -q '[^[:space:]]' "${SCANNER_FILE}"; then
      printf 'warning: skipping empty scanner file: %s\n' "${SCANNER_FILE}" >&2
      continue
    elif ! yq -e '.' "${SCANNER_FILE}" >/dev/null 2>&1; then
      printf 'warning: skipping invalid scanner yaml: %s\n' "${SCANNER_FILE}" >&2
      continue
    elif [[ "$(yq e 'type' "${SCANNER_FILE}" 2>/dev/null)" != "!!map" ]]; then
      printf 'warning: skipping non-mapping scanner yaml: %s\n' "${SCANNER_FILE}" >&2
      continue
    fi

    # Merge only enabled top-level keys from this file
    if ! SCANNER_FILE="${SCANNER_FILE}" ENABLED_SCANNERS_REGEX="${ENABLED_SCANNERS_REGEX}" \
      yq -e -i '
        .scanners *= (
          load(strenv(SCANNER_FILE))
          | with_entries(select(.key | test(strenv(ENABLED_SCANNERS_REGEX))))
        )
      ' "${BACKEND_YAML_FILE}" >/dev/null 2>&1
    then
      printf 'warning: skipping scanner yaml with no enabled scanner keys: %s\n' "${SCANNER_FILE}" >&2
    fi
  done

  # Specify correct socket file name for ScanClamav
  if [[ -n "${CLAMD_SOCKET_FILE:-}" ]] && scanner_enabled "ScanClamav"; then
    CLAMD_SOCKET_FILE="${CLAMD_SOCKET_FILE}" \
      yq -i '
        .scanners.ScanClamav[0].options.clamd_socket = strenv(CLAMD_SOCKET_FILE)
      ' "${BACKEND_YAML_FILE}"
  fi
fi

if [[ -f /etc/clamav/clamd.conf ]]; then
  # see https://manpages.debian.org/stable/clamav-daemon/clamd.conf.5.en.html

  [[ -n "${CLAMD_SOCKET_FILE:-}" ]] && \
    set_config /etc/clamav/clamd.conf LocalSocket "${CLAMD_SOCKET_FILE}"

  [[ -n "${EXTRACTED_FILE_MAX_BYTES:-}" ]] && \
    set_config /etc/clamav/clamd.conf MaxFileSize "${EXTRACTED_FILE_MAX_BYTES}" && \
    set_config /etc/clamav/clamd.conf MaxScanSize "$(( EXTRACTED_FILE_MAX_BYTES * 4 ))" && \
    set_config /etc/clamav/clamd.conf StreamMaxLength "$(( EXTRACTED_FILE_MAX_BYTES + EXTRACTED_FILE_MAX_BYTES / 5 ))"

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

  if is_truthy "${CLAMD_SCAN_ARCHIVE:-false}"; then
    set_config /etc/clamav/clamd.conf ScanArchive true
  else
    set_config /etc/clamav/clamd.conf ScanArchive false
  fi
fi

[[ $# -gt 0 ]] && exec "$@"
