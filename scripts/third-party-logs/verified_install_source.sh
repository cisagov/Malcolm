#!/usr/bin/env bash
# Download and verify an installer before sourcing it into the current shell.
# The expected checksum must be stored in this repository.

verified_source_installer() {
  if [[ $# -ne 2 || ! "$2" =~ ^[[:xdigit:]]{64}$ ]]; then
    echo 'Expected a URL and a pinned SHA-256 checksum' >&2
    return 1
  fi

  local url="$1"
  local expected_sha256="$2"
  local tmp_file
  tmp_file="$(mktemp /tmp/malcolm-install-XXXXXXXX)" || return 1

  if ! curl -fsSL --connect-timeout 15 --max-time 120 -o "$tmp_file" "$url"; then
    rm -f "$tmp_file"
    echo "Could not fetch installer from $url" >&2
    return 1
  fi

  local verified=false
  # macOS ships a BSD sha256sum whose -c does not read GNU checksum files.
  if [[ "$(uname -s)" == Darwin ]] && command -v shasum >/dev/null 2>&1; then
    printf '%s  %s\n' "$expected_sha256" "$tmp_file" | shasum -a 256 -c >/dev/null && verified=true
  elif command -v sha256sum >/dev/null 2>&1; then
    printf '%s  %s\n' "$expected_sha256" "$tmp_file" | sha256sum -c >/dev/null && verified=true
  elif command -v shasum >/dev/null 2>&1; then
    printf '%s  %s\n' "$expected_sha256" "$tmp_file" | shasum -a 256 -c >/dev/null && verified=true
  fi

  if [[ "$verified" != true ]]; then
    rm -f "$tmp_file"
    echo "Installer failed SHA-256 verification: $url" >&2
    return 1
  fi

  # Source rather than execute to preserve existing installation behavior.
  local status=0
  source "$tmp_file" || status=$?
  rm -f "$tmp_file"
  return "$status"
}
