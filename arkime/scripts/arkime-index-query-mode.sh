#!/usr/bin/env bash
# Resolve Arkime's queryAllIndices setting for custom Malcolm index rotations.
# Source this helper from docker_entrypoint.sh or invoke it in isolation in tests.

arkime_index_query_mode() {
  local configured="${1:-auto}"
  local suffix="${2:-}"
  local network_index_pattern="${3:-}"
  local arkime_index_pattern="${4:-arkime_sessions3-*}"

  local mode
  mode="$(printf '%s' "$configured" | tr '[:upper:]' '[:lower:]')"
  case "$mode" in
    true|false)
      printf '%s\n' "$mode"
      ;;
    auto)
      # Arkime's date-range index selector does not consistently discover
      # Logstash's weekly, provider-prefixed non-Arkime indices. Bypass the
      # calculated indices only for those combinations; keep the efficient
      # date-range selection for daily indices and for Arkime's own indices.
      if [[ -n "$network_index_pattern" ]] &&
         [[ "$network_index_pattern" != "$arkime_index_pattern" ]] &&
         [[ "$suffix" =~ %[UVW] ]]; then
        printf '%s\n' true
      else
        printf '%s\n' false
      fi
      ;;
    *)
      printf 'Invalid ARKIME_QUERY_ALL_INDICES value: %s (expected auto, true or false)\n' "$configured" >&2
      return 1
      ;;
  esac
}
