#!/bin/bash

# Copyright (c) 2026 Battelle Energy Alliance, LLC. All rights reserved.

# Sourced by live_capture.sh. Keep capture children under the launcher's ownership
# so stopping the service cannot start a fallback or leave another interface running.
function stop_capture_children() {
    if (( ${#CAPTURE_PIDS[@]} )); then
        kill -TERM "${CAPTURE_PIDS[@]}" 2>/dev/null || true
        wait "${CAPTURE_PIDS[@]}" 2>/dev/null || true
        CAPTURE_PIDS=()
    fi
}

function capture_fallback_init() {
    CAPTURE_PIDS=()
    ARKIME_LIVE_CAPTURE_FALLBACK_SECONDS=${ARKIME_LIVE_CAPTURE_FALLBACK_SECONDS:-300}
    if [[ ! "${ARKIME_LIVE_CAPTURE_FALLBACK_SECONDS}" =~ ^[0-9]{1,9}$ ]]; then
        echo "Invalid ARKIME_LIVE_CAPTURE_FALLBACK_SECONDS; using 300 seconds" >&2
        ARKIME_LIVE_CAPTURE_FALLBACK_SECONDS=300
    fi
    ARKIME_LIVE_CAPTURE_FALLBACK_SECONDS=$((10#${ARKIME_LIVE_CAPTURE_FALLBACK_SECONDS}))
    trap stop_capture_children EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
}

# Bound each request by both a short request timeout and the overall startup deadline.
function arkime_backend_get() {
    local request_seconds=5 remaining
    if (( ARKIME_LIVE_CAPTURE_FALLBACK_SECONDS > 0 )); then
        remaining=$((ARKIME_BACKEND_DEADLINE - SECONDS))
        (( remaining > 0 )) || return 1
        (( remaining < request_seconds )) && request_seconds=${remaining}
    fi
    curl "${CURL_CONFIG_PARAMS[@]}" --connect-timeout 2 --max-time "${request_seconds}" \
        --fail --silent "${OPENSEARCH_URL%/}/$1"
}

function arkime_backend_ready() {
    local health template users
    health=$(arkime_backend_get '_cat/health?h=status') || return 1
    [[ "${health//[[:space:]]/}" =~ ^(yellow|green)$ ]] || return 1
    template=$(arkime_backend_get '_index_template/malcolm_template') || return 1
    jq -e 'any(.index_templates[]?; .name == "malcolm_template")' <<< "${template}" >/dev/null 2>&1 || return 1
    users=$(arkime_backend_get '_cat/indices/arkime_users_v*?format=json&h=index') || return 1
    jq -e 'type == "array" and any(.[]; .index | startswith("arkime_users_v"))' <<< "${users}" >/dev/null 2>&1
}

function wait_for_arkime_backend() {
    ARKIME_BACKEND_DEADLINE=$((SECONDS + ARKIME_LIVE_CAPTURE_FALLBACK_SECONDS))
    until arkime_backend_ready; do
        if (( ARKIME_LIVE_CAPTURE_FALLBACK_SECONDS > 0 && SECONDS >= ARKIME_BACKEND_DEADLINE )); then
            return 1
        fi
        sleep 1
    done
}

function tcpdump_fallback() {
    local output_dir=$1 iface value status run_id
    local pcap_iface=${PCAP_IFACE:-}
    local rotate_minutes=${PCAP_ROTATE_MINUTES:-10}
    local rotate_megabytes=${PCAP_ROTATE_MEGABYTES:-4096}
    local snaplen=${PCAP_SNAPLEN:-0}
    local pattern=${PCAP_TCPDUMP_FILENAME_PATTERN:-%Y%m%d%H%M%S.pcap}
    local -a interfaces=() filter_args=()
    local -A seen=()

    command -v tcpdump >/dev/null 2>&1 || { echo "tcpdump fallback is unavailable" >&2; return 1; }
    read -r -a interfaces <<< "${pcap_iface//,/ }"
    if (( ${#interfaces[@]} == 0 )); then
        echo "Cannot start tcpdump fallback: PCAP_IFACE is empty" >&2
        return 1
    fi
    for iface in "${interfaces[@]}"; do
        [[ "${iface}" =~ ^[a-zA-Z0-9_.:-]+$ ]] || { echo "Invalid fallback capture interface: ${iface}" >&2; return 1; }
    done
    for value in "${rotate_minutes}" "${rotate_megabytes}" "${snaplen}"; do
        [[ "${value}" =~ ^[0-9]{1,9}$ ]] || { echo "Invalid fallback PCAP rotation or snap length" >&2; return 1; }
    done
    # Slashes, including strftime's %D expansion, would put files outside upload.
    if [[ "${pattern}" == */* || "${pattern}" == *%D* ]]; then
        echo "Fallback PCAP filename pattern must not contain directory separators" >&2
        return 1
    fi
    [[ -d "${output_dir}" ]] || { echo "Fallback PCAP directory does not exist: ${output_dir}" >&2; return 1; }
    [[ -n "${PCAP_FILTER:-}" ]] && filter_args=("${PCAP_FILTER}")
    run_id="$(date -u +%Y%m%dT%H%M%S)-$$"
    echo "Falling back to local tcpdump capture on ${pcap_iface}; restart arkime-live to retry Arkime" >&2

    for iface in "${interfaces[@]}"; do
        [[ -z "${seen[${iface}]:-}" ]] || continue
        seen[${iface}]=1
        tcpdump -i "${iface}" -j host -s "$((10#${snaplen}))" \
            -w "${output_dir}/mtcpdump-${iface}-fallback-${run_id}_${pattern}" \
            -G "$((10#${rotate_minutes} * 60))" -C "$((10#${rotate_megabytes}))" \
            -K -n -Z "${PUSER:-arkime}" "${filter_args[@]}" &
        CAPTURE_PIDS+=("$!")
    done
    # A failed interface must stop its siblings, allowing supervisor to retry the service.
    if wait -n "${CAPTURE_PIDS[@]}"; then status=1; else status=$?; fi
    stop_capture_children
    return "${status}"
}

function run_arkime_capture() {
    local output_dir=$1 status
    shift
    "$@" &
    CAPTURE_PIDS=("$!")
    if wait "${CAPTURE_PIDS[0]}"; then status=0; else status=$?; fi
    CAPTURE_PIDS=()
    # Normal exits and deliberate interrupts are not capture failures.
    if (( ARKIME_LIVE_CAPTURE_FALLBACK_SECONDS > 0 && status != 0 && status != 130 && status != 143 )); then
        echo "Arkime live capture failed with status ${status}" >&2
        tcpdump_fallback "${output_dir}"
    else
        return "${status}"
    fi
}
