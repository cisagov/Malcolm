#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2025 Battelle Energy Alliance, LLC.  All rights reserved.

import re
from typing import Any, Optional

from scripts.malcolm_constants import (
    LOGSTASH_JAVA_OPTS_DEFAULT,
    OPENSEARCH_JAVA_OPTS_DEFAULT,
)
from scripts.malcolm_utils import (
    true_or_false_no_quotes,
    DATABASE_MODE_LABELS,
    DATABASE_MODE_ENUMS,
)


def _env_str_to_bool(value: Optional[str]) -> bool:
    """Return True iff value is the string 'true' (case-insensitive).

    Treat None and empty values as False for robustness.
    """
    if value is None:
        return False
    return str(value).strip().lower() == "true"


def _orch_is_k8s(orch_mode: Any) -> bool:
    """Return True for Kubernetes orchestration from enum or string input."""
    from scripts.malcolm_constants import OrchestrationFramework

    if isinstance(orch_mode, OrchestrationFramework):
        return orch_mode == OrchestrationFramework.KUBERNETES
    return str(orch_mode).strip().upper() == "KUBERNETES"


def _orch_from_bool_str(value: str):
    """Map 'true' to KUBERNETES, everything else to DOCKER_COMPOSE."""
    from scripts.malcolm_constants import OrchestrationFramework

    return OrchestrationFramework.KUBERNETES if _env_str_to_bool(value) else OrchestrationFramework.DOCKER_COMPOSE


def _db_mode_to_label(mode: Any) -> str:
    """Normalize database mode to its textual label for env values."""
    if isinstance(mode, int):
        return DATABASE_MODE_LABELS.get(mode, "")
    if mode in DATABASE_MODE_ENUMS:
        return mode
    return str(mode)


def _db_label_from_env(value: str) -> str:
    """Normalize env value for DB mode to the expected textual label."""
    if value in DATABASE_MODE_ENUMS:
        return value
    v = str(value).strip()
    if v.isdigit():
        return DATABASE_MODE_LABELS.get(int(v), value)
    return value


def custom_transform_arkime_rotated_pcap(autoArkime: bool, liveArkime: bool) -> str:
    return true_or_false_no_quotes(autoArkime and (not liveArkime))


def custom_reverse_transform_arkime_rotated_pcap(value: str):
    """Return tuple (autoArkime, liveArkime) with only live derived.

    Align Arkime behavior with Zeek/Suricata rotated-PCAP reverse transforms:
    do not clobber the user's autoArkime setting. Only derive liveArkime
    as the inverse of the rotated flag.
    """
    rotated = _env_str_to_bool(value)
    live_arkime = not rotated
    return ("", live_arkime)


def custom_transform_suricata_disable_ics_all(malcolmIcs: bool) -> str:
    return true_or_false_no_quotes(not malcolmIcs)


def custom_reverse_transform_suricata_disable_ics_all(value: str) -> bool:
    return _env_str_to_bool(value)


def custom_transform_suricata_rotated_pcap(autoSuricata: bool, liveSuricata: bool) -> str:
    return true_or_false_no_quotes(autoSuricata and (not liveSuricata))


def custom_reverse_transform_suricata_rotated_pcap(value: str):
    rotated = _env_str_to_bool(value)
    live_suricata = not rotated
    return ("", live_suricata)


def custom_transform_zeek_file_enable_vtot(vtotApiKey: str) -> str:
    return true_or_false_no_quotes(len(vtotApiKey) > 1)


def custom_reverse_transform_zeek_file_enable_vtot(value: str):
    """When importing EXTRACTED_FILE_ENABLE_VTOT we cannot reconstruct the actual API key.

    To avoid failing validation on the `vtotApiKey` (expects string), return an
    empty string regardless of the boolean flag. The flag merely indicates
    whether a non-empty key exists.
    """
    return ""  # leave the API key unset; user can supply later


def custom_reverse_transform_zeek_vtot_api2_key(value: str) -> str:
    """Reverse transform for VTOT_API2_KEY (VirusTotal API key).

    The .env files use '0' as a sentinel default. Treat '0' or empty as unset,
    otherwise return the raw string. Do not coerce numeric-looking strings to int.
    """
    if value is None:
        return ""
    v = str(value).strip()
    return "" if v in ("", "0") else v


def custom_transform_zeek_vtot_api2_key(value: str) -> str:
    """Forward transform for VTOT_API2_KEY.

    Write '0' when unset/empty to match image defaults and examples. Otherwise
    pass through the provided string.
    """
    if value is None or str(value).strip() == "":
        return "0"
    return str(value)


def custom_transform_filebeat_syslog_tcp_listen(tcp_port: int) -> str:
    return true_or_false_no_quotes(tcp_port is not None and tcp_port > 0)


def custom_reverse_transform_filebeat_syslog_tcp_listen(value: str) -> None:
    # This is a derived env var that should not set config values during loading
    # to avoid conflicts with the port env var. Return None to skip setting.
    return None


def custom_transform_zeek_disable_stats(captureStats: bool) -> str:
    return true_or_false_no_quotes(not captureStats)


def custom_reverse_transform_zeek_disable_stats(value: str) -> bool:
    # The env var represents *disabling* stats. CaptureStats should be the inverse.
    return not _env_str_to_bool(value)


def custom_transform_zeek_rotated_pcap(autoZeek: bool, liveZeek: bool) -> str:
    return true_or_false_no_quotes(autoZeek and (not liveZeek))


def custom_reverse_transform_zeek_rotated_pcap(value: str):
    """Return tuple (autoZeek, liveZeek).

    We do **not** attempt to infer autoZeek from this flag to avoid clobbering
    the user's configured value.  Instead we return an empty string for the
    first position so that the loader skips setting it.  The second tuple
    element sets liveZeek based on the negation of the rotated-pcap flag.
    """
    rotated = _env_str_to_bool(value)
    live_zeek = not rotated
    return ("", live_zeek)


def custom_transform_zeek_file_watcher_polling(orchMode) -> str:
    """Return 'true' when running under Kubernetes orchestration."""
    return true_or_false_no_quotes(_orch_is_k8s(orchMode))


def custom_reverse_transform_zeek_file_watcher_polling(value: str):
    """Return the appropriate OrchestrationFramework value based on the polling flag."""
    return _orch_from_bool_str(value)


def custom_transform_pcap_pipeline_polling(orchMode) -> str:
    return true_or_false_no_quotes(_orch_is_k8s(orchMode))


def custom_reverse_transform_pcap_pipeline_polling(value: str):
    return _orch_from_bool_str(value)


def custom_transform_filebeat_watcher_polling(orchMode) -> str:
    return true_or_false_no_quotes(_orch_is_k8s(orchMode))


def custom_reverse_transform_filebeat_watcher_polling(value: str):
    return _orch_from_bool_str(value)


def custom_transform_filebeat_syslog_udp_listen(udp_port: int) -> str:
    return true_or_false_no_quotes(udp_port is not None and udp_port > 0)


def custom_reverse_transform_filebeat_syslog_udp_listen(value: str) -> None:
    # This is a derived env var that should not set config values during loading
    # to avoid conflicts with the port env var. Return None to skip setting.
    return None


def custom_transform_filebeat_syslog_tcp_port(tcp_port: int, accept_syslog: bool) -> str:
    """Forward transform for FILEBEAT_SYSLOG_TCP_PORT.

    Takes both the port and accept_syslog flag, but only the port is written.
    The accept_syslog flag determines whether the port should be written (it's
    derived from whether the port is non-zero).
    """
    return str(tcp_port) if tcp_port is not None else "0"


def custom_reverse_transform_filebeat_syslog_tcp_port(value: str):
    """Return tuple (port, accept_syslog_enabled).

    If a non-zero port is configured, we infer that syslog should be accepted.
    """
    try:
        port = int(str(value).strip())
    except Exception:
        return (None, False)

    port_value = None if port == 0 else port
    accept_syslog = port is not None and port > 0
    return (port_value, accept_syslog)


def custom_transform_filebeat_syslog_udp_port(udp_port: int, accept_syslog: bool) -> str:
    """Forward transform for FILEBEAT_SYSLOG_UDP_PORT.

    Takes both the port and accept_syslog flag, but only the port is written.
    The accept_syslog flag determines whether the port should be written (it's
    derived from whether the port is non-zero).
    """
    return str(udp_port) if udp_port is not None else "0"


def custom_reverse_transform_filebeat_syslog_udp_port(value: str):
    """Return tuple (port, accept_syslog_enabled).

    If a non-zero port is configured, we infer that syslog should be accepted.
    """
    try:
        port = int(str(value).strip())
    except Exception:
        return (None, False)

    port_value = None if port == 0 else port
    accept_syslog = port is not None and port > 0
    return (port_value, accept_syslog)


def custom_reverse_transform_opensearch_index_size_prune_limit(value: str) -> str:
    """Reverse transform for OPENSEARCH_INDEX_SIZE_PRUNE_LIMIT.

    Accept the raw string (e.g., '250G', '60%'). Treat '0' or empty as unset
    so the config item (expects string) validates and can remain at default.
    """
    if value is None:
        return ""
    v = str(value).strip()
    return "" if v in ("", "0") else v


def custom_transform_opensearch_index_size_prune_limit(limit_str: str) -> str:
    """Forward transform for OPENSEARCH_INDEX_SIZE_PRUNE_LIMIT.

    Consumers expect '0' to disable pruning. When the config item is empty,
    write '0' instead of an empty string. Otherwise, pass through verbatim.
    """
    if limit_str is None or str(limit_str).strip() == "":
        return "0"
    return str(limit_str)


def custom_transform_logstash_java_opts(lsMemory: str) -> str:
    return re.sub(r"(-Xm[sx])(\w+)", rf"\g<1>{lsMemory}", LOGSTASH_JAVA_OPTS_DEFAULT)


def custom_reverse_transform_logstash_java_opts(value: str) -> str:
    match = re.search(r"-Xm[sx](\d+)([gGmMkK]?)", value)
    if match:
        size, unit = match.groups()
        # Default to 'g' if no unit captured (older patterns)
        return f"{size}{unit or 'g'}"
    return "2500"


def custom_transform_opensearch_primary(opensearchPrimaryMode) -> str:
    return _db_mode_to_label(opensearchPrimaryMode)


def custom_reverse_transform_opensearch_primary(value: str):
    """Return the string label expected by the config item given an index."""
    return _db_label_from_env(value)


def custom_transform_opensearch_secondary(opensearchSecondaryMode) -> str:
    return _db_mode_to_label(opensearchSecondaryMode)


def custom_reverse_transform_opensearch_secondary(value: str):
    # Same logic as primary
    return _db_label_from_env(value)


def custom_transform_opensearch_java_opts(osMemory: str) -> str:
    return re.sub(r"(-Xm[sx])(\w+)", rf"\g<1>{osMemory}", OPENSEARCH_JAVA_OPTS_DEFAULT)


def custom_reverse_transform_opensearch_java_opts(value: str) -> str:
    match = re.search(r"-Xm[sx](\d+)([gGmMkK]?)", value)
    if not match:
        return ""
    size, unit = match.groups()
    mem = f"{size}{unit or 'g'}"
    # Skip returning the default value (10g) to avoid unnecessary overrides
    if mem.lower() == "10g":
        return ""
    return mem


def custom_transform_pcap_enable_tcpdump(pcapTcpDump: bool, pcapNetSniff: bool, captureLive: bool) -> str:
    """Forward transform for PCAP_ENABLE_TCPDUMP.

    Maps 3 config items but only uses the first two for the transform logic.
    """
    return true_or_false_no_quotes(pcapTcpDump and (not pcapNetSniff))


def custom_reverse_transform_pcap_enable_tcpdump(value: str):
    """Reverse transform for PCAP_ENABLE_TCPDUMP.

    Returns tuple (tcpdump, netsniff, captureLive).
    Only tcpdump is authoritative; netsniff and captureLive are derived/ignored.
    """
    tcpdump_enabled = _env_str_to_bool(value)
    return (tcpdump_enabled, "", "")


def custom_transform_container_runtime_key(orchMode, runtimeBin: str) -> str:
    """Derive CONTAINER_RUNTIME_KEY from orchestration + runtime.

    - For Kubernetes orchestration, emit 'kubernetes'
    - Otherwise, emit the runtime binary (e.g., 'docker', 'podman')
    Accepts either OrchestrationFramework enum or string for orchMode.
    """
    try:
        from scripts.malcolm_constants import OrchestrationFramework

        if isinstance(orchMode, OrchestrationFramework):
            is_k8s = orchMode == OrchestrationFramework.KUBERNETES
        else:
            is_k8s = str(orchMode).upper() == "KUBERNETES"
        return "kubernetes" if is_k8s else runtimeBin
    except Exception:
        # fail-safe: prefer runtimeBin unless explicit 'KUBERNETES' string
        return "kubernetes" if str(orchMode).upper() == "KUBERNETES" else runtimeBin


def custom_reverse_transform_container_runtime_key(value: str):
    """Return a tuple (orch_mode, runtime_bin).

    orch_mode is returned as an OrchestrationFramework enum instance so that the
    target config item validator passes.
    """
    from scripts.malcolm_constants import OrchestrationFramework

    if value == "kubernetes":
        return (OrchestrationFramework.KUBERNETES, "")

    # For docker runtimes, preserve the runtime binary string as-is
    return (OrchestrationFramework.DOCKER_COMPOSE, value)


def custom_transform_zeek_disable_ics_all(malcolmIcs: bool) -> str:
    return "" if malcolmIcs else true_or_false_no_quotes(not malcolmIcs)


def custom_reverse_transform_zeek_disable_ics_all(value: str) -> bool:
    # Empty string means the disable flag is not set, so ICS analysis remains enabled (True)
    return True if value == "" else not (value.lower() == "true")


def custom_transform_zeek_disable_best_guess_ics(zeekICSBestGuess: bool) -> str:
    return "" if zeekICSBestGuess else true_or_false_no_quotes(not zeekICSBestGuess)


def custom_reverse_transform_zeek_disable_best_guess_ics(value: str) -> bool:
    # Empty string means the disable flag is not set, so best-guess ICS analysis remains enabled (True)
    return True if value == "" else not (value.lower() == "true")


def custom_transform_netbox_url(netboxMode: str, netboxUrl: str) -> str:
    return netboxUrl if (netboxMode == "remote") else ""


def custom_reverse_transform_netbox_url(value: str):
    if value:
        return ("remote", value)
    # Empty URL ⇒ keep existing mode (skip) and do not set netboxUrl
    return ("", "")


def custom_transform_opensearch_url(opensearchPrimaryMode: str, opensearchPrimaryUrl: str) -> str:
    """Forward transform for OPENSEARCH_URL.

    When using local OpenSearch (opensearch-local), return the default internal URL
    even if the user didn't provide one (since the field is hidden for local mode).
    For remote modes, return the user-provided URL or empty if None.
    """
    from scripts.installer.configs.constants.enums import SearchEngineMode

    if opensearchPrimaryMode == SearchEngineMode.OPENSEARCH_LOCAL.value:
        # For local mode, use default if URL is None/empty
        if not opensearchPrimaryUrl or str(opensearchPrimaryUrl).strip() == "":
            return "https://opensearch:9200"
        return opensearchPrimaryUrl
    # For remote modes, return the URL or empty string
    return opensearchPrimaryUrl if opensearchPrimaryUrl else ""


def custom_reverse_transform_opensearch_url(value: str):
    """Reverse transform for OPENSEARCH_URL.

    Return tuple (mode, url). If the URL is the default local URL, don't set mode.
    Otherwise preserve the URL value.
    """
    if value == "https://opensearch:9200":
        # Default local URL - don't override mode, don't set URL (it will use default)
        return ("", "")
    # Non-default URL - preserve it but don't infer mode
    return ("", value if value else "")


# Live capture transforms
def custom_transform_arkime_live_capture(liveArkime: bool, captureLive: bool) -> str:
    """Forward transform for ARKIME_LIVE_CAPTURE.
    
    Write true only if live Arkime is enabled.
    captureLive is a derived/shared flag.
    """
    return true_or_false_no_quotes(liveArkime)


def custom_reverse_transform_arkime_live_capture(value: str):
    """Reverse transform for ARKIME_LIVE_CAPTURE.
    
    Returns tuple (liveArkime, captureLive).
    """
    live_arkime = _env_str_to_bool(value)
    # Don't set captureLive from this env var (it's set by dependency system)
    return (live_arkime, "")


def custom_transform_zeek_live_capture(liveZeek: bool, captureLive: bool) -> str:
    """Forward transform for ZEEK_LIVE_CAPTURE.
    
    Write true only if live Zeek is enabled.
    captureLive is a derived/shared flag.
    """
    return true_or_false_no_quotes(liveZeek)


def custom_reverse_transform_zeek_live_capture(value: str):
    """Reverse transform for ZEEK_LIVE_CAPTURE.
    
    Returns tuple (liveZeek, captureLive).
    """
    live_zeek = _env_str_to_bool(value)
    # Don't set captureLive from this env var (it's set by dependency system)
    return (live_zeek, "")


def custom_transform_suricata_live_capture(liveSuricata: bool, captureLive: bool) -> str:
    """Forward transform for SURICATA_LIVE_CAPTURE.
    
    Write true only if live Suricata is enabled.
    captureLive is a derived/shared flag.
    """
    return true_or_false_no_quotes(liveSuricata)


def custom_reverse_transform_suricata_live_capture(value: str):
    """Reverse transform for SURICATA_LIVE_CAPTURE.
    
    Returns tuple (liveSuricata, captureLive).
    """
    live_suricata = _env_str_to_bool(value)
    # Don't set captureLive from this env var (it's set by dependency system)
    return (live_suricata, "")


def custom_transform_pcap_enable_netsniff(pcapNetSniff: bool, captureLive: bool) -> str:
    """Forward transform for PCAP_ENABLE_NETSNIFF.
    
    Write true only if netsniff is enabled.
    captureLive is a derived/shared flag.
    """
    return true_or_false_no_quotes(pcapNetSniff)


def custom_reverse_transform_pcap_enable_netsniff(value: str):
    """Reverse transform for PCAP_ENABLE_NETSNIFF.
    
    Returns tuple (pcapNetSniff, captureLive).
    """
    netsniff = _env_str_to_bool(value)
    # Don't set captureLive from this env var (it's set by dependency system)
    return (netsniff, "")
