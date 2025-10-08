#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2025 Battelle Energy Alliance, LLC.  All rights reserved.

"""
Validation helpers for Malcolm configuration.

This module provides minimal dependency-aware validation to ensure users
complete fields that were effectively required in the legacy installer.

Goals:
- Keep rules centralized (single source of truth)
- Be presentation-agnostic (usable by TUI/DUI/GUI/Silent)
- Respect dependency visibility (only enforce when inputs are relevant)
"""

from dataclasses import dataclass
from typing import List

from scripts.malcolm_constants import PROFILE_HEDGEHOG

from scripts.installer.configs.constants.configuration_item_keys import (
    KEY_CONFIG_ITEM_OPENSEARCH_PRIMARY_MODE,
    KEY_CONFIG_ITEM_OPENSEARCH_PRIMARY_URL,
    KEY_CONFIG_ITEM_DASHBOARDS_URL,
    KEY_CONFIG_ITEM_OPENSEARCH_SECONDARY_URL,
    KEY_CONFIG_ITEM_BEHIND_REVERSE_PROXY,
    KEY_CONFIG_ITEM_TRAEFIK_LABELS,
    KEY_CONFIG_ITEM_TRAEFIK_HOST,
    KEY_CONFIG_ITEM_TRAEFIK_ENTRYPOINT,
    KEY_CONFIG_ITEM_TRAEFIK_RESOLVER,
    KEY_CONFIG_ITEM_CAPTURE_LIVE_NETWORK_TRAFFIC,
    KEY_CONFIG_ITEM_PCAP_IFACE,
    KEY_CONFIG_ITEM_LIVE_ARKIME,
    KEY_CONFIG_ITEM_PCAP_NET_SNIFF,
    KEY_CONFIG_ITEM_PCAP_TCP_DUMP,
    KEY_CONFIG_ITEM_LIVE_ZEEK,
    KEY_CONFIG_ITEM_LIVE_SURICATA,
    KEY_CONFIG_ITEM_NETBOX_MODE,
    KEY_CONFIG_ITEM_NETBOX_URL,
    KEY_CONFIG_ITEM_USE_DEFAULT_STORAGE_LOCATIONS,
    KEY_CONFIG_ITEM_PCAP_DIR,
    KEY_CONFIG_ITEM_ZEEK_LOG_DIR,
    KEY_CONFIG_ITEM_SURICATA_LOG_DIR,
    KEY_CONFIG_ITEM_INDEX_DIR,
    KEY_CONFIG_ITEM_INDEX_SNAPSHOT_DIR,
    KEY_CONFIG_ITEM_TRAEFIK_OPENSEARCH_HOST,
    KEY_CONFIG_ITEM_LOGSTASH_HOST,
    KEY_CONFIG_ITEM_MALCOLM_PROFILE,
)
from scripts.installer.configs.constants.enums import (
    SearchEngineMode,
    NetboxMode,
)


@dataclass
class ValidationIssue:
    key: str
    label: str
    message: str


def _is_non_empty_str(value) -> bool:
    return isinstance(value, str) and len(value.strip()) > 0


def _validate_primary_remote(malcolm_config, add_issue) -> None:
    primary_mode = malcolm_config.get_value(KEY_CONFIG_ITEM_OPENSEARCH_PRIMARY_MODE)
    if isinstance(primary_mode, str) and primary_mode in {
        SearchEngineMode.OPENSEARCH_REMOTE.value,
        SearchEngineMode.ELASTICSEARCH_REMOTE.value,
    }:
        val = malcolm_config.get_value(KEY_CONFIG_ITEM_OPENSEARCH_PRIMARY_URL)
        if not _is_non_empty_str(val):
            add_issue(
                KEY_CONFIG_ITEM_OPENSEARCH_PRIMARY_URL,
                "Required when primary document store is remote",
            )
        if primary_mode == SearchEngineMode.ELASTICSEARCH_REMOTE.value:
            dval = malcolm_config.get_value(KEY_CONFIG_ITEM_DASHBOARDS_URL)
            if not _is_non_empty_str(dval):
                add_issue(
                    KEY_CONFIG_ITEM_DASHBOARDS_URL,
                    "Required when using remote Elasticsearch (Dashboards)",
                )


def _validate_secondary_remote(malcolm_config, add_issue) -> None:
    if malcolm_config.is_item_visible(KEY_CONFIG_ITEM_OPENSEARCH_SECONDARY_URL):
        sval = malcolm_config.get_value(KEY_CONFIG_ITEM_OPENSEARCH_SECONDARY_URL)
        if not _is_non_empty_str(sval):
            add_issue(
                KEY_CONFIG_ITEM_OPENSEARCH_SECONDARY_URL,
                "Required when forwarding logs to a remote secondary store",
            )


def _validate_traefik_labels(malcolm_config, add_issue) -> None:
    try:
        behind = bool(malcolm_config.get_value(KEY_CONFIG_ITEM_BEHIND_REVERSE_PROXY))
        tlabels = bool(malcolm_config.get_value(KEY_CONFIG_ITEM_TRAEFIK_LABELS))
    except Exception:
        behind = False
        tlabels = False

    if not (behind and tlabels):
        return

    for key, reason in (
        (KEY_CONFIG_ITEM_TRAEFIK_HOST, "Required when Traefik labels are enabled"),
        (
            KEY_CONFIG_ITEM_TRAEFIK_ENTRYPOINT,
            "Required when Traefik labels are enabled",
        ),
        (
            KEY_CONFIG_ITEM_TRAEFIK_RESOLVER,
            "Required when Traefik labels are enabled",
        ),
    ):
        try:
            if malcolm_config.is_item_visible(key):
                v = malcolm_config.get_value(key)
                if not _is_non_empty_str(v):
                    add_issue(key, reason)
        except Exception:
            pass

    try:
        primary_mode = malcolm_config.get_value(KEY_CONFIG_ITEM_OPENSEARCH_PRIMARY_MODE)
        if (
            isinstance(primary_mode, str)
            and primary_mode == SearchEngineMode.OPENSEARCH_LOCAL.value
        ):
            oshost = malcolm_config.get_value(KEY_CONFIG_ITEM_TRAEFIK_OPENSEARCH_HOST)
            host = malcolm_config.get_value(KEY_CONFIG_ITEM_TRAEFIK_HOST)
            if not _is_non_empty_str(oshost) or (host and oshost == host):
                add_issue(
                    KEY_CONFIG_ITEM_TRAEFIK_OPENSEARCH_HOST,
                    "Required (and must differ from Malcolm host) when Traefik labels are enabled with local OpenSearch",
                )
    except Exception:
        pass


def _validate_live_capture_iface(malcolm_config, add_issue) -> None:
    capture_enabled = bool(
        malcolm_config.get_value(KEY_CONFIG_ITEM_CAPTURE_LIVE_NETWORK_TRAFFIC)
    )
    if not capture_enabled:
        return
    any_method = any(
        bool(malcolm_config.get_value(k))
        for k in (
            KEY_CONFIG_ITEM_LIVE_ARKIME,
            KEY_CONFIG_ITEM_PCAP_NET_SNIFF,
            KEY_CONFIG_ITEM_PCAP_TCP_DUMP,
            KEY_CONFIG_ITEM_LIVE_ZEEK,
            KEY_CONFIG_ITEM_LIVE_SURICATA,
        )
    )
    if any_method:
        if malcolm_config.is_item_visible(KEY_CONFIG_ITEM_PCAP_IFACE):
            pcap_iface = malcolm_config.get_value(KEY_CONFIG_ITEM_PCAP_IFACE)
            if not _is_non_empty_str(pcap_iface):
                add_issue(
                    KEY_CONFIG_ITEM_PCAP_IFACE,
                    "Required when live capture is enabled",
                )


def _validate_netbox_remote(malcolm_config, add_issue) -> None:
    netbox_mode = malcolm_config.get_value(KEY_CONFIG_ITEM_NETBOX_MODE)
    if isinstance(netbox_mode, str) and netbox_mode == NetboxMode.REMOTE.value:
        if malcolm_config.is_item_visible(KEY_CONFIG_ITEM_NETBOX_URL):
            nval = malcolm_config.get_value(KEY_CONFIG_ITEM_NETBOX_URL)
            if not _is_non_empty_str(nval):
                add_issue(
                    KEY_CONFIG_ITEM_NETBOX_URL,
                    "Required when NetBox mode is remote",
                )


def _validate_non_default_storage(malcolm_config, add_issue) -> None:
    use_defaults_item = malcolm_config.get_item(
        KEY_CONFIG_ITEM_USE_DEFAULT_STORAGE_LOCATIONS
    )
    use_defaults = bool(use_defaults_item.get_value()) if use_defaults_item else True
    if use_defaults_item and use_defaults_item.is_modified and not use_defaults:
        for key, label_hint in (
            (KEY_CONFIG_ITEM_PCAP_DIR, "PCAP storage directory"),
            (KEY_CONFIG_ITEM_ZEEK_LOG_DIR, "Zeek log directory"),
            (KEY_CONFIG_ITEM_SURICATA_LOG_DIR, "Suricata log directory"),
        ):
            item = malcolm_config.get_item(key)
            if not item or not item.is_modified:
                add_issue(
                    key,
                    f"Required when not using default storage locations ({label_hint})",
                )
        profile = malcolm_config.get_value(KEY_CONFIG_ITEM_MALCOLM_PROFILE)
        primary_mode = malcolm_config.get_value(KEY_CONFIG_ITEM_OPENSEARCH_PRIMARY_MODE)
        if (
            isinstance(profile, str)
            and profile == "malcolm"
            and isinstance(primary_mode, str)
            and primary_mode == SearchEngineMode.OPENSEARCH_LOCAL.value
        ):
            for key, label_hint in (
                (KEY_CONFIG_ITEM_INDEX_DIR, "OpenSearch index directory"),
                (
                    KEY_CONFIG_ITEM_INDEX_SNAPSHOT_DIR,
                    "OpenSearch snapshot directory",
                ),
            ):
                item = malcolm_config.get_item(key)
                if not item or not item.is_modified:
                    add_issue(
                        key,
                        f"Required when not using default storage locations ({label_hint})",
                    )


def _validate_hedgehog_profile(malcolm_config, add_issue) -> None:
    profile = malcolm_config.get_value(KEY_CONFIG_ITEM_MALCOLM_PROFILE)
    if isinstance(profile, str) and profile == PROFILE_HEDGEHOG:
        lshost = malcolm_config.get_value(KEY_CONFIG_ITEM_LOGSTASH_HOST)
        if not _is_non_empty_str(lshost):
            add_issue(
                KEY_CONFIG_ITEM_LOGSTASH_HOST,
                "Required when running with the Hedgehog profile (host:port)",
            )


def validate_required(malcolm_config) -> List[ValidationIssue]:
    """Validate dependency-driven required fields.

    Only enforces when fields are relevant/visible according to the current
    dependency state, mirroring legacy prompts that would not proceed without
    these values.

    Returns:
        A list of ValidationIssue objects. Empty if all checks pass.
    """
    issues: List[ValidationIssue] = []

    def add_issue(key: str, reason: str):
        item = malcolm_config.get_item(key)
        label = item.label if item else key
        issues.append(ValidationIssue(key=key, label=label, message=reason))

    # 1) OpenSearch primary remote -> require URL
    try:
        _validate_primary_remote(malcolm_config, add_issue)
    except Exception:
        pass

    # 2) Secondary remote -> require URL (enforced by visibility)
    try:
        _validate_secondary_remote(malcolm_config, add_issue)
    except Exception:
        pass

    # 3) Traefik labels enabled -> require host/entrypoint/resolver
    try:
        _validate_traefik_labels(malcolm_config, add_issue)
    except Exception:
        pass

    # 4) Live capture with any capture method -> require interface
    try:
        _validate_live_capture_iface(malcolm_config, add_issue)
    except Exception:
        pass

    # 5) NetBox remote -> require URL
    try:
        _validate_netbox_remote(malcolm_config, add_issue)
    except Exception:
        pass

    # container external network name is explicitly optional (blank => default networking)

    # 6) Non-default storage locations -> require the user to supply directories (must be user-modified)
    try:
        _validate_non_default_storage(malcolm_config, add_issue)
    except Exception:
        pass

    # 7) Hedgehog profile -> require Logstash host:port
    try:
        _validate_hedgehog_profile(malcolm_config, add_issue)
    except Exception:
        pass

    return issues


def format_validation_summary(issues: List[ValidationIssue]) -> str:
    """Create a human-readable summary of validation issues."""
    if not issues:
        return ""
    lines = [
        "Some required settings are missing:",
    ]
    for issue in issues:
        lines.append(f"- {issue.label}: {issue.message} ({issue.key})")
    return "\n".join(lines)
