#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2025 Battelle Energy Alliance, LLC.  All rights reserved.

"""Declarative dependency configuration for Malcolm installer.

This module defines all configuration item dependencies in a declarative format
that is easy to read, maintain, and understand. Dependencies are organized by
functional area and specify both visibility and value relationships.
"""

from typing import Dict, Any, Callable, List, Union
from dataclasses import dataclass
from scripts.malcolm_constants import PROFILE_HEDGEHOG, PROFILE_MALCOLM, OrchestrationFramework
from scripts.malcolm_common import SYSTEM_INFO
from scripts.malcolm_utils import isipaddress
from scripts.installer.configs.constants.constants import (
    LOGSTASH_WORKERS_KUBERNETES,
    OPENSEARCH_MEMORY_KUBERNETES,
    LOGSTASH_MEMORY_KUBERNETES,
    SERVICE_PORT_LOGSTASH,
    SERVICE_PORT_OSMALCOLM,
    SYSLOG_DEFAULT_PORT,
    LOCAL_LOGSTASH_HOST,
    LOCAL_DASHBOARDS_URL,
    LOCAL_OPENSEARCH_URL,
    LOCAL_ARKIME_WISE_URL,
)

from scripts.installer.configs.constants.enums import (
    ArkimePCAPCompression,
    FilebeatLogFormat,
    FilebeatFieldNames,
    FileExtractionMode,
    SearchEngineMode,
    NetboxMode,
    OpenPortsChoices,
)

from scripts.installer.configs.constants.configuration_item_keys import *


@dataclass
class VisibilityRule:
    """Defines when a configuration item should be visible in the UI."""

    depends_on: Union[str, List[str]]  # Key(s) this item depends on
    condition: Union[bool, Callable[..., bool]]  # Function that determines visibility
    ui_parent: str = None  # Optional explicit UI parent override
    is_top_level: bool = False  # True if this is a top-level menu item


@dataclass
class ValueRule:
    """Defines automatic value setting based on other configuration items."""

    depends_on: Union[str, List[str]]  # Key(s) this value depends on
    condition: Union[bool, Callable[..., bool]]  # When to apply the default value
    default_value: Any  # Value to set when condition is met
    only_if_unmodified: bool = True  # Only set if user hasn't manually changed it


@dataclass
class DependencySpec:
    """Complete dependency specification for a configuration item."""

    visibility: VisibilityRule = None
    value: ValueRule = None


class _UnchangedType:
    """Sentinel object for default_value indicating that it should remain unchanged."""

    def __repr__(self) -> str:
        return "<UNCHANGED>"


# Use DEFAULT_VALUE_UNCHANGED for ValueRule.default_value if you want
# DependencyManager.value_observer to *not* update the value
# but still want the condition to trigger. Normally you'd just
# set the condition to not trigger if you want to preserve the existing
# value, but for some more complicated situations it can be useful (e.g., mapping
# a value to a list of values but then using DEFAULT_VALUE_UNCHANGED as
# the fallback if it's not handled in that list).
DEFAULT_VALUE_UNCHANGED = _UnchangedType()

# =============================================================================
# DECLARATIVE DEPENDENCY CONFIGURATION
# =============================================================================

DEPENDENCY_CONFIG: Dict[str, DependencySpec] = {
    # -------------------------------------------------------------------------
    # PROFILE AND RUNTIME DEPENDENCIES
    # -------------------------------------------------------------------------
    KEY_CONFIG_ITEM_PROCESS_USER_ID: DependencySpec(
        visibility=VisibilityRule(
            depends_on=KEY_CONFIG_ITEM_RUNTIME_BIN,
            condition=lambda runtime: bool(runtime),
            ui_parent=KEY_CONFIG_ITEM_RUNTIME_BIN,
        )
    ),
    KEY_CONFIG_ITEM_PROCESS_GROUP_ID: DependencySpec(
        visibility=VisibilityRule(
            depends_on=KEY_CONFIG_ITEM_RUNTIME_BIN,
            condition=lambda runtime: bool(runtime),
            ui_parent=KEY_CONFIG_ITEM_RUNTIME_BIN,
        )
    ),
    KEY_CONFIG_ITEM_CONTAINER_NETWORK_NAME: DependencySpec(
        visibility=VisibilityRule(
            depends_on=KEY_CONFIG_ITEM_DOCKER_ORCHESTRATION_MODE,
            condition=lambda orch: orch != OrchestrationFramework.KUBERNETES,
            ui_parent=KEY_CONFIG_ITEM_RUNTIME_BIN,
        )
    ),
    KEY_CONFIG_ITEM_MALCOLM_RESTART_POLICY: DependencySpec(
        visibility=VisibilityRule(
            depends_on=KEY_CONFIG_ITEM_DOCKER_ORCHESTRATION_MODE,
            condition=lambda orch: orch == OrchestrationFramework.DOCKER_COMPOSE,
            ui_parent=KEY_CONFIG_ITEM_RUNTIME_BIN,
        )
    ),
    # Malcolm profile top-level items
    KEY_CONFIG_ITEM_NGINX_SSL: DependencySpec(
        visibility=VisibilityRule(
            depends_on=KEY_CONFIG_ITEM_MALCOLM_PROFILE,
            condition=lambda profile: profile == PROFILE_MALCOLM,
            is_top_level=True,
        )
    ),
    KEY_CONFIG_ITEM_NGINX_RESOLVER_IPV4: DependencySpec(
        visibility=VisibilityRule(
            depends_on=KEY_CONFIG_ITEM_MALCOLM_PROFILE,
            condition=lambda profile: profile == PROFILE_MALCOLM,
            is_top_level=True,
        )
    ),
    KEY_CONFIG_ITEM_NGINX_RESOLVER_IPV6: DependencySpec(
        visibility=VisibilityRule(
            depends_on=KEY_CONFIG_ITEM_MALCOLM_PROFILE,
            condition=lambda profile: profile == PROFILE_MALCOLM,
            is_top_level=True,
        )
    ),
    KEY_CONFIG_ITEM_USE_DEFAULT_STORAGE_LOCATIONS: DependencySpec(
        visibility=VisibilityRule(
            depends_on=KEY_CONFIG_ITEM_DOCKER_ORCHESTRATION_MODE,
            condition=lambda orch: orch != OrchestrationFramework.KUBERNETES,
            is_top_level=True,
        )
    ),
    KEY_CONFIG_ITEM_TRAEFIK_LABELS: DependencySpec(
        visibility=VisibilityRule(
            depends_on=[
                KEY_CONFIG_ITEM_MALCOLM_PROFILE,
                KEY_CONFIG_ITEM_DOCKER_ORCHESTRATION_MODE,
            ],
            condition=lambda profile, orch: (
                profile == PROFILE_MALCOLM and orch == OrchestrationFramework.DOCKER_COMPOSE
            ),
            is_top_level=True,
        )
    ),
    KEY_CONFIG_ITEM_REVERSE_DNS: DependencySpec(
        visibility=VisibilityRule(
            depends_on=KEY_CONFIG_ITEM_MALCOLM_PROFILE,
            condition=lambda profile: profile == PROFILE_MALCOLM,
            is_top_level=True,
        )
    ),
    KEY_CONFIG_ITEM_AUTO_OUI: DependencySpec(
        visibility=VisibilityRule(
            depends_on=KEY_CONFIG_ITEM_MALCOLM_PROFILE,
            condition=lambda profile: profile == PROFILE_MALCOLM,
            is_top_level=True,
        )
    ),
    KEY_CONFIG_ITEM_AUTO_FREQ: DependencySpec(
        visibility=VisibilityRule(
            depends_on=KEY_CONFIG_ITEM_MALCOLM_PROFILE,
            condition=lambda profile: profile == PROFILE_MALCOLM,
            is_top_level=True,
        )
    ),
    KEY_CONFIG_ITEM_OPEN_PORTS: DependencySpec(
        visibility=VisibilityRule(
            depends_on=KEY_CONFIG_ITEM_MALCOLM_PROFILE,
            condition=lambda profile: profile == PROFILE_MALCOLM,
            is_top_level=True,
        ),
        value=ValueRule(
            depends_on=KEY_CONFIG_ITEM_DOCKER_ORCHESTRATION_MODE,
            condition=lambda orch_mode: orch_mode == OrchestrationFramework.KUBERNETES,
            default_value=OpenPortsChoices.CUSTOMIZE,
        ),
    ),
    KEY_CONFIG_ITEM_NETBOX_MODE: DependencySpec(
        visibility=VisibilityRule(
            depends_on=None,
            condition=True,
            is_top_level=True,
        ),
        value=ValueRule(
            depends_on=KEY_CONFIG_ITEM_MALCOLM_PROFILE,
            condition=True,
            default_value=lambda profile: (
                NetboxMode.LOCAL.value if profile == PROFILE_MALCOLM else NetboxMode.REMOTE.value
            ),
            only_if_unmodified=False,
        ),
    ),
    KEY_CONFIG_ITEM_INDEX_MANAGEMENT_POLICY: DependencySpec(
        visibility=VisibilityRule(
            depends_on=KEY_CONFIG_ITEM_MALCOLM_PROFILE,
            condition=lambda profile: profile == PROFILE_MALCOLM,
            is_top_level=True,
        )
    ),
    KEY_CONFIG_ITEM_CLEAN_UP_OLD_ARTIFACTS: DependencySpec(
        visibility=VisibilityRule(
            depends_on=None,
            # actually visible in both profiles, as "hedgehog mode" arkime viewer manages PCAP too
            condition=True,
            is_top_level=True,
        ),
        value=ValueRule(
            depends_on=[
                KEY_CONFIG_ITEM_ARKIME_MANAGE_PCAP,
                KEY_CONFIG_ITEM_CLEAN_UP_OLD_INDICES,
                KEY_CONFIG_ITEM_PRUNE_PCAP,
                KEY_CONFIG_ITEM_PRUNE_LOGS,
            ],
            condition=True,
            default_value=lambda arkime_manage_pcap, clean_old_indices, hedgehog_iso_prune_pcap, hedgehog_iso_prune_logs: (
                bool(arkime_manage_pcap)
                or bool(clean_old_indices)
                or (
                    SYSTEM_INFO["malcolm_iso_install"]
                    and (bool(hedgehog_iso_prune_logs) or bool(hedgehog_iso_prune_pcap))
                )
            ),
        ),
    ),
    # Hedgehog profile items
    KEY_CONFIG_ITEM_REMOTE_MALCOLM_HOST: DependencySpec(
        visibility=VisibilityRule(
            depends_on=KEY_CONFIG_ITEM_MALCOLM_PROFILE,
            condition=lambda profile: profile == PROFILE_HEDGEHOG,
            ui_parent=KEY_CONFIG_ITEM_MALCOLM_PROFILE,
        ),
        value=ValueRule(
            depends_on=KEY_CONFIG_ITEM_MALCOLM_PROFILE,
            condition=lambda profile: profile == PROFILE_MALCOLM,
            default_value="",
            only_if_unmodified=False,
        ),
    ),
    KEY_CONFIG_ITEM_LOGSTASH_HOST: DependencySpec(
        visibility=VisibilityRule(
            depends_on=KEY_CONFIG_ITEM_MALCOLM_PROFILE,
            condition=lambda profile: profile == PROFILE_HEDGEHOG,
            ui_parent=KEY_CONFIG_ITEM_MALCOLM_PROFILE,
        ),
        value=ValueRule(
            depends_on=[
                KEY_CONFIG_ITEM_MALCOLM_PROFILE,
                KEY_CONFIG_ITEM_REMOTE_MALCOLM_HOST,
            ],
            condition=True,
            default_value=lambda profile, malcolm_host: (
                LOCAL_LOGSTASH_HOST
                if profile == PROFILE_MALCOLM
                else (f"{malcolm_host}:{SERVICE_PORT_LOGSTASH}" if malcolm_host else DEFAULT_VALUE_UNCHANGED)
            ),
            only_if_unmodified=False,
        ),
    ),
    KEY_CONFIG_ITEM_REACHBACK_REQUEST_ACL: DependencySpec(
        visibility=VisibilityRule(
            depends_on=KEY_CONFIG_ITEM_MALCOLM_PROFILE,
            condition=lambda profile: (profile == PROFILE_HEDGEHOG) and SYSTEM_INFO["malcolm_iso_install"],
            ui_parent=KEY_CONFIG_ITEM_MALCOLM_PROFILE,
        ),
        value=ValueRule(
            depends_on=[
                KEY_CONFIG_ITEM_MALCOLM_PROFILE,
                KEY_CONFIG_ITEM_REMOTE_MALCOLM_HOST,
            ],
            condition=True,
            default_value=lambda profile, malcolm_host: (
                []
                if ((profile == PROFILE_MALCOLM) or (not SYSTEM_INFO["malcolm_iso_install"]))
                else ([malcolm_host] if isipaddress(malcolm_host) else DEFAULT_VALUE_UNCHANGED)
            ),
            only_if_unmodified=False,
        ),
    ),
    KEY_CONFIG_ITEM_AUX_FW_AIDE: DependencySpec(
        visibility=VisibilityRule(
            depends_on=KEY_CONFIG_ITEM_MALCOLM_PROFILE,
            condition=SYSTEM_INFO["malcolm_iso_install"],
            ui_parent=KEY_CONFIG_ITEM_MALCOLM_PROFILE,
        ),
    ),
    KEY_CONFIG_ITEM_AUX_FW_AUDITLOG: DependencySpec(
        visibility=VisibilityRule(
            depends_on=KEY_CONFIG_ITEM_MALCOLM_PROFILE,
            condition=SYSTEM_INFO["malcolm_iso_install"],
            ui_parent=KEY_CONFIG_ITEM_MALCOLM_PROFILE,
        ),
    ),
    KEY_CONFIG_ITEM_AUX_FW_CPU: DependencySpec(
        visibility=VisibilityRule(
            depends_on=KEY_CONFIG_ITEM_MALCOLM_PROFILE,
            condition=SYSTEM_INFO["malcolm_iso_install"],
            ui_parent=KEY_CONFIG_ITEM_MALCOLM_PROFILE,
        ),
    ),
    KEY_CONFIG_ITEM_AUX_FW_DF: DependencySpec(
        visibility=VisibilityRule(
            depends_on=KEY_CONFIG_ITEM_MALCOLM_PROFILE,
            condition=SYSTEM_INFO["malcolm_iso_install"],
            ui_parent=KEY_CONFIG_ITEM_MALCOLM_PROFILE,
        ),
    ),
    KEY_CONFIG_ITEM_AUX_FW_DISK: DependencySpec(
        visibility=VisibilityRule(
            depends_on=KEY_CONFIG_ITEM_MALCOLM_PROFILE,
            condition=SYSTEM_INFO["malcolm_iso_install"],
            ui_parent=KEY_CONFIG_ITEM_MALCOLM_PROFILE,
        ),
    ),
    KEY_CONFIG_ITEM_AUX_FW_KMSG: DependencySpec(
        visibility=VisibilityRule(
            depends_on=KEY_CONFIG_ITEM_MALCOLM_PROFILE,
            condition=SYSTEM_INFO["malcolm_iso_install"],
            ui_parent=KEY_CONFIG_ITEM_MALCOLM_PROFILE,
        ),
    ),
    KEY_CONFIG_ITEM_AUX_FW_MEM: DependencySpec(
        visibility=VisibilityRule(
            depends_on=KEY_CONFIG_ITEM_MALCOLM_PROFILE,
            condition=SYSTEM_INFO["malcolm_iso_install"],
            ui_parent=KEY_CONFIG_ITEM_MALCOLM_PROFILE,
        ),
    ),
    KEY_CONFIG_ITEM_AUX_FW_NETWORK: DependencySpec(
        visibility=VisibilityRule(
            depends_on=KEY_CONFIG_ITEM_MALCOLM_PROFILE,
            condition=SYSTEM_INFO["malcolm_iso_install"],
            ui_parent=KEY_CONFIG_ITEM_MALCOLM_PROFILE,
        ),
    ),
    KEY_CONFIG_ITEM_AUX_FW_SYSTEMD: DependencySpec(
        visibility=VisibilityRule(
            depends_on=KEY_CONFIG_ITEM_MALCOLM_PROFILE,
            condition=SYSTEM_INFO["malcolm_iso_install"],
            ui_parent=KEY_CONFIG_ITEM_MALCOLM_PROFILE,
        ),
    ),
    KEY_CONFIG_ITEM_AUX_FW_THERMAL: DependencySpec(
        visibility=VisibilityRule(
            depends_on=KEY_CONFIG_ITEM_MALCOLM_PROFILE,
            condition=SYSTEM_INFO["malcolm_iso_install"],
            ui_parent=KEY_CONFIG_ITEM_MALCOLM_PROFILE,
        ),
    ),
    KEY_CONFIG_ITEM_TRAEFIK_HOST: DependencySpec(
        visibility=VisibilityRule(
            depends_on=KEY_CONFIG_ITEM_TRAEFIK_LABELS,
            condition=lambda labels: bool(labels),
            ui_parent=KEY_CONFIG_ITEM_TRAEFIK_LABELS,
        )
    ),
    KEY_CONFIG_ITEM_TRAEFIK_ENTRYPOINT: DependencySpec(
        visibility=VisibilityRule(
            depends_on=KEY_CONFIG_ITEM_TRAEFIK_LABELS,
            condition=lambda labels: bool(labels),
            ui_parent=KEY_CONFIG_ITEM_TRAEFIK_LABELS,
        )
    ),
    KEY_CONFIG_ITEM_TRAEFIK_RESOLVER: DependencySpec(
        visibility=VisibilityRule(
            depends_on=KEY_CONFIG_ITEM_TRAEFIK_LABELS,
            condition=lambda labels: bool(labels),
            ui_parent=KEY_CONFIG_ITEM_TRAEFIK_LABELS,
        )
    ),
    # Traefik OpenSearch host: only relevant when labels are enabled and primary store is local OpenSearch
    KEY_CONFIG_ITEM_TRAEFIK_OPENSEARCH_HOST: DependencySpec(
        visibility=VisibilityRule(
            depends_on=[
                KEY_CONFIG_ITEM_TRAEFIK_LABELS,
                KEY_CONFIG_ITEM_OPENSEARCH_PRIMARY_MODE,
            ],
            condition=lambda labels, mode: bool(labels) and (mode == SearchEngineMode.OPENSEARCH_LOCAL.value),
            ui_parent=KEY_CONFIG_ITEM_TRAEFIK_LABELS,
        )
    ),
    # Malcolm profile children
    KEY_CONFIG_ITEM_EXTRA_TAGS: DependencySpec(
        visibility=VisibilityRule(
            depends_on=KEY_CONFIG_ITEM_MALCOLM_PROFILE,
            condition=lambda profile: profile in (PROFILE_HEDGEHOG, PROFILE_MALCOLM),
            ui_parent=KEY_CONFIG_ITEM_MALCOLM_PROFILE,
        )
    ),
    KEY_CONFIG_ITEM_OPENSEARCH_PRIMARY_MODE: DependencySpec(
        visibility=VisibilityRule(
            depends_on=None,
            condition=True,
            ui_parent=KEY_CONFIG_ITEM_MALCOLM_PROFILE,
        ),
        value=ValueRule(
            depends_on=KEY_CONFIG_ITEM_MALCOLM_PROFILE,
            condition=True,
            default_value=lambda profile: (
                SearchEngineMode.OPENSEARCH_LOCAL.value
                if (profile == PROFILE_MALCOLM)
                else SearchEngineMode.OPENSEARCH_REMOTE.value
            ),
        ),
    ),
    KEY_CONFIG_ITEM_SECONDARY_DOCUMENT_STORE: DependencySpec(
        visibility=VisibilityRule(
            depends_on=KEY_CONFIG_ITEM_MALCOLM_PROFILE,
            condition=lambda profile: profile == PROFILE_MALCOLM,
            ui_parent=KEY_CONFIG_ITEM_MALCOLM_PROFILE,
        )
    ),
    KEY_CONFIG_ITEM_LS_MEMORY: DependencySpec(
        visibility=VisibilityRule(
            depends_on=KEY_CONFIG_ITEM_MALCOLM_PROFILE,
            condition=lambda profile: profile == PROFILE_MALCOLM,
            ui_parent=KEY_CONFIG_ITEM_MALCOLM_PROFILE,
        ),
        value=ValueRule(
            depends_on=KEY_CONFIG_ITEM_DOCKER_ORCHESTRATION_MODE,
            condition=lambda orch_mode: orch_mode == OrchestrationFramework.KUBERNETES,
            default_value=LOGSTASH_MEMORY_KUBERNETES,
        ),
    ),
    KEY_CONFIG_ITEM_LS_WORKERS: DependencySpec(
        visibility=VisibilityRule(
            depends_on=KEY_CONFIG_ITEM_MALCOLM_PROFILE,
            condition=lambda profile: profile == PROFILE_MALCOLM,
            ui_parent=KEY_CONFIG_ITEM_MALCOLM_PROFILE,
        ),
        value=ValueRule(
            depends_on=KEY_CONFIG_ITEM_DOCKER_ORCHESTRATION_MODE,
            condition=lambda orch_mode: orch_mode == OrchestrationFramework.KUBERNETES,
            default_value=LOGSTASH_WORKERS_KUBERNETES,
        ),
    ),
    # -------------------------------------------------------------------------
    # OPENSEARCH/ELASTICSEARCH DEPENDENCIES
    # -------------------------------------------------------------------------
    KEY_CONFIG_ITEM_OPENSEARCH_PRIMARY_SSL_VERIFY: DependencySpec(
        visibility=VisibilityRule(
            depends_on=KEY_CONFIG_ITEM_OPENSEARCH_PRIMARY_MODE,
            condition=lambda mode: mode
            in [
                SearchEngineMode.OPENSEARCH_REMOTE.value,
                SearchEngineMode.ELASTICSEARCH_REMOTE.value,
            ],
            ui_parent=KEY_CONFIG_ITEM_OPENSEARCH_PRIMARY_MODE,
        )
    ),
    KEY_CONFIG_ITEM_OPENSEARCH_SECONDARY_SSL_VERIFY: DependencySpec(
        visibility=VisibilityRule(
            depends_on=KEY_CONFIG_ITEM_OPENSEARCH_SECONDARY_MODE,
            condition=lambda mode: mode
            in [
                SearchEngineMode.OPENSEARCH_REMOTE.value,
                SearchEngineMode.ELASTICSEARCH_REMOTE.value,
            ],
            ui_parent=KEY_CONFIG_ITEM_OPENSEARCH_SECONDARY_MODE,
        )
    ),
    KEY_CONFIG_ITEM_OS_MEMORY: DependencySpec(
        visibility=VisibilityRule(
            depends_on=[KEY_CONFIG_ITEM_MALCOLM_PROFILE, KEY_CONFIG_ITEM_OPENSEARCH_PRIMARY_MODE],
            condition=lambda profile, mode: (
                (profile == PROFILE_MALCOLM) and (mode == SearchEngineMode.OPENSEARCH_LOCAL.value)
            ),
            ui_parent=KEY_CONFIG_ITEM_MALCOLM_PROFILE,
        ),
        value=ValueRule(
            depends_on=KEY_CONFIG_ITEM_DOCKER_ORCHESTRATION_MODE,
            condition=lambda orch_mode: orch_mode == OrchestrationFramework.KUBERNETES,
            default_value=OPENSEARCH_MEMORY_KUBERNETES,
        ),
    ),
    KEY_CONFIG_ITEM_OPENSEARCH_PRIMARY_URL: DependencySpec(
        visibility=VisibilityRule(
            depends_on=[KEY_CONFIG_ITEM_MALCOLM_PROFILE, KEY_CONFIG_ITEM_OPENSEARCH_PRIMARY_MODE],
            condition=lambda profile, mode: (
                (profile == PROFILE_HEDGEHOG) or (mode != SearchEngineMode.OPENSEARCH_LOCAL.value)
            ),
            ui_parent=KEY_CONFIG_ITEM_OPENSEARCH_PRIMARY_MODE,
        ),
        value=ValueRule(
            depends_on=[
                KEY_CONFIG_ITEM_MALCOLM_PROFILE,
                KEY_CONFIG_ITEM_OPENSEARCH_PRIMARY_MODE,
                KEY_CONFIG_ITEM_REMOTE_MALCOLM_HOST,
            ],
            condition=True,
            default_value=lambda profile, mode, malcolm_host: (
                LOCAL_OPENSEARCH_URL
                if ((profile == PROFILE_MALCOLM) and (mode == SearchEngineMode.OPENSEARCH_LOCAL.value))
                else (
                    f"https://{malcolm_host}:{SERVICE_PORT_OSMALCOLM}"
                    if (malcolm_host and (mode == SearchEngineMode.OPENSEARCH_REMOTE.value))
                    else DEFAULT_VALUE_UNCHANGED
                )
            ),
            only_if_unmodified=False,
        ),
    ),
    KEY_CONFIG_ITEM_OPENSEARCH_SECONDARY_URL: DependencySpec(
        visibility=VisibilityRule(
            depends_on=KEY_CONFIG_ITEM_OPENSEARCH_SECONDARY_MODE,
            condition=lambda mode: mode
            in [
                SearchEngineMode.OPENSEARCH_REMOTE.value,
                SearchEngineMode.ELASTICSEARCH_REMOTE.value,
            ],
            ui_parent=KEY_CONFIG_ITEM_OPENSEARCH_SECONDARY_MODE,
        )
    ),
    KEY_CONFIG_ITEM_DASHBOARDS_URL: DependencySpec(
        visibility=VisibilityRule(
            depends_on=[KEY_CONFIG_ITEM_MALCOLM_PROFILE, KEY_CONFIG_ITEM_OPENSEARCH_PRIMARY_MODE],
            condition=lambda profile, mode: (
                (profile == PROFILE_MALCOLM) and (mode == SearchEngineMode.ELASTICSEARCH_REMOTE.value)
            ),
            ui_parent=KEY_CONFIG_ITEM_OPENSEARCH_PRIMARY_MODE,
        ),
        value=ValueRule(
            depends_on=KEY_CONFIG_ITEM_OPENSEARCH_PRIMARY_MODE,
            condition=lambda mode: (
                mode in [SearchEngineMode.OPENSEARCH_LOCAL.value, SearchEngineMode.OPENSEARCH_REMOTE.value]
            ),
            default_value=LOCAL_DASHBOARDS_URL,
            only_if_unmodified=False,
        ),
    ),
    KEY_CONFIG_ITEM_DASHBOARDS_DARK_MODE: DependencySpec(
        visibility=VisibilityRule(
            depends_on=[
                KEY_CONFIG_ITEM_MALCOLM_PROFILE,
                KEY_CONFIG_ITEM_OPENSEARCH_PRIMARY_MODE,
            ],
            condition=lambda profile, mode: (
                profile == PROFILE_MALCOLM and mode != SearchEngineMode.ELASTICSEARCH_REMOTE.value
            ),
        )
    ),
    KEY_CONFIG_ITEM_OPENSEARCH_SECONDARY_MODE: DependencySpec(
        visibility=VisibilityRule(
            depends_on=KEY_CONFIG_ITEM_SECONDARY_DOCUMENT_STORE,
            condition=lambda enabled: bool(enabled),
            ui_parent=KEY_CONFIG_ITEM_SECONDARY_DOCUMENT_STORE,
        )
    ),
    # Index management
    KEY_CONFIG_ITEM_INDEX_MANAGEMENT_HOT_WARM: DependencySpec(
        visibility=VisibilityRule(
            depends_on=KEY_CONFIG_ITEM_INDEX_MANAGEMENT_POLICY,
            condition=lambda enabled: bool(enabled),
            ui_parent=KEY_CONFIG_ITEM_INDEX_MANAGEMENT_POLICY,
        )
    ),
    KEY_CONFIG_ITEM_INDEX_MANAGEMENT_HISTORY_IN_WEEKS: DependencySpec(
        visibility=VisibilityRule(
            depends_on=KEY_CONFIG_ITEM_INDEX_MANAGEMENT_POLICY,
            condition=lambda enabled: bool(enabled),
            ui_parent=KEY_CONFIG_ITEM_INDEX_MANAGEMENT_POLICY,
        )
    ),
    KEY_CONFIG_ITEM_INDEX_MANAGEMENT_OPTIMIZATION_TIME_PERIOD: DependencySpec(
        visibility=VisibilityRule(
            depends_on=KEY_CONFIG_ITEM_INDEX_MANAGEMENT_POLICY,
            condition=lambda enabled: bool(enabled),
            ui_parent=KEY_CONFIG_ITEM_INDEX_MANAGEMENT_POLICY,
        )
    ),
    KEY_CONFIG_ITEM_INDEX_MANAGEMENT_OPTIMIZE_SESSION_SEGMENTS: DependencySpec(
        visibility=VisibilityRule(
            depends_on=KEY_CONFIG_ITEM_INDEX_MANAGEMENT_POLICY,
            condition=lambda enabled: bool(enabled),
            ui_parent=KEY_CONFIG_ITEM_INDEX_MANAGEMENT_POLICY,
        )
    ),
    KEY_CONFIG_ITEM_INDEX_MANAGEMENT_REPLICAS: DependencySpec(
        visibility=VisibilityRule(
            depends_on=KEY_CONFIG_ITEM_INDEX_MANAGEMENT_POLICY,
            condition=lambda enabled: bool(enabled),
            ui_parent=KEY_CONFIG_ITEM_INDEX_MANAGEMENT_POLICY,
        )
    ),
    KEY_CONFIG_ITEM_INDEX_MANAGEMENT_SPI_DATA_RETENTION: DependencySpec(
        visibility=VisibilityRule(
            depends_on=KEY_CONFIG_ITEM_INDEX_MANAGEMENT_POLICY,
            condition=lambda enabled: bool(enabled),
            ui_parent=KEY_CONFIG_ITEM_INDEX_MANAGEMENT_POLICY,
        )
    ),
    # -------------------------------------------------------------------------
    # LIVE CAPTURE DEPENDENCIES
    # -------------------------------------------------------------------------
    # Parent item: automatically enabled when any capture/analysis method is enabled
    KEY_CONFIG_ITEM_CAPTURE_LIVE_NETWORK_TRAFFIC: DependencySpec(
        value=ValueRule(
            depends_on=[
                KEY_CONFIG_ITEM_PCAP_NETSNIFF,
                KEY_CONFIG_ITEM_PCAP_TCPDUMP,
                KEY_CONFIG_ITEM_LIVE_ARKIME,
                KEY_CONFIG_ITEM_LIVE_ZEEK,
                KEY_CONFIG_ITEM_LIVE_SURICATA,
            ],
            condition=True,
            default_value=lambda netsniff, tcpdump, arkime, zeek, suricata: (
                bool(netsniff) or bool(tcpdump) or bool(arkime) or bool(zeek) or bool(suricata)
            ),
        ),
    ),
    KEY_CONFIG_ITEM_PCAP_IFACE: DependencySpec(
        visibility=VisibilityRule(
            depends_on=KEY_CONFIG_ITEM_CAPTURE_LIVE_NETWORK_TRAFFIC,
            condition=lambda enabled: bool(enabled),
            ui_parent=KEY_CONFIG_ITEM_CAPTURE_LIVE_NETWORK_TRAFFIC,
        )
    ),
    KEY_CONFIG_ITEM_PCAP_NETSNIFF: DependencySpec(
        visibility=VisibilityRule(
            depends_on=KEY_CONFIG_ITEM_CAPTURE_LIVE_NETWORK_TRAFFIC,
            condition=lambda enabled: bool(enabled),
            ui_parent=KEY_CONFIG_ITEM_CAPTURE_LIVE_NETWORK_TRAFFIC,
        ),
        value=ValueRule(
            depends_on=[
                KEY_CONFIG_ITEM_CAPTURE_LIVE_NETWORK_TRAFFIC,
                KEY_CONFIG_ITEM_MALCOLM_PROFILE,
                KEY_CONFIG_ITEM_OPENSEARCH_PRIMARY_MODE,
                KEY_CONFIG_ITEM_PCAP_TCPDUMP,
                KEY_CONFIG_ITEM_LIVE_ARKIME,
            ],
            # Compute the default based on current dependencies. This makes
            # netsniff the default capture engine for Malcolm profile when
            # using local OpenSearch and live capture is enabled, unless the
            # user has explicitly enabled tcpdump or Arkime.
            condition=True,
            default_value=lambda live_traffic, profile, mode, tcpdump, arkime: (
                bool(live_traffic)
                and (profile == PROFILE_MALCOLM)
                and (mode == SearchEngineMode.OPENSEARCH_LOCAL.value)
                and (not bool(tcpdump))
                and (not bool(arkime))
            ),
        ),
    ),
    KEY_CONFIG_ITEM_PCAP_TCPDUMP: DependencySpec(
        visibility=VisibilityRule(
            depends_on=KEY_CONFIG_ITEM_CAPTURE_LIVE_NETWORK_TRAFFIC,
            condition=lambda enabled: bool(enabled),
            ui_parent=KEY_CONFIG_ITEM_CAPTURE_LIVE_NETWORK_TRAFFIC,
        ),
        value=ValueRule(
            depends_on=[
                KEY_CONFIG_ITEM_CAPTURE_LIVE_NETWORK_TRAFFIC,
                KEY_CONFIG_ITEM_MALCOLM_PROFILE,
                KEY_CONFIG_ITEM_OPENSEARCH_PRIMARY_MODE,
                KEY_CONFIG_ITEM_PCAP_NETSNIFF,
                KEY_CONFIG_ITEM_LIVE_ARKIME,
            ],
            condition=True,
            default_value=lambda live_traffic, profile, mode, netsniff, arkime: (
                bool(live_traffic)
                and (profile == PROFILE_MALCOLM)
                and (mode == SearchEngineMode.OPENSEARCH_LOCAL.value)
                and (not bool(netsniff))
                and (not bool(arkime))
            ),
        ),
    ),
    KEY_CONFIG_ITEM_LIVE_ARKIME: DependencySpec(
        visibility=VisibilityRule(
            depends_on=[
                KEY_CONFIG_ITEM_CAPTURE_LIVE_NETWORK_TRAFFIC,
                KEY_CONFIG_ITEM_MALCOLM_PROFILE,
                KEY_CONFIG_ITEM_OPENSEARCH_PRIMARY_MODE,
                KEY_CONFIG_ITEM_PCAP_NETSNIFF,
                KEY_CONFIG_ITEM_PCAP_TCPDUMP,
            ],
            condition=lambda live_traffic, profile, mode, _netsniff, _tcpdump: (
                bool(live_traffic)
                and ((profile == PROFILE_HEDGEHOG) or (mode != SearchEngineMode.OPENSEARCH_LOCAL.value))
            ),
            ui_parent=KEY_CONFIG_ITEM_CAPTURE_LIVE_NETWORK_TRAFFIC,
        ),
        value=ValueRule(
            depends_on=[
                KEY_CONFIG_ITEM_CAPTURE_LIVE_NETWORK_TRAFFIC,
                KEY_CONFIG_ITEM_MALCOLM_PROFILE,
                KEY_CONFIG_ITEM_OPENSEARCH_PRIMARY_MODE,
                KEY_CONFIG_ITEM_PCAP_NETSNIFF,
                KEY_CONFIG_ITEM_PCAP_TCPDUMP,
            ],
            # Always compute the default from current dependency values, but
            # only apply it if the user hasn't modified the item yet.
            condition=True,
            default_value=lambda live_traffic, profile, mode, netsniff, tcpdump: (
                bool(live_traffic)
                and ((profile == PROFILE_HEDGEHOG) or (mode != SearchEngineMode.OPENSEARCH_LOCAL.value))
                and (not bool(netsniff))
                and (not bool(tcpdump))
            ),
        ),
    ),
    KEY_CONFIG_ITEM_LIVE_ZEEK: DependencySpec(
        visibility=VisibilityRule(
            depends_on=KEY_CONFIG_ITEM_CAPTURE_LIVE_NETWORK_TRAFFIC,
            condition=lambda enabled: bool(enabled),
            ui_parent=KEY_CONFIG_ITEM_CAPTURE_LIVE_NETWORK_TRAFFIC,
        ),
        value=ValueRule(
            depends_on=KEY_CONFIG_ITEM_CAPTURE_LIVE_NETWORK_TRAFFIC,
            condition=True,
            default_value=lambda enabled: bool(enabled),
            only_if_unmodified=False,
        ),
    ),
    KEY_CONFIG_ITEM_LIVE_SURICATA: DependencySpec(
        visibility=VisibilityRule(
            depends_on=KEY_CONFIG_ITEM_CAPTURE_LIVE_NETWORK_TRAFFIC,
            condition=lambda enabled: bool(enabled),
            ui_parent=KEY_CONFIG_ITEM_CAPTURE_LIVE_NETWORK_TRAFFIC,
        ),
        value=ValueRule(
            depends_on=KEY_CONFIG_ITEM_CAPTURE_LIVE_NETWORK_TRAFFIC,
            condition=True,
            default_value=lambda enabled: bool(enabled),
            only_if_unmodified=False,
        ),
    ),
    KEY_CONFIG_ITEM_PCAP_FILTER: DependencySpec(
        visibility=VisibilityRule(
            depends_on=KEY_CONFIG_ITEM_CAPTURE_LIVE_NETWORK_TRAFFIC,
            condition=lambda enabled: bool(enabled),
            ui_parent=KEY_CONFIG_ITEM_CAPTURE_LIVE_NETWORK_TRAFFIC,
        )
    ),
    KEY_CONFIG_ITEM_TWEAK_IFACE: DependencySpec(
        visibility=VisibilityRule(
            depends_on=KEY_CONFIG_ITEM_CAPTURE_LIVE_NETWORK_TRAFFIC,
            condition=lambda enabled: bool(enabled),
            ui_parent=KEY_CONFIG_ITEM_CAPTURE_LIVE_NETWORK_TRAFFIC,
        ),
        value=ValueRule(
            depends_on=KEY_CONFIG_ITEM_CAPTURE_LIVE_NETWORK_TRAFFIC,
            condition=True,
            default_value=lambda enabled: bool(enabled),
            only_if_unmodified=False,
        ),
    ),
    KEY_CONFIG_ITEM_CAPTURE_STATS: DependencySpec(
        visibility=VisibilityRule(
            depends_on=KEY_CONFIG_ITEM_CAPTURE_LIVE_NETWORK_TRAFFIC,
            condition=lambda enabled: bool(enabled),
            ui_parent=KEY_CONFIG_ITEM_CAPTURE_LIVE_NETWORK_TRAFFIC,
        ),
        value=ValueRule(
            depends_on=KEY_CONFIG_ITEM_CAPTURE_LIVE_NETWORK_TRAFFIC,
            condition=lambda enabled: bool(enabled),
            default_value=True,
        ),
    ),
    # Live Arkime node host (Malcolm profile + live arkime enabled)
    KEY_CONFIG_ITEM_LIVE_ARKIME_NODE_HOST: DependencySpec(
        visibility=VisibilityRule(
            depends_on=KEY_CONFIG_ITEM_LIVE_ARKIME,
            condition=lambda live_arkime: bool(live_arkime),
            ui_parent=KEY_CONFIG_ITEM_LIVE_ARKIME,
        )
    ),
    KEY_CONFIG_ITEM_LIVE_ARKIME_COMP_TYPE: DependencySpec(
        visibility=VisibilityRule(
            depends_on=KEY_CONFIG_ITEM_LIVE_ARKIME,
            condition=lambda live_arkime: bool(live_arkime),
            ui_parent=KEY_CONFIG_ITEM_LIVE_ARKIME,
        )
    ),
    KEY_CONFIG_ITEM_LIVE_ARKIME_COMP_LEVEL: DependencySpec(
        visibility=VisibilityRule(
            depends_on=[KEY_CONFIG_ITEM_LIVE_ARKIME, KEY_CONFIG_ITEM_LIVE_ARKIME_COMP_TYPE],
            condition=lambda live_arkime, comp_type: (
                bool(live_arkime) and (comp_type != ArkimePCAPCompression.NONE.value)
            ),
            ui_parent=KEY_CONFIG_ITEM_LIVE_ARKIME_COMP_TYPE,
        )
    ),
    KEY_CONFIG_ITEM_ARKIME_EXPOSE_WISE: DependencySpec(
        visibility=VisibilityRule(
            depends_on=[KEY_CONFIG_ITEM_MALCOLM_PROFILE, KEY_CONFIG_ITEM_AUTO_ARKIME],
            condition=lambda profile, _auto_arkime: profile == PROFILE_MALCOLM,
            ui_parent=KEY_CONFIG_ITEM_AUTO_ARKIME,
        ),
        value=ValueRule(
            depends_on=KEY_CONFIG_ITEM_MALCOLM_PROFILE,
            condition=True,
            default_value=lambda profile: profile == PROFILE_MALCOLM,
            only_if_unmodified=False,
        ),
    ),
    KEY_CONFIG_ITEM_ARKIME_ALLOW_WISE_CONFIG: DependencySpec(
        visibility=VisibilityRule(
            depends_on=[KEY_CONFIG_ITEM_MALCOLM_PROFILE, KEY_CONFIG_ITEM_AUTO_ARKIME],
            condition=lambda profile, _auto_arkime: profile == PROFILE_MALCOLM,
            ui_parent=KEY_CONFIG_ITEM_AUTO_ARKIME,
        ),
        value=ValueRule(
            depends_on=KEY_CONFIG_ITEM_MALCOLM_PROFILE,
            condition=lambda profile: (profile != PROFILE_MALCOLM),
            default_value=False,
            only_if_unmodified=False,
        ),
    ),
    KEY_CONFIG_ITEM_ARKIME_WISE_URL: DependencySpec(
        visibility=VisibilityRule(
            depends_on=[KEY_CONFIG_ITEM_MALCOLM_PROFILE, KEY_CONFIG_ITEM_AUTO_ARKIME],
            condition=lambda profile, _auto_arkime: profile != PROFILE_MALCOLM,
            ui_parent=KEY_CONFIG_ITEM_AUTO_ARKIME,
        ),
        value=ValueRule(
            depends_on=[
                KEY_CONFIG_ITEM_MALCOLM_PROFILE,
                KEY_CONFIG_ITEM_REMOTE_MALCOLM_HOST,
            ],
            condition=True,
            default_value=lambda profile, malcolm_host: (
                LOCAL_ARKIME_WISE_URL
                if (profile == PROFILE_MALCOLM)
                else (f"https://{malcolm_host}/wise/" if malcolm_host else DEFAULT_VALUE_UNCHANGED)
            ),
            only_if_unmodified=False,
        ),
    ),
    # -------------------------------------------------------------------------
    # NETBOX DEPENDENCIES
    # -------------------------------------------------------------------------
    KEY_CONFIG_ITEM_NETBOX_URL: DependencySpec(
        visibility=VisibilityRule(
            depends_on=[KEY_CONFIG_ITEM_MALCOLM_PROFILE, KEY_CONFIG_ITEM_NETBOX_MODE],
            condition=lambda profile, mode: ((profile == PROFILE_MALCOLM) and (mode == NetboxMode.REMOTE.value)),
            ui_parent=KEY_CONFIG_ITEM_NETBOX_MODE,
        )
    ),
    KEY_CONFIG_ITEM_NETBOX_LOGSTASH_ENRICH: DependencySpec(
        visibility=VisibilityRule(
            depends_on=[KEY_CONFIG_ITEM_MALCOLM_PROFILE, KEY_CONFIG_ITEM_NETBOX_MODE],
            condition=lambda profile, mode: ((profile == PROFILE_MALCOLM) and (mode != NetboxMode.DISABLED.value)),
            ui_parent=KEY_CONFIG_ITEM_NETBOX_MODE,
        )
    ),
    KEY_CONFIG_ITEM_NETBOX_AUTO_POPULATE: DependencySpec(
        visibility=VisibilityRule(
            depends_on=[KEY_CONFIG_ITEM_MALCOLM_PROFILE, KEY_CONFIG_ITEM_NETBOX_MODE],
            condition=lambda profile, mode: ((profile == PROFILE_MALCOLM) and (mode != NetboxMode.DISABLED.value)),
            ui_parent=KEY_CONFIG_ITEM_NETBOX_MODE,
        )
    ),
    KEY_CONFIG_ITEM_NETBOX_LOGSTASH_AUTO_CREATE_PREFIX: DependencySpec(
        visibility=VisibilityRule(
            depends_on=[KEY_CONFIG_ITEM_MALCOLM_PROFILE, KEY_CONFIG_ITEM_NETBOX_MODE],
            condition=lambda profile, mode: ((profile == PROFILE_MALCOLM) and (mode != NetboxMode.DISABLED.value)),
            ui_parent=KEY_CONFIG_ITEM_NETBOX_MODE,
        )
    ),
    KEY_CONFIG_ITEM_NETBOX_AUTO_POPULATE_SUBNET_FILTER: DependencySpec(
        visibility=VisibilityRule(
            depends_on=[KEY_CONFIG_ITEM_MALCOLM_PROFILE, KEY_CONFIG_ITEM_NETBOX_MODE],
            condition=lambda profile, mode: ((profile == PROFILE_MALCOLM) and (mode != NetboxMode.DISABLED.value)),
            ui_parent=KEY_CONFIG_ITEM_NETBOX_MODE,
        )
    ),
    KEY_CONFIG_ITEM_NETBOX_SITE_NAME: DependencySpec(
        visibility=VisibilityRule(
            depends_on=[KEY_CONFIG_ITEM_MALCOLM_PROFILE, KEY_CONFIG_ITEM_NETBOX_MODE],
            condition=lambda profile, mode: (
                (profile == PROFILE_HEDGEHOG) or ((profile == PROFILE_MALCOLM) and (mode != NetboxMode.DISABLED.value))
            ),
            ui_parent=KEY_CONFIG_ITEM_NETBOX_MODE,
        )
    ),
    # -------------------------------------------------------------------------
    # FILE CARVING DEPENDENCIES
    # -------------------------------------------------------------------------
    KEY_CONFIG_ITEM_FILE_CARVE_ENABLED: DependencySpec(
        visibility=VisibilityRule(
            depends_on=[KEY_CONFIG_ITEM_AUTO_ZEEK, KEY_CONFIG_ITEM_LIVE_ZEEK],
            condition=lambda auto, live: bool(auto) or bool(live),
            ui_parent=KEY_CONFIG_ITEM_AUTO_ZEEK,
        ),
        value=ValueRule(
            depends_on=KEY_CONFIG_ITEM_FILE_CARVE_MODE,
            condition=True,
            default_value=lambda mode: mode != FileExtractionMode.NONE.value,
        ),
    ),
    KEY_CONFIG_ITEM_FILE_CARVE_MODE: DependencySpec(
        visibility=VisibilityRule(
            depends_on=KEY_CONFIG_ITEM_FILE_CARVE_ENABLED,
            condition=lambda enabled: bool(enabled),
            ui_parent=KEY_CONFIG_ITEM_FILE_CARVE_ENABLED,
        ),
        value=ValueRule(
            depends_on=KEY_CONFIG_ITEM_FILE_CARVE_ENABLED,
            condition=True,
            default_value=lambda enabled: (
                FileExtractionMode.INTERESTING.value if enabled else FileExtractionMode.NONE.value
            ),
            only_if_unmodified=False,
        ),
    ),
    KEY_CONFIG_ITEM_FILE_PRESERVE_MODE: DependencySpec(
        visibility=VisibilityRule(
            depends_on=KEY_CONFIG_ITEM_FILE_CARVE_MODE,
            condition=lambda mode: mode != FileExtractionMode.NONE.value,
            ui_parent=KEY_CONFIG_ITEM_FILE_CARVE_MODE,
        )
    ),
    KEY_CONFIG_ITEM_EXTRACTED_FILE_MAX_SIZE_THRESHOLD: DependencySpec(
        visibility=VisibilityRule(
            depends_on=KEY_CONFIG_ITEM_FILE_CARVE_MODE,
            condition=lambda mode: mode != FileExtractionMode.NONE.value,
            ui_parent=KEY_CONFIG_ITEM_FILE_CARVE_MODE,
        )
    ),
    KEY_CONFIG_ITEM_EXTRACTED_FILE_MAX_PERCENT_THRESHOLD: DependencySpec(
        visibility=VisibilityRule(
            depends_on=KEY_CONFIG_ITEM_FILE_CARVE_MODE,
            condition=lambda mode: mode != FileExtractionMode.NONE.value,
            ui_parent=KEY_CONFIG_ITEM_FILE_CARVE_MODE,
        )
    ),
    KEY_CONFIG_ITEM_FILE_CARVE_HTTP_SERVER: DependencySpec(
        visibility=VisibilityRule(
            depends_on=KEY_CONFIG_ITEM_FILE_CARVE_MODE,
            condition=lambda mode: mode != FileExtractionMode.NONE.value,
            ui_parent=KEY_CONFIG_ITEM_FILE_CARVE_MODE,
        ),
        value=ValueRule(
            depends_on=KEY_CONFIG_ITEM_FILE_CARVE_MODE,
            condition=True,
            default_value=lambda mode: mode != FileExtractionMode.NONE.value,
            only_if_unmodified=False,
        ),
    ),
    KEY_CONFIG_ITEM_FILE_CARVE_HTTP_SERVER_ZIP: DependencySpec(
        visibility=VisibilityRule(
            depends_on=KEY_CONFIG_ITEM_FILE_CARVE_HTTP_SERVER,
            condition=lambda enabled: bool(enabled),
            ui_parent=KEY_CONFIG_ITEM_FILE_CARVE_HTTP_SERVER,
        )
    ),
    KEY_CONFIG_ITEM_FILE_CARVE_HTTP_SERVE_ENCRYPT_KEY: DependencySpec(
        visibility=VisibilityRule(
            depends_on=KEY_CONFIG_ITEM_FILE_CARVE_HTTP_SERVER,
            condition=lambda enabled: bool(enabled),
            ui_parent=KEY_CONFIG_ITEM_FILE_CARVE_HTTP_SERVER,
        )
    ),
    KEY_CONFIG_ITEM_CAPA_SCAN: DependencySpec(
        visibility=VisibilityRule(
            depends_on=KEY_CONFIG_ITEM_FILE_CARVE_MODE,
            condition=lambda mode: mode != FileExtractionMode.NONE.value,
            ui_parent=KEY_CONFIG_ITEM_FILE_CARVE_MODE,
        )
    ),
    KEY_CONFIG_ITEM_CLAM_AV_SCAN: DependencySpec(
        visibility=VisibilityRule(
            depends_on=KEY_CONFIG_ITEM_FILE_CARVE_MODE,
            condition=lambda mode: mode != FileExtractionMode.NONE.value,
            ui_parent=KEY_CONFIG_ITEM_FILE_CARVE_MODE,
        )
    ),
    KEY_CONFIG_ITEM_YARA_SCAN: DependencySpec(
        visibility=VisibilityRule(
            depends_on=KEY_CONFIG_ITEM_FILE_CARVE_MODE,
            condition=lambda mode: mode != FileExtractionMode.NONE.value,
            ui_parent=KEY_CONFIG_ITEM_FILE_CARVE_MODE,
        )
    ),
    KEY_CONFIG_ITEM_VTOT_API_KEY: DependencySpec(
        visibility=VisibilityRule(
            depends_on=KEY_CONFIG_ITEM_FILE_CARVE_MODE,
            condition=lambda mode: mode != FileExtractionMode.NONE.value,
            ui_parent=KEY_CONFIG_ITEM_FILE_CARVE_MODE,
        )
    ),
    KEY_CONFIG_ITEM_FILE_SCAN_RULE_UPDATE: DependencySpec(
        visibility=VisibilityRule(
            depends_on=KEY_CONFIG_ITEM_FILE_CARVE_MODE,
            condition=lambda mode: mode != FileExtractionMode.NONE.value,
            ui_parent=KEY_CONFIG_ITEM_FILE_CARVE_MODE,
        ),
        value=ValueRule(
            depends_on=KEY_CONFIG_ITEM_FILE_CARVE_MODE,
            condition=True,
            default_value=False,
        ),
    ),
    # -------------------------------------------------------------------------
    # OPEN PORTS DEPENDENCIES
    # -------------------------------------------------------------------------
    # OpenSearch exposure (depends on both open ports and primary mode)
    KEY_CONFIG_ITEM_EXPOSE_OPENSEARCH: DependencySpec(
        visibility=VisibilityRule(
            depends_on=[
                KEY_CONFIG_ITEM_OPEN_PORTS,
                KEY_CONFIG_ITEM_OPENSEARCH_PRIMARY_MODE,
                KEY_CONFIG_ITEM_DOCKER_ORCHESTRATION_MODE,
            ],
            condition=lambda expose_selection, mode, orch_mode: (
                (orch_mode != OrchestrationFramework.KUBERNETES)
                and (expose_selection == OpenPortsChoices.CUSTOMIZE.value)
                and (mode == SearchEngineMode.OPENSEARCH_LOCAL.value)
            ),
            ui_parent=KEY_CONFIG_ITEM_OPEN_PORTS,
        ),
        value=ValueRule(
            depends_on=[
                KEY_CONFIG_ITEM_OPEN_PORTS,
                KEY_CONFIG_ITEM_OPENSEARCH_PRIMARY_MODE,
                KEY_CONFIG_ITEM_DOCKER_ORCHESTRATION_MODE,
            ],
            condition=lambda expose_selection, mode, orch_mode: (
                (orch_mode == OrchestrationFramework.KUBERNETES)
                or (
                    (mode == SearchEngineMode.OPENSEARCH_LOCAL.value)
                    and expose_selection in (OpenPortsChoices.YES.value, OpenPortsChoices.NO.value)
                )
            ),
            default_value=lambda expose_selection, mode, orch_mode: (
                (orch_mode == OrchestrationFramework.KUBERNETES)
                or (
                    (mode == SearchEngineMode.OPENSEARCH_LOCAL.value)
                    and {
                        OpenPortsChoices.YES.value: True,
                        OpenPortsChoices.NO.value: False,
                    }.get(expose_selection, DEFAULT_VALUE_UNCHANGED)
                )
            ),
            only_if_unmodified=False,
        ),
    ),
    KEY_CONFIG_ITEM_EXPOSE_LOGSTASH: DependencySpec(
        visibility=VisibilityRule(
            depends_on=[
                KEY_CONFIG_ITEM_OPEN_PORTS,
                KEY_CONFIG_ITEM_DOCKER_ORCHESTRATION_MODE,
            ],
            condition=lambda expose_selection, orch_mode: (
                (orch_mode != OrchestrationFramework.KUBERNETES)
                and (expose_selection == OpenPortsChoices.CUSTOMIZE.value)
            ),
            ui_parent=KEY_CONFIG_ITEM_OPEN_PORTS,
        ),
        value=ValueRule(
            depends_on=[
                KEY_CONFIG_ITEM_OPEN_PORTS,
                KEY_CONFIG_ITEM_DOCKER_ORCHESTRATION_MODE,
            ],
            condition=lambda expose_selection, orch_mode: (
                (orch_mode == OrchestrationFramework.KUBERNETES)
                or expose_selection in (OpenPortsChoices.YES.value, OpenPortsChoices.NO.value)
            ),
            default_value=lambda expose_selection, orch_mode: (
                (orch_mode == OrchestrationFramework.KUBERNETES)
                or {
                    OpenPortsChoices.YES.value: True,
                    OpenPortsChoices.NO.value: False,
                }.get(expose_selection, DEFAULT_VALUE_UNCHANGED)
            ),
            only_if_unmodified=False,
        ),
    ),
    KEY_CONFIG_ITEM_EXPOSE_FILEBEAT_TCP: DependencySpec(
        visibility=VisibilityRule(
            depends_on=[
                KEY_CONFIG_ITEM_OPEN_PORTS,
                KEY_CONFIG_ITEM_DOCKER_ORCHESTRATION_MODE,
            ],
            condition=lambda expose_selection, orch_mode: (
                (orch_mode == OrchestrationFramework.KUBERNETES)
                or (expose_selection == OpenPortsChoices.CUSTOMIZE.value)
            ),
            ui_parent=KEY_CONFIG_ITEM_OPEN_PORTS,
        ),
        value=ValueRule(
            depends_on=[
                KEY_CONFIG_ITEM_OPEN_PORTS,
                KEY_CONFIG_ITEM_DOCKER_ORCHESTRATION_MODE,
            ],
            condition=lambda expose_selection, orch_mode: (
                (orch_mode == OrchestrationFramework.KUBERNETES)
                or expose_selection in (OpenPortsChoices.YES.value, OpenPortsChoices.NO.value)
            ),
            default_value=lambda expose_selection, orch_mode: (
                (orch_mode == OrchestrationFramework.KUBERNETES)
                or {
                    OpenPortsChoices.YES.value: True,
                    OpenPortsChoices.NO.value: False,
                }.get(expose_selection, DEFAULT_VALUE_UNCHANGED)
            ),
            only_if_unmodified=False,
        ),
    ),
    KEY_CONFIG_ITEM_EXPOSE_SFTP: DependencySpec(
        visibility=VisibilityRule(
            depends_on=[
                KEY_CONFIG_ITEM_OPEN_PORTS,
                KEY_CONFIG_ITEM_DOCKER_ORCHESTRATION_MODE,
            ],
            condition=lambda expose_selection, orch_mode: (
                (orch_mode != OrchestrationFramework.KUBERNETES)
                and (expose_selection == OpenPortsChoices.CUSTOMIZE.value)
            ),
            ui_parent=KEY_CONFIG_ITEM_OPEN_PORTS,
        ),
        value=ValueRule(
            depends_on=[
                KEY_CONFIG_ITEM_OPEN_PORTS,
                KEY_CONFIG_ITEM_DOCKER_ORCHESTRATION_MODE,
            ],
            condition=lambda expose_selection, orch_mode: (
                (orch_mode == OrchestrationFramework.KUBERNETES)
                or expose_selection in (OpenPortsChoices.YES.value, OpenPortsChoices.NO.value)
            ),
            default_value=lambda expose_selection, orch_mode: (
                (orch_mode == OrchestrationFramework.KUBERNETES)
                or {
                    # they only get this if they do "customize", it's not on by default even with KEY_CONFIG_ITEM_OPEN_PORTS="Yes""
                    OpenPortsChoices.YES.value: False,
                    OpenPortsChoices.NO.value: False,
                }.get(expose_selection, DEFAULT_VALUE_UNCHANGED)
            ),
            only_if_unmodified=False,
        ),
    ),
    KEY_CONFIG_ITEM_SYSLOG_TCP_PORT: DependencySpec(
        visibility=VisibilityRule(
            depends_on=KEY_CONFIG_ITEM_OPEN_PORTS,
            condition=lambda expose_selection: expose_selection == OpenPortsChoices.CUSTOMIZE.value,
            ui_parent=KEY_CONFIG_ITEM_OPEN_PORTS,
        ),
        value=ValueRule(
            depends_on=[
                KEY_CONFIG_ITEM_OPEN_PORTS,
                KEY_CONFIG_ITEM_DOCKER_ORCHESTRATION_MODE,
            ],
            condition=lambda expose_selection, orch_mode: (
                (orch_mode == OrchestrationFramework.KUBERNETES)
                or expose_selection in (OpenPortsChoices.YES.value, OpenPortsChoices.NO.value)
            ),
            default_value=lambda expose_selection, orch_mode: (
                SYSLOG_DEFAULT_PORT
                if (orch_mode == OrchestrationFramework.KUBERNETES)
                else {
                    # they only get this if they do "customize", it's not on by default even with KEY_CONFIG_ITEM_OPEN_PORTS="Yes""
                    OpenPortsChoices.YES.value: 0,
                    OpenPortsChoices.NO.value: 0,
                }.get(expose_selection, DEFAULT_VALUE_UNCHANGED)
            ),
            only_if_unmodified=False,
        ),
    ),
    KEY_CONFIG_ITEM_SYSLOG_UDP_PORT: DependencySpec(
        visibility=VisibilityRule(
            depends_on=KEY_CONFIG_ITEM_OPEN_PORTS,
            condition=lambda expose_selection: expose_selection == OpenPortsChoices.CUSTOMIZE.value,
            ui_parent=KEY_CONFIG_ITEM_OPEN_PORTS,
        ),
        value=ValueRule(
            depends_on=[
                KEY_CONFIG_ITEM_OPEN_PORTS,
                KEY_CONFIG_ITEM_DOCKER_ORCHESTRATION_MODE,
            ],
            condition=lambda expose_selection, orch_mode: (
                (orch_mode == OrchestrationFramework.KUBERNETES)
                or expose_selection in (OpenPortsChoices.YES.value, OpenPortsChoices.NO.value)
            ),
            default_value=lambda expose_selection, orch_mode: (
                SYSLOG_DEFAULT_PORT
                if (orch_mode == OrchestrationFramework.KUBERNETES)
                else {
                    # they only get this if they do "customize", it's not on by default even with KEY_CONFIG_ITEM_OPEN_PORTS="Yes""
                    OpenPortsChoices.YES.value: 0,
                    OpenPortsChoices.NO.value: 0,
                }.get(expose_selection, DEFAULT_VALUE_UNCHANGED)
            ),
            only_if_unmodified=False,
        ),
    ),
    KEY_CONFIG_ITEM_FILEBEAT_TCP_DEFAULTS: DependencySpec(
        visibility=VisibilityRule(
            depends_on=KEY_CONFIG_ITEM_EXPOSE_FILEBEAT_TCP,
            condition=lambda enabled: bool(enabled),
            ui_parent=KEY_CONFIG_ITEM_EXPOSE_FILEBEAT_TCP,
        )
    ),
    KEY_CONFIG_ITEM_FILEBEAT_TCP_LOG_FORMAT: DependencySpec(
        visibility=VisibilityRule(
            depends_on=[KEY_CONFIG_ITEM_EXPOSE_FILEBEAT_TCP, KEY_CONFIG_ITEM_FILEBEAT_TCP_DEFAULTS],
            condition=lambda exposed, defaults: bool(exposed) and not bool(defaults),
            ui_parent=KEY_CONFIG_ITEM_EXPOSE_FILEBEAT_TCP,
        )
    ),
    KEY_CONFIG_ITEM_FILEBEAT_TCP_PARSE_SOURCE_FIELD: DependencySpec(
        visibility=VisibilityRule(
            depends_on=KEY_CONFIG_ITEM_FILEBEAT_TCP_LOG_FORMAT,
            condition=lambda format: format == FilebeatLogFormat.JSON.value,
            ui_parent=KEY_CONFIG_ITEM_FILEBEAT_TCP_LOG_FORMAT,
        ),
        value=ValueRule(
            depends_on=KEY_CONFIG_ITEM_FILEBEAT_TCP_LOG_FORMAT,
            condition=lambda format: format == FilebeatLogFormat.JSON.value,
            default_value=FilebeatFieldNames.MESSAGE.value,
        ),
    ),
    KEY_CONFIG_ITEM_FILEBEAT_TCP_PARSE_TARGET_FIELD: DependencySpec(
        visibility=VisibilityRule(
            depends_on=KEY_CONFIG_ITEM_FILEBEAT_TCP_LOG_FORMAT,
            condition=lambda format: format == FilebeatLogFormat.JSON.value,
            ui_parent=KEY_CONFIG_ITEM_FILEBEAT_TCP_LOG_FORMAT,
        ),
        value=ValueRule(
            depends_on=KEY_CONFIG_ITEM_FILEBEAT_TCP_LOG_FORMAT,
            condition=lambda format: format == FilebeatLogFormat.JSON.value,
            default_value=FilebeatFieldNames.MISCBEAT.value,
        ),
    ),
    KEY_CONFIG_ITEM_FILEBEAT_TCP_PARSE_DROP_FIELD: DependencySpec(
        visibility=VisibilityRule(
            depends_on=KEY_CONFIG_ITEM_FILEBEAT_TCP_LOG_FORMAT,
            condition=lambda format: format == FilebeatLogFormat.JSON.value,
            ui_parent=KEY_CONFIG_ITEM_FILEBEAT_TCP_LOG_FORMAT,
        ),
        value=ValueRule(
            depends_on=KEY_CONFIG_ITEM_FILEBEAT_TCP_LOG_FORMAT,
            condition=lambda format: format == FilebeatLogFormat.JSON.value,
            default_value=FilebeatFieldNames.MESSAGE.value,
        ),
    ),
    KEY_CONFIG_ITEM_FILEBEAT_TCP_TAG: DependencySpec(
        visibility=VisibilityRule(
            depends_on=[KEY_CONFIG_ITEM_EXPOSE_FILEBEAT_TCP, KEY_CONFIG_ITEM_FILEBEAT_TCP_DEFAULTS],
            condition=lambda exposed, defaults: bool(exposed) and not bool(defaults),
            ui_parent=KEY_CONFIG_ITEM_EXPOSE_FILEBEAT_TCP,
        )
    ),
    # -------------------------------------------------------------------------
    # ARTIFACT CLEANUP DEPENDENCIES
    # -------------------------------------------------------------------------
    KEY_CONFIG_ITEM_ARKIME_MANAGE_PCAP: DependencySpec(
        visibility=VisibilityRule(
            depends_on=KEY_CONFIG_ITEM_CLEAN_UP_OLD_ARTIFACTS,
            condition=lambda cleanup: bool(cleanup),
            ui_parent=KEY_CONFIG_ITEM_CLEAN_UP_OLD_ARTIFACTS,
        ),
        value=ValueRule(
            depends_on=KEY_CONFIG_ITEM_CLEAN_UP_OLD_ARTIFACTS,
            condition=True,
            default_value=lambda cleanup: bool(cleanup),
            only_if_unmodified=False,
        ),
    ),
    KEY_CONFIG_ITEM_ARKIME_FREESPACEG: DependencySpec(
        visibility=VisibilityRule(
            depends_on=KEY_CONFIG_ITEM_ARKIME_MANAGE_PCAP,
            condition=lambda enabled: bool(enabled),
            ui_parent=KEY_CONFIG_ITEM_ARKIME_MANAGE_PCAP,
        )
    ),
    KEY_CONFIG_ITEM_CLEAN_UP_OLD_INDICES: DependencySpec(
        visibility=VisibilityRule(
            depends_on=[
                KEY_CONFIG_ITEM_MALCOLM_PROFILE,
                KEY_CONFIG_ITEM_CLEAN_UP_OLD_ARTIFACTS,
            ],
            condition=lambda profile, cleanup: (profile == PROFILE_MALCOLM) and bool(cleanup),
            ui_parent=KEY_CONFIG_ITEM_CLEAN_UP_OLD_ARTIFACTS,
        ),
        value=ValueRule(
            depends_on=KEY_CONFIG_ITEM_CLEAN_UP_OLD_ARTIFACTS,
            condition=True,
            default_value=lambda cleanup: bool(cleanup),
            only_if_unmodified=False,
        ),
    ),
    KEY_CONFIG_ITEM_INDEX_PRUNE_THRESHOLD: DependencySpec(
        visibility=VisibilityRule(
            depends_on=KEY_CONFIG_ITEM_CLEAN_UP_OLD_INDICES,
            condition=lambda cleanup: bool(cleanup),
            ui_parent=KEY_CONFIG_ITEM_CLEAN_UP_OLD_INDICES,
        ),
        value=ValueRule(
            depends_on=KEY_CONFIG_ITEM_CLEAN_UP_OLD_INDICES,
            condition=lambda cleanup: not bool(cleanup),
            default_value="",
            only_if_unmodified=False,
        ),
    ),
    KEY_CONFIG_ITEM_INDEX_PRUNE_NAME_SORT: DependencySpec(
        visibility=VisibilityRule(
            depends_on=KEY_CONFIG_ITEM_CLEAN_UP_OLD_INDICES,
            condition=lambda cleanup: bool(cleanup),
            ui_parent=KEY_CONFIG_ITEM_CLEAN_UP_OLD_INDICES,
        )
    ),
    KEY_CONFIG_ITEM_PRUNE_PCAP: DependencySpec(
        visibility=VisibilityRule(
            depends_on=KEY_CONFIG_ITEM_CLEAN_UP_OLD_ARTIFACTS,
            condition=lambda cleanup: SYSTEM_INFO["malcolm_iso_install"] and bool(cleanup),
            ui_parent=KEY_CONFIG_ITEM_CLEAN_UP_OLD_ARTIFACTS,
        ),
    ),
    KEY_CONFIG_ITEM_PRUNE_LOGS: DependencySpec(
        visibility=VisibilityRule(
            depends_on=KEY_CONFIG_ITEM_CLEAN_UP_OLD_ARTIFACTS,
            condition=lambda cleanup: SYSTEM_INFO["malcolm_iso_install"] and bool(cleanup),
            ui_parent=KEY_CONFIG_ITEM_CLEAN_UP_OLD_ARTIFACTS,
        ),
    ),
    # -------------------------------------------------------------------------
    # STORAGE LOCATION DEPENDENCIES
    # -------------------------------------------------------------------------
    KEY_CONFIG_ITEM_PCAP_DIR: DependencySpec(
        visibility=VisibilityRule(
            depends_on=KEY_CONFIG_ITEM_USE_DEFAULT_STORAGE_LOCATIONS,
            condition=lambda use_default: not use_default,
            ui_parent=KEY_CONFIG_ITEM_USE_DEFAULT_STORAGE_LOCATIONS,
        )
    ),
    KEY_CONFIG_ITEM_ZEEK_LOG_DIR: DependencySpec(
        visibility=VisibilityRule(
            depends_on=KEY_CONFIG_ITEM_USE_DEFAULT_STORAGE_LOCATIONS,
            condition=lambda use_default: not use_default,
            ui_parent=KEY_CONFIG_ITEM_USE_DEFAULT_STORAGE_LOCATIONS,
        )
    ),
    KEY_CONFIG_ITEM_SURICATA_LOG_DIR: DependencySpec(
        visibility=VisibilityRule(
            depends_on=KEY_CONFIG_ITEM_USE_DEFAULT_STORAGE_LOCATIONS,
            condition=lambda use_default: not use_default,
            ui_parent=KEY_CONFIG_ITEM_USE_DEFAULT_STORAGE_LOCATIONS,
        )
    ),
    # Index and snapshot directories are only relevant for Malcolm profile with local OpenSearch,
    # and shown when not using default storage locations
    KEY_CONFIG_ITEM_INDEX_DIR: DependencySpec(
        visibility=VisibilityRule(
            depends_on=[
                KEY_CONFIG_ITEM_USE_DEFAULT_STORAGE_LOCATIONS,
                KEY_CONFIG_ITEM_MALCOLM_PROFILE,
                KEY_CONFIG_ITEM_OPENSEARCH_PRIMARY_MODE,
            ],
            condition=lambda use_default, profile, mode: (not use_default)
            and (profile == PROFILE_MALCOLM)
            and (mode == SearchEngineMode.OPENSEARCH_LOCAL.value),
            ui_parent=KEY_CONFIG_ITEM_USE_DEFAULT_STORAGE_LOCATIONS,
        )
    ),
    KEY_CONFIG_ITEM_INDEX_SNAPSHOT_DIR: DependencySpec(
        visibility=VisibilityRule(
            depends_on=[
                KEY_CONFIG_ITEM_USE_DEFAULT_STORAGE_LOCATIONS,
                KEY_CONFIG_ITEM_MALCOLM_PROFILE,
                KEY_CONFIG_ITEM_OPENSEARCH_PRIMARY_MODE,
            ],
            condition=lambda use_default, profile, mode: (not use_default)
            and (profile == PROFILE_MALCOLM)
            and (mode == SearchEngineMode.OPENSEARCH_LOCAL.value),
            ui_parent=KEY_CONFIG_ITEM_USE_DEFAULT_STORAGE_LOCATIONS,
        )
    ),
    # -------------------------------------------------------------------------
    # ANALYSIS DEPENDENCIES
    # -------------------------------------------------------------------------
    KEY_CONFIG_ITEM_SURICATA_RULE_UPDATE: DependencySpec(
        visibility=VisibilityRule(
            depends_on=[KEY_CONFIG_ITEM_AUTO_SURICATA, KEY_CONFIG_ITEM_LIVE_SURICATA],
            condition=lambda auto, live: bool(auto) or bool(live),
            ui_parent=KEY_CONFIG_ITEM_AUTO_SURICATA,
        ),
        value=ValueRule(
            depends_on=[KEY_CONFIG_ITEM_AUTO_SURICATA, KEY_CONFIG_ITEM_LIVE_SURICATA],
            condition=True,
            default_value=False,
        ),
    ),
    KEY_CONFIG_ITEM_MALCOLM_ICS: DependencySpec(
        visibility=VisibilityRule(
            depends_on=[KEY_CONFIG_ITEM_AUTO_ZEEK, KEY_CONFIG_ITEM_LIVE_ZEEK],
            condition=lambda auto, live: bool(auto) or bool(live),
            ui_parent=KEY_CONFIG_ITEM_AUTO_ZEEK,
        )
    ),
    KEY_CONFIG_ITEM_ZEEK_ICS_BEST_GUESS: DependencySpec(
        visibility=VisibilityRule(
            depends_on=KEY_CONFIG_ITEM_MALCOLM_ICS,
            condition=lambda enabled: bool(enabled),
            ui_parent=KEY_CONFIG_ITEM_MALCOLM_ICS,
        )
    ),
    # -------------------------------------------------------------------------
    # ZEEK INTELLIGENCE DEPENDENCIES
    # -------------------------------------------------------------------------
    KEY_CONFIG_ITEM_ZEEK_PULL_INTELLIGENCE_FEEDS: DependencySpec(
        visibility=VisibilityRule(
            depends_on=[KEY_CONFIG_ITEM_AUTO_ZEEK, KEY_CONFIG_ITEM_LIVE_ZEEK],
            condition=lambda auto, live: bool(auto) or bool(live),
            ui_parent=KEY_CONFIG_ITEM_AUTO_ZEEK,
        ),
        value=ValueRule(
            depends_on=[
                KEY_CONFIG_ITEM_ZEEK_INTEL_ON_STARTUP,
                KEY_CONFIG_ITEM_ZEEK_INTEL_CRON_EXPRESSION,
            ],
            condition=True,
            default_value=lambda on_startup, cron_exp: bool(on_startup) or bool(cron_exp),
        ),
    ),
    KEY_CONFIG_ITEM_ZEEK_INTEL_ON_STARTUP: DependencySpec(
        visibility=VisibilityRule(
            depends_on=KEY_CONFIG_ITEM_ZEEK_PULL_INTELLIGENCE_FEEDS,
            condition=lambda enabled: bool(enabled),
            ui_parent=KEY_CONFIG_ITEM_ZEEK_PULL_INTELLIGENCE_FEEDS,
        ),
        value=ValueRule(
            depends_on=KEY_CONFIG_ITEM_ZEEK_PULL_INTELLIGENCE_FEEDS,
            condition=True,
            default_value=lambda enabled: bool(enabled),
            only_if_unmodified=False,
        ),
    ),
    KEY_CONFIG_ITEM_ZEEK_INTEL_CRON_EXPRESSION: DependencySpec(
        visibility=VisibilityRule(
            depends_on=KEY_CONFIG_ITEM_ZEEK_PULL_INTELLIGENCE_FEEDS,
            condition=lambda enabled: bool(enabled),
            ui_parent=KEY_CONFIG_ITEM_ZEEK_PULL_INTELLIGENCE_FEEDS,
        ),
        value=ValueRule(
            depends_on=KEY_CONFIG_ITEM_ZEEK_PULL_INTELLIGENCE_FEEDS,
            condition=True,
            default_value=lambda enabled: "0 0 * * *" if bool(enabled) else "",
            only_if_unmodified=False,
        ),
    ),
    KEY_CONFIG_ITEM_ZEEK_INTEL_FEED_SINCE: DependencySpec(
        visibility=VisibilityRule(
            depends_on=KEY_CONFIG_ITEM_ZEEK_PULL_INTELLIGENCE_FEEDS,
            condition=lambda enabled: bool(enabled),
            ui_parent=KEY_CONFIG_ITEM_ZEEK_PULL_INTELLIGENCE_FEEDS,
        )
    ),
    KEY_CONFIG_ITEM_ZEEK_INTEL_ITEM_EXPIRATION: DependencySpec(
        visibility=VisibilityRule(
            depends_on=KEY_CONFIG_ITEM_ZEEK_PULL_INTELLIGENCE_FEEDS,
            condition=lambda enabled: bool(enabled),
            ui_parent=KEY_CONFIG_ITEM_ZEEK_PULL_INTELLIGENCE_FEEDS,
        )
    ),
}
