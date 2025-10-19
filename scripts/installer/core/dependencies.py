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
from scripts.malcolm_constants import PROFILE_HEDGEHOG, PROFILE_MALCOLM
from scripts.malcolm_constants import OrchestrationFramework
from scripts.installer.configs.constants.constants import (
    LOGSTASH_WORKERS_KUBERNETES,
    SYSLOG_DEFAULT_PORT,
)

from scripts.installer.configs.constants.enums import (
    DockerRestartPolicy,
    FilebeatLogFormat,
    FilebeatFieldNames,
    SearchEngineMode,
    NetboxMode,
    OpenPortsChoices,
)

from scripts.installer.configs.constants.configuration_item_keys import *


@dataclass
class VisibilityRule:
    """Defines when a configuration item should be visible in the UI."""

    depends_on: Union[str, List[str]]  # Key(s) this item depends on
    condition: Callable[..., bool]  # Function that determines visibility
    ui_parent: str = None  # Optional explicit UI parent override
    is_top_level: bool = False  # True if this is a top-level menu item


@dataclass
class ValueRule:
    """Defines automatic value setting based on other configuration items."""

    depends_on: Union[str, List[str]]  # Key(s) this value depends on
    condition: Callable[..., bool]  # When to apply the default value
    default_value: Any  # Value to set when condition is met
    only_if_unmodified: bool = True  # Only set if user hasn't manually changed it


@dataclass
class DependencySpec:
    """Complete dependency specification for a configuration item."""

    visibility: VisibilityRule = None
    value: ValueRule = None


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
    KEY_CONFIG_ITEM_MALCOLM_AUTO_RESTART: DependencySpec(
        visibility=VisibilityRule(
            depends_on=KEY_CONFIG_ITEM_DOCKER_ORCHESTRATION_MODE,
            condition=lambda orch: orch != OrchestrationFramework.KUBERNETES,
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
    # behind reverse proxy: forced true in kubernetes (no prompt); compose shows normally
    KEY_CONFIG_ITEM_BEHIND_REVERSE_PROXY: DependencySpec(
        visibility=VisibilityRule(
            depends_on=[
                KEY_CONFIG_ITEM_MALCOLM_PROFILE,
                KEY_CONFIG_ITEM_DOCKER_ORCHESTRATION_MODE,
            ],
            condition=lambda profile, orch: (
                profile == PROFILE_MALCOLM and orch == OrchestrationFramework.DOCKER_COMPOSE
            ),
            is_top_level=True,
        ),
        value=ValueRule(
            depends_on=KEY_CONFIG_ITEM_DOCKER_ORCHESTRATION_MODE,
            condition=lambda orch: orch == OrchestrationFramework.KUBERNETES,
            default_value=True,
            only_if_unmodified=True,
        ),
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
        )
    ),
    KEY_CONFIG_ITEM_NETBOX_MODE: DependencySpec(
        visibility=VisibilityRule(
            depends_on=KEY_CONFIG_ITEM_MALCOLM_PROFILE,
            condition=lambda profile: profile == PROFILE_MALCOLM,
            is_top_level=True,
        )
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
            depends_on=KEY_CONFIG_ITEM_MALCOLM_PROFILE,
            condition=lambda profile: profile == PROFILE_MALCOLM,
            is_top_level=True,
        )
    ),
    # Hedgehog profile top-level items
    KEY_CONFIG_ITEM_LOGSTASH_HOST: DependencySpec(
        visibility=VisibilityRule(
            depends_on=KEY_CONFIG_ITEM_MALCOLM_PROFILE,
            condition=lambda profile: profile == PROFILE_HEDGEHOG,
            is_top_level=True,
        )
    ),
    # Traefik configuration: shown when reverse proxy is enabled
    KEY_CONFIG_ITEM_TRAEFIK_LABELS: DependencySpec(
        visibility=VisibilityRule(
            depends_on=KEY_CONFIG_ITEM_BEHIND_REVERSE_PROXY,
            condition=lambda behind: bool(behind),
            ui_parent=KEY_CONFIG_ITEM_BEHIND_REVERSE_PROXY,
        )
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
            condition=lambda labels, mode: bool(labels) and mode == SearchEngineMode.OPENSEARCH_LOCAL.value,
            ui_parent=KEY_CONFIG_ITEM_TRAEFIK_LABELS,
        )
    ),
    # Malcolm profile children
    KEY_CONFIG_ITEM_OPENSEARCH_PRIMARY_MODE: DependencySpec(
        visibility=VisibilityRule(
            depends_on=KEY_CONFIG_ITEM_MALCOLM_PROFILE,
            condition=lambda profile: profile == PROFILE_MALCOLM,
            ui_parent=KEY_CONFIG_ITEM_MALCOLM_PROFILE,
        ),
        # Keep primary mode in sync with the maintain flag when user hasn't explicitly set it.
        # True  -> opensearch-local
        # False -> opensearch-remote
        value=ValueRule(
            depends_on=KEY_CONFIG_ITEM_MALCOLM_MAINTAIN_OPENSEARCH,
            condition=lambda maintain: isinstance(maintain, bool),
            default_value=lambda maintain: (
                SearchEngineMode.OPENSEARCH_LOCAL.value if bool(maintain) else SearchEngineMode.OPENSEARCH_REMOTE.value
            ),
            only_if_unmodified=False,
        ),
    ),
    KEY_CONFIG_ITEM_MALCOLM_MAINTAIN_OPENSEARCH: DependencySpec(
        visibility=VisibilityRule(
            depends_on=KEY_CONFIG_ITEM_MALCOLM_PROFILE,
            condition=lambda profile: profile == PROFILE_MALCOLM,
            ui_parent=KEY_CONFIG_ITEM_MALCOLM_PROFILE,
        ),
        # Keep this checkbox in sync with the selected primary store: local -> True, remote -> False
        value=ValueRule(
            depends_on=KEY_CONFIG_ITEM_OPENSEARCH_PRIMARY_MODE,
            condition=lambda mode: isinstance(mode, str) and mode != "",
            default_value=lambda mode: mode == SearchEngineMode.OPENSEARCH_LOCAL.value,
            only_if_unmodified=False,
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
        )
    ),
    KEY_CONFIG_ITEM_LS_WORKERS: DependencySpec(
        visibility=VisibilityRule(
            depends_on=KEY_CONFIG_ITEM_MALCOLM_PROFILE,
            condition=lambda profile: profile == PROFILE_MALCOLM,
            ui_parent=KEY_CONFIG_ITEM_MALCOLM_PROFILE,
        ),
        value=ValueRule(
            depends_on=KEY_CONFIG_ITEM_DOCKER_ORCHESTRATION_MODE,
            condition=lambda orch_mode: orch_mode != OrchestrationFramework.DOCKER_COMPOSE,
            default_value=LOGSTASH_WORKERS_KUBERNETES,
        ),
    ),
    # Profile-dependent nested items
    # restart policy only applicable under compose and when auto-restart is enabled
    KEY_CONFIG_ITEM_MALCOLM_RESTART_POLICY: DependencySpec(
        visibility=VisibilityRule(
            depends_on=[
                KEY_CONFIG_ITEM_MALCOLM_AUTO_RESTART,
                KEY_CONFIG_ITEM_DOCKER_ORCHESTRATION_MODE,
            ],
            condition=lambda enabled, orch: bool(enabled) and orch == OrchestrationFramework.DOCKER_COMPOSE,
            ui_parent=KEY_CONFIG_ITEM_MALCOLM_AUTO_RESTART,
        ),
        value=ValueRule(
            depends_on=KEY_CONFIG_ITEM_MALCOLM_AUTO_RESTART,
            condition=lambda enabled: bool(enabled),
            default_value=DockerRestartPolicy.UNLESS_STOPPED.value,
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
            is_top_level=True,
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
            is_top_level=True,
        )
    ),
    KEY_CONFIG_ITEM_OS_MEMORY: DependencySpec(
        visibility=VisibilityRule(
            depends_on=[
                KEY_CONFIG_ITEM_MALCOLM_PROFILE,
                KEY_CONFIG_ITEM_MALCOLM_MAINTAIN_OPENSEARCH,
            ],
            condition=lambda profile, maintain: profile == PROFILE_MALCOLM and bool(maintain),
            ui_parent=KEY_CONFIG_ITEM_MALCOLM_PROFILE,
        )
    ),
    KEY_CONFIG_ITEM_OPENSEARCH_PRIMARY_URL: DependencySpec(
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
            depends_on=KEY_CONFIG_ITEM_OPENSEARCH_PRIMARY_MODE,
            condition=lambda mode: mode == SearchEngineMode.ELASTICSEARCH_REMOTE.value,
            ui_parent=KEY_CONFIG_ITEM_OPENSEARCH_PRIMARY_MODE,
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
    # NETWORK AND SYSLOG DEPENDENCIES
    # -------------------------------------------------------------------------
    KEY_CONFIG_ITEM_SYSLOG_TCP_PORT: DependencySpec(
        visibility=VisibilityRule(
            depends_on=KEY_CONFIG_ITEM_ACCEPT_STANDARD_SYSLOG_MESSAGES,
            condition=lambda enabled: bool(enabled),
            ui_parent=KEY_CONFIG_ITEM_ACCEPT_STANDARD_SYSLOG_MESSAGES,
        ),
        value=ValueRule(
            depends_on=KEY_CONFIG_ITEM_ACCEPT_STANDARD_SYSLOG_MESSAGES,
            condition=lambda enabled: bool(enabled),
            default_value=SYSLOG_DEFAULT_PORT,
        ),
    ),
    KEY_CONFIG_ITEM_SYSLOG_UDP_PORT: DependencySpec(
        visibility=VisibilityRule(
            depends_on=KEY_CONFIG_ITEM_ACCEPT_STANDARD_SYSLOG_MESSAGES,
            condition=lambda enabled: bool(enabled),
            ui_parent=KEY_CONFIG_ITEM_ACCEPT_STANDARD_SYSLOG_MESSAGES,
        ),
        value=ValueRule(
            depends_on=KEY_CONFIG_ITEM_ACCEPT_STANDARD_SYSLOG_MESSAGES,
            condition=lambda enabled: bool(enabled),
            default_value=SYSLOG_DEFAULT_PORT,
        ),
    ),
    # Dark mode depends on profile and primary store mode
    KEY_CONFIG_ITEM_DASHBOARDS_DARK_MODE: DependencySpec(
        visibility=VisibilityRule(
            depends_on=[
                KEY_CONFIG_ITEM_MALCOLM_PROFILE,
                KEY_CONFIG_ITEM_OPENSEARCH_PRIMARY_MODE,
            ],
            condition=lambda profile, mode: (
                profile == PROFILE_MALCOLM and mode != SearchEngineMode.ELASTICSEARCH_REMOTE.value
            ),
            is_top_level=True,
        )
    ),
    # -------------------------------------------------------------------------
    # LIVE CAPTURE DEPENDENCIES
    # -------------------------------------------------------------------------
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
            condition=lambda live_traffic, profile, mode, tcpdump, arkime: True,
            default_value=lambda live_traffic, profile, mode, tcpdump, arkime: (
                bool(live_traffic)
                and (profile == PROFILE_MALCOLM)
                and (mode == SearchEngineMode.OPENSEARCH_LOCAL.value)
                and (not bool(tcpdump))
                and (not bool(arkime))
            ),
            only_if_unmodified=True,
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
                KEY_CONFIG_ITEM_PCAP_NETSNIFF,
                KEY_CONFIG_ITEM_LIVE_ARKIME,
            ],
            condition=lambda live_traffic, netsniff, arkime: (not bool(live_traffic)) or bool(netsniff) or bool(arkime),
            default_value=False,
            only_if_unmodified=True,
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
            condition=lambda live_traffic, profile, mode, netsniff, tcpdump: True,
            default_value=lambda live_traffic, profile, mode, netsniff, tcpdump: (
                bool(live_traffic)
                and ((profile == PROFILE_HEDGEHOG) or (mode != SearchEngineMode.OPENSEARCH_LOCAL.value))
                and (not bool(netsniff))
                and (not bool(tcpdump))
            ),
            only_if_unmodified=True,
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
            condition=lambda enabled: bool(enabled),
            default_value=True,
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
            condition=lambda enabled: bool(enabled),
            default_value=True,
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
            condition=lambda enabled: bool(enabled),
            default_value=True,
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
    # -------------------------------------------------------------------------
    # NETBOX DEPENDENCIES
    # -------------------------------------------------------------------------
    KEY_CONFIG_ITEM_NETBOX_URL: DependencySpec(
        visibility=VisibilityRule(
            depends_on=KEY_CONFIG_ITEM_NETBOX_MODE,
            condition=lambda mode: mode == NetboxMode.REMOTE.value,
            ui_parent=KEY_CONFIG_ITEM_NETBOX_MODE,
        )
    ),
    KEY_CONFIG_ITEM_NETBOX_LOGSTASH_ENRICH: DependencySpec(
        visibility=VisibilityRule(
            depends_on=KEY_CONFIG_ITEM_NETBOX_MODE,
            condition=lambda mode: mode != NetboxMode.DISABLED.value,
            ui_parent=KEY_CONFIG_ITEM_NETBOX_MODE,
        )
    ),
    KEY_CONFIG_ITEM_NETBOX_AUTO_POPULATE: DependencySpec(
        visibility=VisibilityRule(
            depends_on=KEY_CONFIG_ITEM_NETBOX_MODE,
            condition=lambda mode: mode != NetboxMode.DISABLED.value,
            ui_parent=KEY_CONFIG_ITEM_NETBOX_MODE,
        )
    ),
    KEY_CONFIG_ITEM_NETBOX_LOGSTASH_AUTO_SUBNETS: DependencySpec(
        visibility=VisibilityRule(
            depends_on=KEY_CONFIG_ITEM_NETBOX_MODE,
            condition=lambda mode: mode != NetboxMode.DISABLED.value,
            ui_parent=KEY_CONFIG_ITEM_NETBOX_MODE,
        )
    ),
    KEY_CONFIG_ITEM_NETBOX_SITE_NAME: DependencySpec(
        visibility=VisibilityRule(
            depends_on=KEY_CONFIG_ITEM_NETBOX_MODE,
            condition=lambda mode: mode != NetboxMode.DISABLED.value,
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
        )
    ),
    KEY_CONFIG_ITEM_FILE_CARVE_MODE: DependencySpec(
        visibility=VisibilityRule(
            depends_on=KEY_CONFIG_ITEM_FILE_CARVE_ENABLED,
            condition=lambda enabled: bool(enabled),
            ui_parent=KEY_CONFIG_ITEM_FILE_CARVE_ENABLED,
        )
    ),
    KEY_CONFIG_ITEM_FILE_PRESERVE_MODE: DependencySpec(
        visibility=VisibilityRule(
            depends_on=KEY_CONFIG_ITEM_FILE_CARVE_MODE,
            condition=lambda mode: mode != "none",
            ui_parent=KEY_CONFIG_ITEM_FILE_CARVE_MODE,
        )
    ),
    KEY_CONFIG_ITEM_EXTRACTED_FILE_MAX_SIZE_THRESHOLD: DependencySpec(
        visibility=VisibilityRule(
            depends_on=KEY_CONFIG_ITEM_FILE_CARVE_MODE,
            condition=lambda mode: mode != "none",
            ui_parent=KEY_CONFIG_ITEM_FILE_CARVE_MODE,
        )
    ),
    KEY_CONFIG_ITEM_EXTRACTED_FILE_MAX_PERCENT_THRESHOLD: DependencySpec(
        visibility=VisibilityRule(
            depends_on=KEY_CONFIG_ITEM_FILE_CARVE_MODE,
            condition=lambda mode: mode != "none",
            ui_parent=KEY_CONFIG_ITEM_FILE_CARVE_MODE,
        )
    ),
    KEY_CONFIG_ITEM_FILE_CARVE_HTTP_SERVER: DependencySpec(
        visibility=VisibilityRule(
            depends_on=KEY_CONFIG_ITEM_FILE_CARVE_MODE,
            condition=lambda mode: mode != "none",
            ui_parent=KEY_CONFIG_ITEM_FILE_CARVE_MODE,
        )
    ),
    KEY_CONFIG_ITEM_FILE_CARVE_HTTP_SERVER_ZIP: DependencySpec(
        visibility=VisibilityRule(
            depends_on=KEY_CONFIG_ITEM_FILE_CARVE_HTTP_SERVER,
            condition=lambda mode: mode != "none",
            ui_parent=KEY_CONFIG_ITEM_FILE_CARVE_HTTP_SERVER,
        )
    ),
    KEY_CONFIG_ITEM_FILE_CARVE_HTTP_SERVE_ENCRYPT_KEY: DependencySpec(
        visibility=VisibilityRule(
            depends_on=KEY_CONFIG_ITEM_FILE_CARVE_HTTP_SERVER,
            condition=lambda mode: mode != "none",
            ui_parent=KEY_CONFIG_ITEM_FILE_CARVE_HTTP_SERVER,
        )
    ),
    KEY_CONFIG_ITEM_CAPA_SCAN: DependencySpec(
        visibility=VisibilityRule(
            depends_on=KEY_CONFIG_ITEM_FILE_CARVE_MODE,
            condition=lambda mode: mode != "none",
            ui_parent=KEY_CONFIG_ITEM_FILE_CARVE_MODE,
        )
    ),
    KEY_CONFIG_ITEM_CLAM_AV_SCAN: DependencySpec(
        visibility=VisibilityRule(
            depends_on=KEY_CONFIG_ITEM_FILE_CARVE_MODE,
            condition=lambda mode: mode != "none",
            ui_parent=KEY_CONFIG_ITEM_FILE_CARVE_MODE,
        )
    ),
    KEY_CONFIG_ITEM_YARA_SCAN: DependencySpec(
        visibility=VisibilityRule(
            depends_on=KEY_CONFIG_ITEM_FILE_CARVE_MODE,
            condition=lambda mode: mode != "none",
            ui_parent=KEY_CONFIG_ITEM_FILE_CARVE_MODE,
        )
    ),
    KEY_CONFIG_ITEM_VTOT_API_KEY: DependencySpec(
        visibility=VisibilityRule(
            depends_on=KEY_CONFIG_ITEM_FILE_CARVE_MODE,
            condition=lambda mode: mode != "none",
            ui_parent=KEY_CONFIG_ITEM_FILE_CARVE_MODE,
        )
    ),
    KEY_CONFIG_ITEM_FILE_SCAN_RULE_UPDATE: DependencySpec(
        visibility=VisibilityRule(
            depends_on=KEY_CONFIG_ITEM_FILE_CARVE_MODE,
            condition=lambda mode: mode != "none",
            ui_parent=KEY_CONFIG_ITEM_FILE_CARVE_MODE,
        ),
        value=ValueRule(
            depends_on=KEY_CONFIG_ITEM_FILE_CARVE_MODE,
            condition=lambda mode: mode != "none",
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
            ],
            condition=lambda ports, mode: (
                ports == OpenPortsChoices.CUSTOMIZE.value and mode == SearchEngineMode.OPENSEARCH_LOCAL.value
            ),
            ui_parent=KEY_CONFIG_ITEM_OPEN_PORTS,
        ),
        value=ValueRule(
            depends_on=[
                KEY_CONFIG_ITEM_OPEN_PORTS,
                KEY_CONFIG_ITEM_OPENSEARCH_PRIMARY_MODE,
            ],
            condition=lambda ports, mode: (
                ports == OpenPortsChoices.YES.value and mode == SearchEngineMode.OPENSEARCH_LOCAL.value
            ),
            default_value=True,
        ),
    ),
    KEY_CONFIG_ITEM_EXPOSE_LOGSTASH: DependencySpec(
        visibility=VisibilityRule(
            depends_on=KEY_CONFIG_ITEM_OPEN_PORTS,
            condition=lambda selection: selection == OpenPortsChoices.CUSTOMIZE.value,
            ui_parent=KEY_CONFIG_ITEM_OPEN_PORTS,
        ),
        value=ValueRule(
            depends_on=KEY_CONFIG_ITEM_OPEN_PORTS,
            condition=lambda selection: selection == OpenPortsChoices.YES.value,
            default_value=True,
        ),
    ),
    KEY_CONFIG_ITEM_EXPOSE_FILEBEAT_TCP: DependencySpec(
        visibility=VisibilityRule(
            depends_on=KEY_CONFIG_ITEM_OPEN_PORTS,
            condition=lambda selection: selection == OpenPortsChoices.CUSTOMIZE.value,
            ui_parent=KEY_CONFIG_ITEM_OPEN_PORTS,
        ),
        value=ValueRule(
            depends_on=KEY_CONFIG_ITEM_OPEN_PORTS,
            condition=lambda selection: selection == OpenPortsChoices.YES.value,
            default_value=True,
        ),
    ),
    KEY_CONFIG_ITEM_EXPOSE_SFTP: DependencySpec(
        visibility=VisibilityRule(
            depends_on=KEY_CONFIG_ITEM_OPEN_PORTS,
            condition=lambda selection: selection == OpenPortsChoices.CUSTOMIZE.value,
            ui_parent=KEY_CONFIG_ITEM_OPEN_PORTS,
        ),
        value=ValueRule(
            depends_on=KEY_CONFIG_ITEM_OPEN_PORTS,
            condition=lambda selection: selection == OpenPortsChoices.YES.value,
            default_value=True,
        ),
    ),
    KEY_CONFIG_ITEM_ACCEPT_STANDARD_SYSLOG_MESSAGES: DependencySpec(
        visibility=VisibilityRule(
            depends_on=KEY_CONFIG_ITEM_OPEN_PORTS,
            condition=lambda selection: selection == OpenPortsChoices.CUSTOMIZE.value,
            ui_parent=KEY_CONFIG_ITEM_OPEN_PORTS,
        ),
        value=ValueRule(
            depends_on=KEY_CONFIG_ITEM_OPEN_PORTS,
            condition=lambda selection: selection == OpenPortsChoices.YES.value,
            default_value=True,
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
            depends_on=[
                KEY_CONFIG_ITEM_CLEAN_UP_OLD_ARTIFACTS,
                KEY_CONFIG_ITEM_AUTO_ARKIME,
            ],
            condition=lambda cleanup, auto_arkime: bool(cleanup) and bool(auto_arkime),
            ui_parent=KEY_CONFIG_ITEM_CLEAN_UP_OLD_ARTIFACTS,
        )
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
            depends_on=KEY_CONFIG_ITEM_CLEAN_UP_OLD_ARTIFACTS,
            condition=lambda enabled: bool(enabled),
            ui_parent=KEY_CONFIG_ITEM_CLEAN_UP_OLD_ARTIFACTS,
        )
    ),
    KEY_CONFIG_ITEM_INDEX_PRUNE_SIZE_LIMIT: DependencySpec(
        visibility=VisibilityRule(
            depends_on=KEY_CONFIG_ITEM_CLEAN_UP_OLD_INDICES,
            condition=lambda enabled: bool(enabled),
            ui_parent=KEY_CONFIG_ITEM_CLEAN_UP_OLD_INDICES,
        )
    ),
    KEY_CONFIG_ITEM_INDEX_PRUNE_NAME_SORT: DependencySpec(
        visibility=VisibilityRule(
            depends_on=KEY_CONFIG_ITEM_CLEAN_UP_OLD_INDICES,
            condition=lambda enabled: bool(enabled),
            ui_parent=KEY_CONFIG_ITEM_CLEAN_UP_OLD_INDICES,
        )
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
            condition=lambda auto, live: bool(auto) or bool(live),
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
            depends_on=[KEY_CONFIG_ITEM_AUTO_ZEEK, KEY_CONFIG_ITEM_LIVE_ZEEK],
            condition=lambda auto, live: bool(auto) or bool(live),
            default_value=False,
        ),
    ),
    KEY_CONFIG_ITEM_ZEEK_INTEL_ON_STARTUP: DependencySpec(
        visibility=VisibilityRule(
            depends_on=KEY_CONFIG_ITEM_ZEEK_PULL_INTELLIGENCE_FEEDS,
            condition=lambda enabled: bool(enabled),
            ui_parent=KEY_CONFIG_ITEM_ZEEK_PULL_INTELLIGENCE_FEEDS,
        )
    ),
    KEY_CONFIG_ITEM_ZEEK_INTEL_CRON_EXPRESSION: DependencySpec(
        visibility=VisibilityRule(
            depends_on=KEY_CONFIG_ITEM_ZEEK_PULL_INTELLIGENCE_FEEDS,
            condition=lambda enabled: bool(enabled),
            ui_parent=KEY_CONFIG_ITEM_ZEEK_PULL_INTELLIGENCE_FEEDS,
        )
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
