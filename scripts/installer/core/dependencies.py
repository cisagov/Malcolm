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
    SYSLOG_DEFAULT_PORT,
    LOGSTASH_WORKERS_DOCKER_COMPOSE,
    LOGSTASH_WORKERS_KUBERNETES,
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
    KEY_CONFIG_ITEM_DOCKER_EXTRA_USERS: DependencySpec(
        visibility=VisibilityRule(
            depends_on=KEY_CONFIG_ITEM_RUNTIME_BIN,
            condition=lambda runtime: runtime == "docker",
        )
    ),
    # Malcolm profile top-level items
    KEY_CONFIG_ITEM_MALCOLM_AUTO_RESTART: DependencySpec(
        visibility=VisibilityRule(
            depends_on=[
                KEY_CONFIG_ITEM_MALCOLM_PROFILE,
                KEY_CONFIG_ITEM_DOCKER_ORCHESTRATION_MODE,
            ],
            condition=lambda profile, orch: (
                profile == PROFILE_MALCOLM
                and orch == OrchestrationFramework.DOCKER_COMPOSE
            ),
            is_top_level=True,
        )
    ),
    KEY_CONFIG_ITEM_NGINX_SSL: DependencySpec(
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
                profile == PROFILE_MALCOLM
                and orch == OrchestrationFramework.DOCKER_COMPOSE
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
    KEY_CONFIG_ITEM_CLEAN_UP_OLD_INDICES: DependencySpec(
        visibility=VisibilityRule(
            depends_on=KEY_CONFIG_ITEM_MALCOLM_PROFILE,
            condition=lambda profile: profile == PROFILE_MALCOLM,
            is_top_level=True,
        )
    ),
    KEY_CONFIG_ITEM_FILE_CARVE_ENABLED: DependencySpec(
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
                SearchEngineMode.OPENSEARCH_LOCAL.value
                if bool(maintain)
                else SearchEngineMode.OPENSEARCH_REMOTE.value
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
            condition=lambda orch_mode: orch_mode
            != OrchestrationFramework.DOCKER_COMPOSE,
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
            condition=lambda enabled, orch: bool(enabled)
            and orch == OrchestrationFramework.DOCKER_COMPOSE,
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
            condition=lambda profile, maintain: profile == PROFILE_MALCOLM
            and bool(maintain),
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
                profile == PROFILE_MALCOLM
                and mode != SearchEngineMode.ELASTICSEARCH_REMOTE.value
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
    KEY_CONFIG_ITEM_PCAP_NET_SNIFF: DependencySpec(
        visibility=VisibilityRule(
            depends_on=KEY_CONFIG_ITEM_CAPTURE_LIVE_NETWORK_TRAFFIC,
            condition=lambda enabled: bool(enabled),
            ui_parent=KEY_CONFIG_ITEM_CAPTURE_LIVE_NETWORK_TRAFFIC,
        )
    ),
    KEY_CONFIG_ITEM_PCAP_TCP_DUMP: DependencySpec(
        visibility=VisibilityRule(
            depends_on=KEY_CONFIG_ITEM_CAPTURE_LIVE_NETWORK_TRAFFIC,
            condition=lambda enabled: bool(enabled),
            ui_parent=KEY_CONFIG_ITEM_CAPTURE_LIVE_NETWORK_TRAFFIC,
        )
    ),
    KEY_CONFIG_ITEM_LIVE_ARKIME: DependencySpec(
        visibility=VisibilityRule(
            depends_on=KEY_CONFIG_ITEM_CAPTURE_LIVE_NETWORK_TRAFFIC,
            condition=lambda enabled: bool(enabled),
            ui_parent=KEY_CONFIG_ITEM_CAPTURE_LIVE_NETWORK_TRAFFIC,
        )
    ),
    KEY_CONFIG_ITEM_LIVE_ZEEK: DependencySpec(
        visibility=VisibilityRule(
            depends_on=KEY_CONFIG_ITEM_CAPTURE_LIVE_NETWORK_TRAFFIC,
            condition=lambda enabled: bool(enabled),
            ui_parent=KEY_CONFIG_ITEM_CAPTURE_LIVE_NETWORK_TRAFFIC,
        )
    ),
    KEY_CONFIG_ITEM_LIVE_SURICATA: DependencySpec(
        visibility=VisibilityRule(
            depends_on=KEY_CONFIG_ITEM_CAPTURE_LIVE_NETWORK_TRAFFIC,
            condition=lambda enabled: bool(enabled),
            ui_parent=KEY_CONFIG_ITEM_CAPTURE_LIVE_NETWORK_TRAFFIC,
        )
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
        )
    ),
    KEY_CONFIG_ITEM_CAPTURE_STATS: DependencySpec(
        visibility=VisibilityRule(
            depends_on=KEY_CONFIG_ITEM_CAPTURE_LIVE_NETWORK_TRAFFIC,
            condition=lambda enabled: bool(enabled),
            ui_parent=KEY_CONFIG_ITEM_CAPTURE_LIVE_NETWORK_TRAFFIC,
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
            depends_on=KEY_CONFIG_ITEM_NETBOX_LOGSTASH_ENRICH,
            condition=lambda enabled: bool(enabled),
            ui_parent=KEY_CONFIG_ITEM_NETBOX_LOGSTASH_ENRICH,
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
    # -------------------------------------------------------------------------
    # OPEN PORTS DEPENDENCIES
    # -------------------------------------------------------------------------
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
}


# =============================================================================
# COMPLEX MULTI-DEPENDENCY RULES
# =============================================================================

# Some dependencies are too complex for the simple declarative format above.
# These are defined as functions that return dependency specifications.


def get_complex_dependencies() -> Dict[str, DependencySpec]:
    """Return complex dependency rules that require custom logic."""

    complex_deps = {}

    # OpenSearch exposure (depends on both open ports and primary mode)
    complex_deps[KEY_CONFIG_ITEM_EXPOSE_OPENSEARCH] = DependencySpec(
        visibility=VisibilityRule(
            depends_on=[
                KEY_CONFIG_ITEM_OPEN_PORTS,
                KEY_CONFIG_ITEM_OPENSEARCH_PRIMARY_MODE,
            ],
            condition=lambda ports, mode: (
                ports == OpenPortsChoices.CUSTOMIZE.value
                and mode == SearchEngineMode.OPENSEARCH_LOCAL.value
            ),
            ui_parent=KEY_CONFIG_ITEM_OPEN_PORTS,
        ),
        value=ValueRule(
            depends_on=[
                KEY_CONFIG_ITEM_OPEN_PORTS,
                KEY_CONFIG_ITEM_OPENSEARCH_PRIMARY_MODE,
            ],
            condition=lambda ports, mode: (
                ports == OpenPortsChoices.YES.value
                and mode == SearchEngineMode.OPENSEARCH_LOCAL.value
            ),
            default_value=True,
        ),
    )

    # Traefik OpenSearch host: only relevant when labels are enabled and primary store is local OpenSearch
    complex_deps[KEY_CONFIG_ITEM_TRAEFIK_OPENSEARCH_HOST] = DependencySpec(
        visibility=VisibilityRule(
            depends_on=[
                KEY_CONFIG_ITEM_TRAEFIK_LABELS,
                KEY_CONFIG_ITEM_OPENSEARCH_PRIMARY_MODE,
            ],
            condition=lambda labels, mode: bool(labels)
            and mode == SearchEngineMode.OPENSEARCH_LOCAL.value,
            ui_parent=KEY_CONFIG_ITEM_TRAEFIK_LABELS,
        )
    )

    # Live Arkime node host (Malcolm profile + live arkime enabled)
    complex_deps[KEY_CONFIG_ITEM_LIVE_ARKIME_NODE_HOST] = DependencySpec(
        visibility=VisibilityRule(
            depends_on=[KEY_CONFIG_ITEM_MALCOLM_PROFILE, KEY_CONFIG_ITEM_LIVE_ARKIME],
            condition=lambda profile, live_arkime: (
                profile == PROFILE_MALCOLM and bool(live_arkime)
            ),
            ui_parent=KEY_CONFIG_ITEM_LIVE_ARKIME,
        )
    )

    # Filebeat TCP parsing options (JSON format only)
    for field_key in [
        KEY_CONFIG_ITEM_FILEBEAT_TCP_PARSE_SOURCE_FIELD,
        KEY_CONFIG_ITEM_FILEBEAT_TCP_PARSE_TARGET_FIELD,
        KEY_CONFIG_ITEM_FILEBEAT_TCP_PARSE_DROP_FIELD,
    ]:
        complex_deps[field_key] = DependencySpec(
            visibility=VisibilityRule(
                depends_on=KEY_CONFIG_ITEM_FILEBEAT_TCP_LOG_FORMAT,
                condition=lambda format: format == FilebeatLogFormat.JSON.value,
                ui_parent=KEY_CONFIG_ITEM_FILEBEAT_TCP_LOG_FORMAT,
            )
        )

    # Set default JSON parsing field values
    complex_deps[KEY_CONFIG_ITEM_FILEBEAT_TCP_PARSE_SOURCE_FIELD] = DependencySpec(
        visibility=complex_deps[
            KEY_CONFIG_ITEM_FILEBEAT_TCP_PARSE_SOURCE_FIELD
        ].visibility,
        value=ValueRule(
            depends_on=KEY_CONFIG_ITEM_FILEBEAT_TCP_LOG_FORMAT,
            condition=lambda format: format == FilebeatLogFormat.JSON.value,
            default_value=FilebeatFieldNames.MESSAGE.value,
        ),
    )

    complex_deps[KEY_CONFIG_ITEM_FILEBEAT_TCP_PARSE_TARGET_FIELD] = DependencySpec(
        visibility=complex_deps[
            KEY_CONFIG_ITEM_FILEBEAT_TCP_PARSE_TARGET_FIELD
        ].visibility,
        value=ValueRule(
            depends_on=KEY_CONFIG_ITEM_FILEBEAT_TCP_LOG_FORMAT,
            condition=lambda format: format == FilebeatLogFormat.JSON.value,
            default_value=FilebeatFieldNames.MISCBEAT.value,
        ),
    )

    complex_deps[KEY_CONFIG_ITEM_FILEBEAT_TCP_PARSE_DROP_FIELD] = DependencySpec(
        visibility=complex_deps[
            KEY_CONFIG_ITEM_FILEBEAT_TCP_PARSE_DROP_FIELD
        ].visibility,
        value=ValueRule(
            depends_on=KEY_CONFIG_ITEM_FILEBEAT_TCP_LOG_FORMAT,
            condition=lambda format: format == FilebeatLogFormat.JSON.value,
            default_value=FilebeatFieldNames.MESSAGE.value,
        ),
    )

    # ------------------------------------------------------------------
    # Live capture defaults (explicit declarative rules, no bulk handler)
    # ------------------------------------------------------------------
    # live_arkime default: True for hedgehog or when primary store is not local
    complex_deps[KEY_CONFIG_ITEM_LIVE_ARKIME] = DependencySpec(
        value=ValueRule(
            depends_on=[
                KEY_CONFIG_ITEM_CAPTURE_LIVE_NETWORK_TRAFFIC,
                KEY_CONFIG_ITEM_MALCOLM_PROFILE,
                KEY_CONFIG_ITEM_OPENSEARCH_PRIMARY_MODE,
            ],
            condition=lambda enabled, _profile, _mode: bool(enabled),
            default_value=lambda _enabled, profile, mode: (
                profile == PROFILE_HEDGEHOG
                or mode != SearchEngineMode.OPENSEARCH_LOCAL.value
            ),
        )
    )

    # pcap_net_sniff default is the opposite of live_arkime default when enabled
    complex_deps[KEY_CONFIG_ITEM_PCAP_NET_SNIFF] = DependencySpec(
        value=ValueRule(
            depends_on=[
                KEY_CONFIG_ITEM_CAPTURE_LIVE_NETWORK_TRAFFIC,
                KEY_CONFIG_ITEM_MALCOLM_PROFILE,
                KEY_CONFIG_ITEM_OPENSEARCH_PRIMARY_MODE,
            ],
            condition=lambda enabled, _profile, _mode: bool(enabled),
            default_value=lambda _enabled, profile, mode: not (
                profile == PROFILE_HEDGEHOG
                or mode != SearchEngineMode.OPENSEARCH_LOCAL.value
            ),
        )
    )

    # Additional live capture related defaults when enabled
    for key in [
        KEY_CONFIG_ITEM_LIVE_ZEEK,
        KEY_CONFIG_ITEM_LIVE_SURICATA,
        KEY_CONFIG_ITEM_TWEAK_IFACE,
        KEY_CONFIG_ITEM_CAPTURE_STATS,
    ]:
        complex_deps[key] = DependencySpec(
            value=ValueRule(
                depends_on=KEY_CONFIG_ITEM_CAPTURE_LIVE_NETWORK_TRAFFIC,
                condition=lambda enabled: bool(enabled),
                default_value=True,
            )
        )

    return complex_deps
