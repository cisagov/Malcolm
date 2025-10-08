#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Normalize inbound values and format outbound values for stores."""

from typing import Any, Type


def _normalize_enum_by_value(enum_cls: Type, value: Any) -> Any:
    try:
        if isinstance(value, enum_cls):
            # configuration store generally persists .value for simple enums
            return getattr(value, "value", value)
        if isinstance(value, str):
            try:
                return getattr(enum_cls(value), "value", value)
            except Exception:
                # try by name for convenience
                member = getattr(enum_cls, value, None) or getattr(
                    enum_cls, value.upper(), None
                )
                if member is not None:
                    return getattr(member, "value", member)
        # attempt direct construction from raw
        return getattr(enum_cls(value), "value", value)
    except Exception:
        return value


def _normalize_enum_keep_member(enum_cls: Type, value: Any) -> Any:
    try:
        if isinstance(value, enum_cls):
            return value
        if isinstance(value, str):
            member = enum_cls.__members__.get(value) or enum_cls.__members__.get(
                value.upper()
            )
            if member is not None:
                return member
        return enum_cls(value)
    except Exception:
        return value


def apply_inbound(key: str, value: Any) -> Any:
    """Normalize inbound values by key.

    - Simple enums are stored as their canonical .value (usually strings)
    - Flag enums (e.g., orchestration) are stored as the Enum instance
    - Special cases (OpenSearch modes) map to canonical labels
    - Installation enums map to their enum members
    """
    try:
        from scripts.installer.configs.constants.configuration_item_keys import (
            KEY_CONFIG_ITEM_MALCOLM_RESTART_POLICY,
            KEY_CONFIG_ITEM_RUNTIME_BIN,
            KEY_CONFIG_ITEM_FILEBEAT_TCP_LOG_FORMAT,
            KEY_CONFIG_ITEM_NETBOX_MODE,
            KEY_CONFIG_ITEM_IMAGE_ARCH,
            KEY_CONFIG_ITEM_DOCKER_ORCHESTRATION_MODE,
            KEY_CONFIG_ITEM_OPENSEARCH_PRIMARY_MODE,
            KEY_CONFIG_ITEM_OPENSEARCH_SECONDARY_MODE,
            KEY_CONFIG_ITEM_OPEN_PORTS,
            KEY_CONFIG_ITEM_FILE_CARVE_MODE,
            KEY_CONFIG_ITEM_FILE_PRESERVE_MODE,
        )
        from scripts.installer.configs.constants.enums import (
            DockerRestartPolicy,
            ContainerRuntime,
            FilebeatLogFormat,
            NetboxMode,
            OpenPortsChoices,
            FileExtractionMode,
            FilePreservationMode,
        )
        from scripts.malcolm_constants import (
            ImageArchitecture,
            OrchestrationFramework,
            DATABASE_MODE_LABELS,
            DatabaseMode,
        )
        from scripts.installer.configs.constants.installation_item_keys import (
            KEY_INSTALLATION_ITEM_DOCKER_INSTALL_METHOD,
            KEY_INSTALLATION_ITEM_DOCKER_COMPOSE_INSTALL_METHOD,
        )
        from scripts.installer.configs.constants.enums import (
            DockerInstallMethod,
            DockerComposeInstallMethod,
        )
    except Exception:
        # If imports fail in some contexts (docs/tools), fall back to passthrough
        return value

    # Simple enums serialized to .value
    if key == KEY_CONFIG_ITEM_MALCOLM_RESTART_POLICY:
        return _normalize_enum_by_value(DockerRestartPolicy, value)
    if key == KEY_CONFIG_ITEM_RUNTIME_BIN:
        return _normalize_enum_by_value(ContainerRuntime, value)
    if key == KEY_CONFIG_ITEM_FILEBEAT_TCP_LOG_FORMAT:
        return _normalize_enum_by_value(FilebeatLogFormat, value)
    if key == KEY_CONFIG_ITEM_NETBOX_MODE:
        return _normalize_enum_by_value(NetboxMode, value)
    if key == KEY_CONFIG_ITEM_IMAGE_ARCH:
        return _normalize_enum_by_value(ImageArchitecture, value)
    if key == KEY_CONFIG_ITEM_OPEN_PORTS:
        return _normalize_enum_by_value(OpenPortsChoices, value)
    if key == KEY_CONFIG_ITEM_FILE_CARVE_MODE:
        return _normalize_enum_by_value(FileExtractionMode, value)
    if key == KEY_CONFIG_ITEM_FILE_PRESERVE_MODE:
        return _normalize_enum_by_value(FilePreservationMode, value)

    # Flag enum kept as member
    if key == KEY_CONFIG_ITEM_DOCKER_ORCHESTRATION_MODE:
        return _normalize_enum_keep_member(OrchestrationFramework, value)

    # OpenSearch modes to canonical labels
    if key in (KEY_CONFIG_ITEM_OPENSEARCH_PRIMARY_MODE, KEY_CONFIG_ITEM_OPENSEARCH_SECONDARY_MODE):
        if isinstance(value, DatabaseMode):
            return DATABASE_MODE_LABELS.get(value, str(value))
        if isinstance(value, str) and value.isdigit():
            try:
                return DATABASE_MODE_LABELS.get(int(value), value)
            except Exception:
                return value
        return value

    # Installation enums: keep enum member
    if key == KEY_INSTALLATION_ITEM_DOCKER_INSTALL_METHOD:
        return _normalize_enum_keep_member(DockerInstallMethod, value)
    if key == KEY_INSTALLATION_ITEM_DOCKER_COMPOSE_INSTALL_METHOD:
        return _normalize_enum_keep_member(DockerComposeInstallMethod, value)

    return value


def apply_outbound(key: str, value: Any) -> Any:
    """Map internal values into user-friendly strings for display/summary."""
    try:
        from enum import Enum
        from scripts.malcolm_constants import DATABASE_MODE_LABELS, DatabaseMode
    except Exception:
        # minimal fallback
        if hasattr(value, "name"):
            try:
                return value.name
            except Exception:
                return value
        return value

    if isinstance(value, Enum):
        # prefer .value when it is a string label; fall back to .name
        try:
            return value.value if isinstance(value.value, str) else value.name
        except Exception:
            return getattr(value, "name", value)
    if isinstance(value, DatabaseMode):
        return DATABASE_MODE_LABELS.get(value, str(value))
    return value
