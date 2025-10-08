#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2025 Battelle Energy Alliance, LLC.  All rights reserved.


"""Build and format configuration summaries for UI display."""

from typing import List, Tuple
from enum import Enum


def _normalize_display_string(value: str) -> str:
    """Normalize common enum-like strings for consistent UI display.

    Standardizes values like yes/no and restart policies to Title case so that
    booleans (rendered as Yes/No) match enum strings (e.g., "no").
    """
    if value is None:
        return "Not set"
    lower = str(value).strip().lower()
    mapping = {
        "yes": "Yes",
        "no": "No",
        "always": "Always",
        # keep hyphen but Title-case the first word for readability
        "unless-stopped": "Unless-stopped",
    }
    return mapping.get(lower, value)


def _get_restart_policy_display(malcolm_config) -> str:
    """Get the restart policy display value based on auto-restart setting and policy value.

    Args:
        malcolm_config: MalcolmConfig instance

    Returns:
        String representation of the restart policy
    """
    from scripts.installer.configs.constants.configuration_item_keys import (
        KEY_CONFIG_ITEM_MALCOLM_AUTO_RESTART,
        KEY_CONFIG_ITEM_MALCOLM_RESTART_POLICY,
    )

    auto_restart = malcolm_config.get_value(KEY_CONFIG_ITEM_MALCOLM_AUTO_RESTART)
    restart_policy = malcolm_config.get_value(KEY_CONFIG_ITEM_MALCOLM_RESTART_POLICY)

    if not auto_restart:
        # Keep display consistent with other booleans
        return "No"

    # If auto-restart is enabled, use the configured policy or default to "unless-stopped"
    if restart_policy:
        # Handle enum values explicitly
        if isinstance(restart_policy, Enum):
            return _normalize_display_string(restart_policy.value)
        return _normalize_display_string(str(restart_policy))

    return _normalize_display_string(
        "unless-stopped"
    )  # Default when auto-restart is enabled


def build_configuration_summary_items(
    malcolm_config, config_dir: str
) -> List[Tuple[str, str]]:
    """Build a list of configuration summary items for display.

    Args:
        malcolm_config: MalcolmConfig instance containing all configuration
        config_dir: Configuration directory path where files will be saved

    Returns:
        List of (label, value) tuples representing configuration items
    """
    from scripts.installer.configs.constants.configuration_item_keys import (
        KEY_CONFIG_ITEM_RUNTIME_BIN,
        KEY_CONFIG_ITEM_MALCOLM_PROFILE,
        KEY_CONFIG_ITEM_MALCOLM_AUTO_RESTART,
        KEY_CONFIG_ITEM_MALCOLM_RESTART_POLICY,
        KEY_CONFIG_ITEM_DOCKER_ORCHESTRATION_MODE,
        KEY_CONFIG_ITEM_PCAP_NODE_NAME,
        KEY_CONFIG_ITEM_NGINX_SSL,
        KEY_CONFIG_ITEM_USE_DEFAULT_STORAGE_LOCATIONS,
        KEY_CONFIG_ITEM_CONTAINER_NETWORK_NAME,
        KEY_CONFIG_ITEM_PROCESS_USER_ID,
        KEY_CONFIG_ITEM_PROCESS_GROUP_ID,
    )
    from scripts.installer.configs.constants.installation_item_keys import (
        KEY_INSTALLATION_ITEM_AUTO_TWEAKS,
    )
    from scripts.malcolm_constants import OrchestrationFramework

    # determine orchestration to match legacy display behavior
    orch_mode = malcolm_config.get_value(KEY_CONFIG_ITEM_DOCKER_ORCHESTRATION_MODE)

    summary_items = [
        ("Installation Directory", config_dir),
        ("Container Runtime", malcolm_config.get_value(KEY_CONFIG_ITEM_RUNTIME_BIN)),
        ("Malcolm Profile", malcolm_config.get_value(KEY_CONFIG_ITEM_MALCOLM_PROFILE)),
        ("Node Name", malcolm_config.get_value(KEY_CONFIG_ITEM_PCAP_NODE_NAME)),
        ("Process User ID", malcolm_config.get_value(KEY_CONFIG_ITEM_PROCESS_USER_ID)),
        (
            "Process Group ID",
            malcolm_config.get_value(KEY_CONFIG_ITEM_PROCESS_GROUP_ID),
        ),
    ]

    # legacy parity: only include auto-restart and restart policy when using docker compose
    if orch_mode != OrchestrationFramework.KUBERNETES:
        summary_items.append(
            (
                "Auto-Restart Malcolm",
                (
                    "Yes"
                    if malcolm_config.get_value(KEY_CONFIG_ITEM_MALCOLM_AUTO_RESTART)
                    else "No"
                ),
            )
        )
        summary_items.append(
            ("Restart Policy", _get_restart_policy_display(malcolm_config))
        )

    # remaining items are common to both orchestration modes
    summary_items.extend(
        [
            (
                "HTTPS/SSL",
                "Yes" if malcolm_config.get_value(KEY_CONFIG_ITEM_NGINX_SSL) else "No",
            ),
            (
                "Auto System Tweaks",
                (
                    "Yes"
                    if malcolm_config.get_value(KEY_INSTALLATION_ITEM_AUTO_TWEAKS)
                    else "No"
                ),
            ),
            (
                "Default Storage Locations",
                (
                    "Yes"
                    if malcolm_config.get_value(
                        KEY_CONFIG_ITEM_USE_DEFAULT_STORAGE_LOCATIONS
                    )
                    else "No"
                ),
            ),
            (
                "Container Network",
                malcolm_config.get_value(KEY_CONFIG_ITEM_CONTAINER_NETWORK_NAME)
                or "default",
            ),
        ]
    )

    return summary_items


def format_summary_value(label: str, value) -> str:
    """Format a configuration value for display, handling passwords and None values.

    Args:
        label: The configuration item label
        value: The configuration value to format

    Returns:
        Formatted string suitable for display
    """
    if "password" in label.lower() and value:
        return "********"
    # Use centralized outbound formatting, then apply simple scalar normalization
    try:
        from scripts.installer.core.transform_registry import apply_outbound

        value = apply_outbound("", value)
    except Exception:
        pass
    if isinstance(value, bool):
        return "Yes" if value else "No"
    if isinstance(value, Enum):
        try:
            return _normalize_display_string(value.value)
        except Exception:
            return _normalize_display_string(str(value))
    if value is None or value == "":
        return "Not set"
    return _normalize_display_string(str(value))
