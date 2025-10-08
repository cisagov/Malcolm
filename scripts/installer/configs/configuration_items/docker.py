#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2025 Battelle Energy Alliance, LLC.  All rights reserved.


"""
Container options configuration items for Malcolm installer.

This module contains all configuration items related to container options,
including restart policies, reverse proxy settings, and network configuration.
"""

# from scripts.malcolm_common import
from scripts.malcolm_utils import str2bool as str_to_bool, SYSTEM_INFO
from scripts.malcolm_constants import (
    OrchestrationFramework,
    OrchestrationFrameworksSupported,
    WidgetType,
)

from scripts.installer.core.config_item import ConfigItem
from scripts.installer.configs.constants.constants import ORCHESTRATION_MODE_CHOICES
from scripts.installer.configs.constants.enums import DockerRestartPolicy
from scripts.installer.configs.constants.configuration_item_keys import (
    KEY_CONFIG_ITEM_MALCOLM_AUTO_RESTART,
    KEY_CONFIG_ITEM_BEHIND_REVERSE_PROXY,
    KEY_CONFIG_ITEM_TRAEFIK_HOST,
    KEY_CONFIG_ITEM_TRAEFIK_OPENSEARCH_HOST,
    KEY_CONFIG_ITEM_TRAEFIK_ENTRYPOINT,
    KEY_CONFIG_ITEM_TRAEFIK_RESOLVER,
    KEY_CONFIG_ITEM_TRAEFIK_LABELS,
    KEY_CONFIG_ITEM_CONTAINER_NETWORK_NAME,
    KEY_CONFIG_ITEM_DOCKER_ORCHESTRATION_MODE,
    KEY_CONFIG_ITEM_MALCOLM_RESTART_POLICY,
    KEY_CONFIG_ITEM_PROCESS_GROUP_ID,
    KEY_CONFIG_ITEM_PROCESS_USER_ID,
    KEY_CONFIG_ITEM_DOCKER_EXTRA_USERS,
)

CONFIG_ITEM_DOCKER_EXTRA_USERS = ConfigItem(
    key=KEY_CONFIG_ITEM_DOCKER_EXTRA_USERS,
    label="Additional Docker Users",
    default_value=[],
    validator=lambda x: isinstance(x, list),
    question=f"Enter a comma-separated list of non-root users to add to the 'docker' group",
    widget_type=WidgetType.TEXT,
    metadata={
        "affects_install_context": True,  # Tag indicating this also updates InstallContext
        "install_context_field": "docker_extra_users",  # The corresponding InstallContext field
    },
)

CONFIG_ITEM_PROCESS_GROUP_ID = ConfigItem(
    key=KEY_CONFIG_ITEM_PROCESS_GROUP_ID,
    label="Process Group ID",
    default_value=SYSTEM_INFO["recommended_nonroot_gid"],
    validator=lambda x: isinstance(x, int) and x >= 0,
    question=f"Enter group ID (GID) for running non-root Malcolm processes",
    widget_type=WidgetType.NUMBER,
)

CONFIG_ITEM_PROCESS_USER_ID = ConfigItem(
    key=KEY_CONFIG_ITEM_PROCESS_USER_ID,
    label="Process User ID",
    default_value=SYSTEM_INFO["recommended_nonroot_uid"],
    validator=lambda x: isinstance(x, int) and x >= 0,
    question=f"Enter user ID (UID) for running non-root Malcolm processes",
    widget_type=WidgetType.NUMBER,
)


CONFIG_ITEM_DOCKER_ORCHESTRATION_MODE = ConfigItem(
    key=KEY_CONFIG_ITEM_DOCKER_ORCHESTRATION_MODE,
    label="Docker Orchestration Mode",
    default_value=OrchestrationFramework.DOCKER_COMPOSE,
    # Present clear names to users; tags are normalized by MalcolmConfig
    choices=ORCHESTRATION_MODE_CHOICES,
    validator=lambda x: isinstance(x, OrchestrationFramework),
    question="Select docker orchestration mode",
    widget_type=WidgetType.SELECT,
)

CONFIG_ITEM_MALCOLM_AUTO_RESTART = ConfigItem(
    key=KEY_CONFIG_ITEM_MALCOLM_AUTO_RESTART,
    label="Auto-Restart Malcolm",
    default_value=False,
    validator=lambda x: isinstance(x, bool),
    question=(
        "Automatically restart Malcolm after system or container daemon restarts?"
    ),
    widget_type=WidgetType.CHECKBOX,
)

CONFIG_ITEM_MALCOLM_RESTART_POLICY = ConfigItem(
    key=KEY_CONFIG_ITEM_MALCOLM_RESTART_POLICY,
    label="Malcolm Restart Policy",
    default_value=DockerRestartPolicy.NO.value,
    choices=[x.value for x in DockerRestartPolicy],
    validator=lambda x: isinstance(x, str) and x in [v.value for v in DockerRestartPolicy],
    question="Select Malcolm restart policy",
    widget_type=WidgetType.SELECT,
) # fmt: skip

CONFIG_ITEM_BEHIND_REVERSE_PROXY = ConfigItem(
    key=KEY_CONFIG_ITEM_BEHIND_REVERSE_PROXY,
    label="Behind Reverse Proxy",
    default_value=False,
    validator=lambda x: isinstance(x, bool),
    question=f"Will Malcolm be running behind another reverse proxy (Traefik, Caddy, etc.)?",
    widget_type=WidgetType.CHECKBOX,
)

CONFIG_ITEM_TRAEFIK_HOST = ConfigItem(
    key=KEY_CONFIG_ITEM_TRAEFIK_HOST,
    label="Traefik Host",
    default_value="",
    validator=lambda x: isinstance(x, str),
    question=f"Request domain (host header value) for Malcolm interface Traefik router (e.g., malcolm.example.org)",
    widget_type=WidgetType.TEXT,
)

CONFIG_ITEM_TRAEFIK_OPENSEARCH_HOST = ConfigItem(
    key=KEY_CONFIG_ITEM_TRAEFIK_OPENSEARCH_HOST,
    label="Traefik OpenSearch Host",
    default_value="",
    validator=lambda x: isinstance(x, str),
    question=f"Request domain (host header value) for OpenSearch Traefik router (e.g., opensearch.malcolm.example.org)",
    widget_type=WidgetType.TEXT,
)

CONFIG_ITEM_TRAEFIK_ENTRYPOINT = ConfigItem(
    key=KEY_CONFIG_ITEM_TRAEFIK_ENTRYPOINT,
    label="Traefik Entrypoint",
    default_value="websecure",
    validator=lambda x: isinstance(x, str),
    question=f"Traefik router entrypoint (e.g., websecure)",
    widget_type=WidgetType.TEXT,
)

CONFIG_ITEM_TRAEFIK_RESOLVER = ConfigItem(
    key=KEY_CONFIG_ITEM_TRAEFIK_RESOLVER,
    label="Traefik Resolver",
    default_value="",
    validator=lambda x: isinstance(x, str),
    question=f"Traefik router resolver (e.g., myresolver)",
    widget_type=WidgetType.TEXT,
)

CONFIG_ITEM_TRAEFIK_LABELS = ConfigItem(
    key=KEY_CONFIG_ITEM_TRAEFIK_LABELS,
    label="Traefik Labels",
    default_value=False,
    validator=lambda x: isinstance(x, bool),
    question=f"Configure labels for Traefik?",
    widget_type=WidgetType.CHECKBOX,
)

CONFIG_ITEM_CONTAINER_NETWORK_NAME = ConfigItem(
    key=KEY_CONFIG_ITEM_CONTAINER_NETWORK_NAME,
    label="Container Network Name",
    default_value="",
    validator=lambda x: isinstance(x, str),
    question=f"External container network name (or leave blank for default networking)",
    widget_type=WidgetType.TEXT,
)


def get_docker_config_item_dict():
    """Get all ConfigItem objects from this module.

    Returns:
        Dict mapping configuration key strings to their ConfigItem objects
    """
    config_items = {}
    # Iterate over globals to find all defined ConfigItem objects in this module
    for key_name, key_value in globals().items():
        # Check if this is a ConfigItem object
        if isinstance(key_value, ConfigItem):
            # Store the entire ConfigItem object with its key as the dictionary key
            config_items[key_value.key] = key_value
    return config_items


# A dictionary mapping configuration keys to their ConfigItem objects, created once at module load.
ALL_DOCKER_CONFIG_ITEMS_DICT = get_docker_config_item_dict()

if __name__ == "__main__":
    # print(globals().items())
    print(ALL_DOCKER_CONFIG_ITEMS_DICT.keys())
