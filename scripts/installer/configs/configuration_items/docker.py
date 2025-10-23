#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2025 Battelle Energy Alliance, LLC.  All rights reserved.


"""
Container options configuration items for Malcolm installer.

This module contains all configuration items related to container options,
including restart policies, reverse proxy settings, and network configuration.
"""

from scripts.malcolm_common import SYSTEM_INFO
from scripts.malcolm_constants import (
    OrchestrationFramework,
    WidgetType,
)

from scripts.installer.core.config_item import ConfigItem
from scripts.installer.configs.constants.constants import ORCHESTRATION_MODE_CHOICES
from scripts.installer.configs.constants.enums import DockerRestartPolicy
from scripts.installer.configs.constants.configuration_item_keys import (
    KEY_CONFIG_ITEM_CONTAINER_NETWORK_NAME,
    KEY_CONFIG_ITEM_DOCKER_ORCHESTRATION_MODE,
    KEY_CONFIG_ITEM_MALCOLM_RESTART_POLICY,
    KEY_CONFIG_ITEM_PROCESS_GROUP_ID,
    KEY_CONFIG_ITEM_PROCESS_USER_ID,
    KEY_CONFIG_ITEM_TRAEFIK_ENTRYPOINT,
    KEY_CONFIG_ITEM_TRAEFIK_HOST,
    KEY_CONFIG_ITEM_TRAEFIK_LABELS,
    KEY_CONFIG_ITEM_TRAEFIK_OPENSEARCH_HOST,
    KEY_CONFIG_ITEM_TRAEFIK_RESOLVER,
)

CONFIG_ITEM_PROCESS_GROUP_ID = ConfigItem(
    key=KEY_CONFIG_ITEM_PROCESS_GROUP_ID,
    label="Process Group ID",
    default_value=SYSTEM_INFO["recommended_nonroot_gid"],
    validator=lambda x: isinstance(x, int) and x >= 0,
    question="Group ID (GID) for running non-root Malcolm processes",
    widget_type=WidgetType.NUMBER,
)

CONFIG_ITEM_PROCESS_USER_ID = ConfigItem(
    key=KEY_CONFIG_ITEM_PROCESS_USER_ID,
    label="Process User ID",
    default_value=SYSTEM_INFO["recommended_nonroot_uid"],
    validator=lambda x: isinstance(x, int) and x >= 0,
    question="User ID (UID) for running non-root Malcolm processes",
    widget_type=WidgetType.NUMBER,
)


CONFIG_ITEM_DOCKER_ORCHESTRATION_MODE = ConfigItem(
    key=KEY_CONFIG_ITEM_DOCKER_ORCHESTRATION_MODE,
    label="Container Orchestration Mode",
    default_value=OrchestrationFramework.DOCKER_COMPOSE,
    # Present clear names to users; tags are normalized by MalcolmConfig
    choices=ORCHESTRATION_MODE_CHOICES,
    validator=lambda x: isinstance(x, OrchestrationFramework),
    question="Select container orchestration mode",
    widget_type=WidgetType.SELECT,
)

CONFIG_ITEM_MALCOLM_RESTART_POLICY = ConfigItem(
    key=KEY_CONFIG_ITEM_MALCOLM_RESTART_POLICY,
    label="Malcolm Restart Policy",
    default_value=DockerRestartPolicy.NO.value,
    choices=[x.value for x in DockerRestartPolicy],
    validator=lambda x: isinstance(x, str) and x in [v.value for v in DockerRestartPolicy],
    question="Select policy for restarting Malcolm after system or container daemon restarts",
    widget_type=WidgetType.SELECT,
)

CONFIG_ITEM_TRAEFIK_LABELS = ConfigItem(
    key=KEY_CONFIG_ITEM_TRAEFIK_LABELS,
    label="Traefik Labels",
    default_value=False,
    validator=lambda x: isinstance(x, bool),
    question="Enable labels for Traefik reverse proxy?",
    widget_type=WidgetType.CHECKBOX,
)

CONFIG_ITEM_TRAEFIK_HOST = ConfigItem(
    key=KEY_CONFIG_ITEM_TRAEFIK_HOST,
    label="Traefik Host",
    default_value="",
    validator=lambda x: isinstance(x, str),
    question="Request domain (host header value) for Malcolm interface Traefik router (e.g., malcolm.example.org)",
    widget_type=WidgetType.TEXT,
)

CONFIG_ITEM_TRAEFIK_OPENSEARCH_HOST = ConfigItem(
    key=KEY_CONFIG_ITEM_TRAEFIK_OPENSEARCH_HOST,
    label="Traefik OpenSearch Host",
    default_value="",
    validator=lambda x: isinstance(x, str),
    question="Request domain (host header value) for OpenSearch Traefik router (e.g., opensearch.malcolm.example.org)",
    widget_type=WidgetType.TEXT,
)

CONFIG_ITEM_TRAEFIK_ENTRYPOINT = ConfigItem(
    key=KEY_CONFIG_ITEM_TRAEFIK_ENTRYPOINT,
    label="Traefik Entrypoint",
    default_value="websecure",
    validator=lambda x: isinstance(x, str),
    question="Traefik router entrypoint (e.g., websecure)",
    widget_type=WidgetType.TEXT,
)

CONFIG_ITEM_TRAEFIK_RESOLVER = ConfigItem(
    key=KEY_CONFIG_ITEM_TRAEFIK_RESOLVER,
    label="Traefik Resolver",
    default_value="",
    validator=lambda x: isinstance(x, str),
    question="Traefik router resolver (e.g., myresolver)",
    widget_type=WidgetType.TEXT,
)

CONFIG_ITEM_CONTAINER_NETWORK_NAME = ConfigItem(
    key=KEY_CONFIG_ITEM_CONTAINER_NETWORK_NAME,
    label="Container Network Name",
    default_value="",
    validator=lambda x: isinstance(x, str),
    question="External container network name (blank for default networking)",
    accept_blank=True,
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
