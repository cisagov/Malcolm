#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2025 Battelle Energy Alliance, LLC.  All rights reserved.


"""Logstash configuration items for Malcolm installer.

This module contains all configuration items related to Logstash settings,
including memory allocation and worker configuration.
"""

from typing import Any, Tuple

from scripts.malcolm_constants import OrchestrationFramework, WidgetType
from scripts.malcolm_common import SYSTEM_INFO
from scripts.installer.core.config_item import ConfigItem
from scripts.installer.configs.configuration_items.docker import (
    CONFIG_ITEM_DOCKER_ORCHESTRATION_MODE,
)
from scripts.installer.configs.constants.configuration_item_keys import (
    KEY_CONFIG_ITEM_LS_MEMORY,
    KEY_CONFIG_ITEM_LS_WORKERS,
    KEY_CONFIG_ITEM_LOGSTASH_HOST,
)

CONFIG_ITEM_LS_MEMORY = ConfigItem(
    key=KEY_CONFIG_ITEM_LS_MEMORY,
    label="Logstash Memory",
    default_value=SYSTEM_INFO["suggested_ls_memory"],
    question=f"Memory allocation for Logstash (e.g., 4g, 2500m, etc.)",
    widget_type=WidgetType.TEXT,
)

# Default value handled in MalcolmConfig based on DOCKER_ORCHESTRATION_MODE
CONFIG_ITEM_LS_WORKERS = ConfigItem(
    key=KEY_CONFIG_ITEM_LS_WORKERS,
    label="Logstash Workers",
    default_value=SYSTEM_INFO["suggested_ls_workers"],
    validator=lambda x: isinstance(x, int),
    question=f"Number of Logstash pipeline workers (e.g., 4, 8, etc.)",
    widget_type=WidgetType.NUMBER,
)

# This contains the port as well as the host
CONFIG_ITEM_LOGSTASH_HOST = ConfigItem(
    key=KEY_CONFIG_ITEM_LOGSTASH_HOST,
    label="Logstash Host",
    default_value=None,
    validator=lambda x: isinstance(x, str),
    question=f'Logstash host and port (for when running "capture-only" profile; e.g., 192.168.1.123:5044)',
    widget_type=WidgetType.TEXT,
)


def get_logstash_config_item_dict():
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
ALL_LOGSTASH_CONFIG_ITEMS_DICT = get_logstash_config_item_dict()

if __name__ == "__main__":
    # print(globals().items())
    print(ALL_LOGSTASH_CONFIG_ITEMS_DICT.keys())
