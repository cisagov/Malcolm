#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2025 Battelle Energy Alliance, LLC.  All rights reserved.


"""
Network and Authentication configuration items for Malcolm installer.

This module contains all configuration items related to network and authentication settings.
"""

from typing import Any, Tuple

from scripts.malcolm_constants import WidgetType
from scripts.malcolm_utils import str2bool

from scripts.installer.core.config_item import ConfigItem
from scripts.installer.configs.constants.configuration_item_keys import (
    KEY_CONFIG_ITEM_NGINX_SSL,
    KEY_CONFIG_ITEM_NGINX_RESOLVER_IPV4_OFF,
    KEY_CONFIG_ITEM_NGINX_RESOLVER_IPV6_OFF,
    KEY_CONFIG_ITEM_CAPTURE_LIVE_NETWORK_TRAFFIC,
)

CONFIG_ITEM_CAPTURE_LIVE_NETWORK_TRAFFIC = ConfigItem(
    key=KEY_CONFIG_ITEM_CAPTURE_LIVE_NETWORK_TRAFFIC,
    label="Capture Live Network Traffic",
    default_value=False,
    validator=lambda x: isinstance(x, bool),
    question=f"Capture live network traffic",
    widget_type=WidgetType.CHECKBOX,
)

CONFIG_ITEM_NGINX_SSL = ConfigItem(
    key=KEY_CONFIG_ITEM_NGINX_SSL,
    label="Require HTTPS Connections",
    default_value=True,
    validator=lambda x: isinstance(x, bool),
    question=f"Require encrypted HTTPS connections",
    widget_type=WidgetType.CHECKBOX,
)

CONFIG_ITEM_NGINX_RESOLVER_IPV4 = ConfigItem(
    key=KEY_CONFIG_ITEM_NGINX_RESOLVER_IPV4_OFF,
    label="Enable IPv4 for nginx resolver directive",
    default_value=True,
    validator=lambda x: isinstance(x, bool),
    question=f"Enable IPv4 for nginx resolver directive",
    widget_type=WidgetType.CHECKBOX,
)

CONFIG_ITEM_NGINX_RESOLVER_IPV6 = ConfigItem(
    key=KEY_CONFIG_ITEM_NGINX_RESOLVER_IPV6_OFF,
    label="Enable IPv6 for nginx resolver directive",
    default_value=False,
    validator=lambda x: isinstance(x, bool),
    question=f"Enable IPv6 for nginx resolver directive",
    widget_type=WidgetType.CHECKBOX,
)


def get_network_config_item_dict():
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
ALL_NETWORK_CONFIG_ITEMS_DICT = get_network_config_item_dict()

if __name__ == "__main__":
    print(ALL_NETWORK_CONFIG_ITEMS_DICT.keys())
