#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2025 Battelle Energy Alliance, LLC.  All rights reserved.


"""NetBox configuration items for Malcolm installer.

This module contains all configuration items related to NetBox settings,
including NetBox instance management and network traffic enrichment options.
"""

from scripts.installer.core.config_item import ConfigItem
from scripts.installer.configs.constants.enums import NetboxMode
from scripts.installer.configs.constants.configuration_item_keys import (
    KEY_CONFIG_ITEM_NETBOX_AUTO_POPULATE,
    KEY_CONFIG_ITEM_NETBOX_LOGSTASH_AUTO_SUBNETS,
    KEY_CONFIG_ITEM_NETBOX_LOGSTASH_ENRICH,
    KEY_CONFIG_ITEM_NETBOX_MODE,
    KEY_CONFIG_ITEM_NETBOX_SITE_NAME,
    KEY_CONFIG_ITEM_NETBOX_URL,
)
from scripts.malcolm_constants import WidgetType

CONFIG_ITEM_NETBOX_MODE = ConfigItem(
    key=KEY_CONFIG_ITEM_NETBOX_MODE,
    label="NetBox Mode",
    default_value="disabled",
    choices=[x.value for x in NetboxMode],
    validator=lambda x: isinstance(x, str) and x in [v.value for v in NetboxMode],
    question="Select NetBox mode",
    widget_type=WidgetType.SELECT,
)

CONFIG_ITEM_NETBOX_URL = ConfigItem(
    key=KEY_CONFIG_ITEM_NETBOX_URL,
    label="NetBox URL",
    default_value="",
    validator=lambda x: isinstance(x, str),
    question='Remote NetBox URL',
    widget_type=WidgetType.TEXT,
)

CONFIG_ITEM_NETBOX_LOGSTASH_ENRICH = ConfigItem(
    key=KEY_CONFIG_ITEM_NETBOX_LOGSTASH_ENRICH,
    label="NetBox Enrichment",
    default_value=True,
    validator=lambda x: isinstance(x, bool),
    question="Enrich network traffic using NetBox?",
    widget_type=WidgetType.CHECKBOX,
)

CONFIG_ITEM_NETBOX_AUTO_POPULATE = ConfigItem(
    key=KEY_CONFIG_ITEM_NETBOX_AUTO_POPULATE,
    label="Auto-Populate NetBox Inventory",
    default_value=False,
    validator=lambda x: isinstance(x, bool),
    question="Automatically populate NetBox inventory based on observed network traffic?",
    widget_type=WidgetType.CHECKBOX,
)

CONFIG_ITEM_NETBOX_LOGSTASH_AUTO_SUBNETS = ConfigItem(
    key=KEY_CONFIG_ITEM_NETBOX_LOGSTASH_AUTO_SUBNETS,
    label="Auto-Create Subnet Prefixes",
    default_value=False,
    validator=lambda x: isinstance(x, bool),
    question="Automatically create missing NetBox subnet prefixes based on observed network traffic?",
    widget_type=WidgetType.CHECKBOX,
)

# Default value handled in MalcolmConfig based on AUTO_POPULATE/AUTO_SUBNETS and PCAP_NODE_NAME
CONFIG_ITEM_NETBOX_SITE_NAME = ConfigItem(
    key=KEY_CONFIG_ITEM_NETBOX_SITE_NAME,
    label="NetBox Site Name",
    default_value=None,
    validator=lambda x: isinstance(x, str),
    question="Default NetBox site name",
    widget_type=WidgetType.TEXT,
)


def get_netbox_config_item_dict():
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
ALL_NETBOX_CONFIG_ITEMS_DICT = get_netbox_config_item_dict()

if __name__ == "__main__":
    # print(globals().items())
    print(ALL_NETBOX_CONFIG_ITEMS_DICT.keys())
