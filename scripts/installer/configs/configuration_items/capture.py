#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2025 Battelle Energy Alliance, LLC.  All rights reserved.

"""
Live traffic capture configuration items for Malcolm installer.

This module contains all configuration items related to live traffic capture settings,
including network interface configuration, capture filters, and capture methods.
"""

from scripts.malcolm_constants import DATABASE_MODE_LABELS, DatabaseMode, WidgetType
from scripts.malcolm_utils import get_hostname_without_domain

from scripts.installer.core.config_item import ConfigItem
from scripts.installer.configs.constants.configuration_item_keys import (
    KEY_CONFIG_ITEM_PCAP_IFACE,
    KEY_CONFIG_ITEM_PCAP_FILTER,
    KEY_CONFIG_ITEM_TWEAK_IFACE,
    KEY_CONFIG_ITEM_CAPTURE_STATS,
    KEY_CONFIG_ITEM_LIVE_ARKIME,
    KEY_CONFIG_ITEM_LIVE_ARKIME_NODE_HOST,
    KEY_CONFIG_ITEM_PCAP_NET_SNIFF,
    KEY_CONFIG_ITEM_PCAP_TCP_DUMP,
    KEY_CONFIG_ITEM_LIVE_ZEEK,
    KEY_CONFIG_ITEM_LIVE_SURICATA,
    KEY_CONFIG_ITEM_PCAP_NODE_NAME,
)

CONFIG_ITEM_PCAP_IFACE = ConfigItem(
    key=KEY_CONFIG_ITEM_PCAP_IFACE,
    label="Capture Interface(s)",
    default_value="",
    validator=lambda x: isinstance(x, str),
    question=f"Capture interface(s) (comma-separated)",
    widget_type=WidgetType.TEXT,
)

CONFIG_ITEM_PCAP_FILTER = ConfigItem(
    key=KEY_CONFIG_ITEM_PCAP_FILTER,
    label="Capture Filter",
    default_value="",
    validator=lambda x: isinstance(x, str),
    question=f"Capture filter (tcpdump-like filter expression; leave blank to capture all traffic)",
    widget_type=WidgetType.TEXT,
)

CONFIG_ITEM_TWEAK_IFACE = ConfigItem(
    key=KEY_CONFIG_ITEM_TWEAK_IFACE,
    label="Optimize Interface",
    default_value=True,
    validator=lambda x: isinstance(x, bool),
    question=f"Disable capture interface hardware offloading and adjust ring buffer sizes",
    widget_type=WidgetType.CHECKBOX,
)

# For CAPTURE_STATS, we'll use SURICATA_STATS_ENABLED since that seems to be its primary equivalent
# This also writes to another env var SURICATA_STATS_EVE_ENABLED
CONFIG_ITEM_CAPTURE_STATS = ConfigItem(
    key=KEY_CONFIG_ITEM_CAPTURE_STATS,
    label="Capture Live Traffic Statistics",
    default_value=False,
    validator=lambda x: isinstance(x, bool),
    question=f"Enable live packet capture statistics for Zeek and/or Suricata",
    widget_type=WidgetType.CHECKBOX,
)

CONFIG_ITEM_LIVE_ARKIME = ConfigItem(
    key=KEY_CONFIG_ITEM_LIVE_ARKIME,
    label="Arkime Live Traffic Capture",
    default_value=False,
    validator=lambda x: isinstance(x, bool),
    question=f"Capture live network traffic with Arkime capture (not available with --opensearch {DATABASE_MODE_LABELS[DatabaseMode.OpenSearchLocal]})",
    widget_type=WidgetType.CHECKBOX,
)

# Default value handled in MalcolmConfig based on LIVE_ARKIME and PCAP_NODE_NAME
CONFIG_ITEM_LIVE_ARKIME_NODE_HOST = ConfigItem(
    key=KEY_CONFIG_ITEM_LIVE_ARKIME_NODE_HOST,
    label="Arkime Node Host",
    default_value=get_hostname_without_domain(),
    validator=lambda x: isinstance(x, str),
    question=f"The node hostname or IP address to associate with live network traffic observed by Arkime capture",
    widget_type=WidgetType.TEXT,
)

CONFIG_ITEM_PCAP_NET_SNIFF = ConfigItem(
    key=KEY_CONFIG_ITEM_PCAP_NET_SNIFF,
    label="Netsniff-ng Live Traffic Capture",
    default_value=False,
    validator=lambda x: isinstance(x, bool),
    question=f"Capture live network traffic with netsniff-ng for Arkime",
    widget_type=WidgetType.CHECKBOX,
)

CONFIG_ITEM_PCAP_TCP_DUMP = ConfigItem(
    key=KEY_CONFIG_ITEM_PCAP_TCP_DUMP,
    label="Tcpdump Live Traffic Capture",
    default_value=False,
    validator=lambda x: isinstance(x, bool),
    question=f"Capture live network traffic with tcpdump for Arkime",
    widget_type=WidgetType.CHECKBOX,
)

CONFIG_ITEM_LIVE_ZEEK = ConfigItem(
    key=KEY_CONFIG_ITEM_LIVE_ZEEK,
    label="Zeek Live Traffic Capture",
    default_value=False,
    validator=lambda x: isinstance(x, bool),
    question=f"Capture live network traffic with Zeek",
    widget_type=WidgetType.CHECKBOX,
)

CONFIG_ITEM_LIVE_SURICATA = ConfigItem(
    key=KEY_CONFIG_ITEM_LIVE_SURICATA,
    label="Suricata Live Traffic Capture",
    default_value=False,
    validator=lambda x: isinstance(x, bool),
    question=f"Capture live network traffic with Suricata",
    widget_type=WidgetType.CHECKBOX,
)

CONFIG_ITEM_PCAP_NODE_NAME = ConfigItem(
    key=KEY_CONFIG_ITEM_PCAP_NODE_NAME,
    label="Network Traffic Metadata Node Name",
    default_value=get_hostname_without_domain(),
    validator=lambda x: isinstance(x, str),
    question=f"The node name to associate with network traffic metadata",
    widget_type=WidgetType.TEXT,
)


def get_capture_config_item_dict():
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
ALL_CAPTURE_CONFIG_ITEMS_DICT = get_capture_config_item_dict()

if __name__ == "__main__":
    # print(globals().items())
    print(ALL_CAPTURE_CONFIG_ITEMS_DICT.keys())
