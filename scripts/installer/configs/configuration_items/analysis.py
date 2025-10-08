#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2025 Battelle Energy Alliance, LLC.  All rights reserved.

"""
Analysis configuration items for Malcolm installer.

This module contains all configuration items related to traffic analysis settings,
including Zeek analysis, Suricata analysis, and file extraction configuration.
"""

from scripts.malcolm_constants import WidgetType
from scripts.malcolm_utils import str2bool as str_to_bool

from scripts.installer.core.config_item import ConfigItem
from scripts.installer.configs.constants.config_env_var_keys import *
from scripts.installer.configs.constants.configuration_item_keys import (
    KEY_CONFIG_ITEM_AUTO_ZEEK,
    KEY_CONFIG_ITEM_AUTO_SURICATA,
    KEY_CONFIG_ITEM_AUTO_ARKIME,
    KEY_CONFIG_ITEM_SURICATA_RULE_UPDATE,
    KEY_CONFIG_ITEM_MALCOLM_ICS,
    KEY_CONFIG_ITEM_ZEEK_ICS_BEST_GUESS,
    KEY_CONFIG_ITEM_REVERSE_DNS,
    KEY_CONFIG_ITEM_AUTO_OUI,
    KEY_CONFIG_ITEM_AUTO_FREQ,
)

CONFIG_ITEM_ZEEK_AUTO_ANALYZE_PCAP_FILES = ConfigItem(
    key=KEY_CONFIG_ITEM_AUTO_ZEEK,
    label="Enable Zeek Analysis",
    default_value=True,
    validator=lambda x: isinstance(x, bool),
    question=f"Automatically analyze all PCAP files with Zeek?",
    widget_type=WidgetType.CHECKBOX,
)

CONFIG_ITEM_SURICATA_AUTO_ANALYZE_PCAP_FILES = ConfigItem(
    key=KEY_CONFIG_ITEM_AUTO_SURICATA,
    label="Enable Suricata Analysis",
    default_value=True,
    validator=lambda x: isinstance(x, bool),
    question=f"Automatically analyze all PCAP files with Suricata?",
    widget_type=WidgetType.CHECKBOX,
)

CONFIG_ITEM_ARKIME_AUTO_ANALYZE_PCAP_FILES = ConfigItem(
    key=KEY_CONFIG_ITEM_AUTO_ARKIME,
    label="Enable Arkime Analysis",
    default_value=True,
    validator=lambda x: isinstance(x, bool),
    question=f"Automatically analyze all PCAP files with Arkime?",
    widget_type=WidgetType.CHECKBOX,
)

CONFIG_ITEM_SURICATA_UPDATE_RULES = ConfigItem(
    key=KEY_CONFIG_ITEM_SURICATA_RULE_UPDATE,
    label="Enable Suricata Rule Updates",
    default_value=False,
    validator=lambda x: isinstance(x, bool),
    question=f"Download updated Suricata signatures periodically?",
    widget_type=WidgetType.CHECKBOX,
)

CONFIG_ITEM_ZEEK_DISABLE_ICS_ALL = ConfigItem(
    key=KEY_CONFIG_ITEM_MALCOLM_ICS,
    label="Enable Zeek ICS/OT Monitoring",
    default_value=False,
    validator=lambda x: isinstance(x, bool),
    question=f"Is Malcolm being used to monitor an Operational Technology/Industrial Control Systems (OT/ICS) network?",
    widget_type=WidgetType.CHECKBOX,
)

CONFIG_ITEM_ZEEK_DISABLE_BEST_GUESS_ICS = ConfigItem(
    key=KEY_CONFIG_ITEM_ZEEK_ICS_BEST_GUESS,
    label="Enable Zeek ICS Best Guess Mode",
    default_value=True,
    validator=lambda x: isinstance(x, bool),
    question=f'Should Malcolm use "best guess" to identify potential OT/ICS traffic with Zeek?',
    widget_type=WidgetType.CHECKBOX,
)

CONFIG_ITEM_LOGSTASH_REVERSE_DNS = ConfigItem(
    key=KEY_CONFIG_ITEM_REVERSE_DNS,
    label="Enable Reverse DNS Lookups",
    default_value=False,
    validator=lambda x: isinstance(x, bool),
    question=f"Perform reverse DNS lookup locally for source and destination IP addresses in logs?",
    widget_type=WidgetType.CHECKBOX,
)

CONFIG_ITEM_LOGSTASH_OUI_LOOKUP = ConfigItem(
    key=KEY_CONFIG_ITEM_AUTO_OUI,
    label="Enable OUI Lookups",
    default_value=True,
    validator=lambda x: isinstance(x, bool),
    question=f"Perform hardware vendor OUI lookups for MAC addresses",
    widget_type=WidgetType.CHECKBOX,
)

CONFIG_ITEM_FREQ_LOOKUP = ConfigItem(
    key=KEY_CONFIG_ITEM_AUTO_FREQ,
    label="Enable Frequency Scoring",
    default_value=True,
    validator=lambda x: isinstance(x, bool),
    question=f"Perform string randomness scoring on some fields?",
    widget_type=WidgetType.CHECKBOX,
)


def get_analysis_config_item_dict():
    """Get all ConfigItem objects from this module.

    Returns:
        Dict mapping configuration key strings to their ConfigItem objects
    """
    config_items = {}
    # Iterate over globals to find all defined ConfigItem objects in this module
    for _, key_value in globals().items():
        # Check if this is a ConfigItem object with a name that starts with CONFIG_ITEM_
        if isinstance(key_value, ConfigItem):
            # Store the entire ConfigItem object with its key as the dictionary key
            config_items[key_value.key] = key_value
    return config_items


# A dictionary mapping configuration keys to their ConfigItem objects, created once at module load.
ALL_ANALYSIS_CONFIG_ITEMS_DICT = get_analysis_config_item_dict()

if __name__ == "__main__":
    # print(globals().items())
    print(ALL_ANALYSIS_CONFIG_ITEMS_DICT.keys())
