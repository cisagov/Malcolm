#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2025 Battelle Energy Alliance, LLC.  All rights reserved.

"""Threat intelligence configuration items for Malcolm installer.

This module contains all configuration items related to threat intelligence feeds,
including Zeek intelligence feed configuration and update settings.
"""

from typing import Any, Tuple

from scripts.malcolm_constants import WidgetType
from scripts.malcolm_utils import str2bool as str_to_bool

from scripts.installer.core.config_item import ConfigItem
from scripts.installer.configs.constants.configuration_item_keys import (
    KEY_CONFIG_ITEM_ZEEK_PULL_INTELLIGENCE_FEEDS,
    KEY_CONFIG_ITEM_ZEEK_INTEL_ON_STARTUP,
    KEY_CONFIG_ITEM_ZEEK_INTEL_FEED_SINCE,
    KEY_CONFIG_ITEM_ZEEK_INTEL_CRON_EXPRESSION,
    KEY_CONFIG_ITEM_ZEEK_INTEL_ITEM_EXPIRATION,
)

CONFIG_ITEM_ZEEK_PULL_INTELLIGENCE_FEEDS = ConfigItem(
    key=KEY_CONFIG_ITEM_ZEEK_PULL_INTELLIGENCE_FEEDS,
    label="Zeek Pull Intelligence Feeds",
    default_value=True,
    validator=lambda x: isinstance(x, bool),
    question=f"Pull from threat intelligence feeds on container startup",
    widget_type=WidgetType.CHECKBOX,
)

CONFIG_ITEM_ZEEK_INTEL_ON_STARTUP = ConfigItem(
    key=KEY_CONFIG_ITEM_ZEEK_INTEL_ON_STARTUP,
    label="Pull Threat Intelligence Feeds on Startup",
    default_value=True,
    validator=lambda x: isinstance(x, bool),
    question=f"Pull from threat intelligence feeds on container startup",
    widget_type=WidgetType.CHECKBOX,
)

CONFIG_ITEM_ZEEK_INTEL_FEED_SINCE = ConfigItem(
    key=KEY_CONFIG_ITEM_ZEEK_INTEL_FEED_SINCE,
    label='Threat Indicator "Since" Period',
    default_value="7 days ago",
    validator=lambda x: isinstance(x, str),
    question=f"When pulling from threat intelligence feeds, only process indicators created or modified since this time",
    widget_type=WidgetType.TEXT,
)

CONFIG_ITEM_ZEEK_INTEL_CRON_EXPRESSION = ConfigItem(
    key=KEY_CONFIG_ITEM_ZEEK_INTEL_CRON_EXPRESSION,
    label="Threat Intel Cron Expression",
    default_value="0 0 * * *",
    validator=lambda x: isinstance(x, str),
    question=f"Cron expression for scheduled pulls from threat intelligence feeds",
    widget_type=WidgetType.TEXT,
)

CONFIG_ITEM_ZEEK_INTEL_ITEM_EXPIRATION = ConfigItem(
    key=KEY_CONFIG_ITEM_ZEEK_INTEL_ITEM_EXPIRATION,
    label="Zeek's Intel::item_expiration timeout",
    default_value="-1min",
    validator=lambda x: isinstance(x, str),
    question=f"Specifies the value for Zeek's Intel::item_expiration timeout (-1min to disable)",
    widget_type=WidgetType.TEXT,
)


def get_zeek_intel_config_item_dict():
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
ALL_ZEEK_INTEL_CONFIG_ITEMS_DICT = get_zeek_intel_config_item_dict()

if __name__ == "__main__":
    # print(globals().items())
    print(ALL_ZEEK_INTEL_CONFIG_ITEMS_DICT.keys())
