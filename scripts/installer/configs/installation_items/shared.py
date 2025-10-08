#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2025 Battelle Energy Alliance, LLC.  All rights reserved.

"""
Cross-platform installation configuration items for Malcolm installer.

This module contains all configuration items related to the installation process
that are shared across all platforms (Linux, macOS, Windows).
"""

import os
from scripts.malcolm_constants import WidgetType
from scripts.malcolm_utils import str2bool

from scripts.installer.core.config_item import ConfigItem
from scripts.installer.configs.constants.installation_item_keys import (
    KEY_INSTALLATION_ITEM_AUTO_TWEAKS,
    KEY_INSTALLATION_ITEM_INSTALLATION_PATH,
    KEY_INSTALLATION_ITEM_LOAD_MALCOLM_IMAGES,
    KEY_INSTALLATION_ITEM_PULL_MALCOLM_IMAGES,
    KEY_INSTALLATION_ITEM_APPLY_MEMORY_SETTINGS,
)

CONFIG_ITEM_AUTO_TWEAKS = ConfigItem(
    key=KEY_INSTALLATION_ITEM_AUTO_TWEAKS,
    label="Automatically Apply System Tweaks",
    default_value=True,
    validator=lambda x: isinstance(x, bool),
    question=f"Apply recommended system tweaks automatically without asking for confirmation?",
    widget_type=WidgetType.CHECKBOX,
)

CONFIG_ITEM_INSTALLATION_PATH = ConfigItem(
    key=KEY_INSTALLATION_ITEM_INSTALLATION_PATH,
    label="Malcolm Installation Path",
    default_value=os.path.join(os.getcwd(), "malcolm"),
    validator=lambda x: isinstance(x, str) and len(x.strip()) > 0,
    question=f"Directory path where Malcolm will be installed?",
    widget_type=WidgetType.TEXT,
)

CONFIG_ITEM_LOAD_MALCOLM_IMAGES = ConfigItem(
    key=KEY_INSTALLATION_ITEM_LOAD_MALCOLM_IMAGES,
    label="Load Malcolm Images From Provided Image File",
    default_value=False,
    validator=lambda x: isinstance(x, bool),
    question=f"Load Malcolm container images from provided image file?",
    widget_type=WidgetType.CHECKBOX,
)

CONFIG_ITEM_PULL_MALCOLM_IMAGES = ConfigItem(
    key=KEY_INSTALLATION_ITEM_PULL_MALCOLM_IMAGES,
    label="Pull Malcolm Images From Registry",
    default_value=False,
    validator=lambda x: isinstance(x, bool),
    question=f"Pull Malcolm container images from registry?",
    widget_type=WidgetType.CHECKBOX,
)

CONFIG_ITEM_APPLY_MEMORY_SETTINGS = ConfigItem(
    key=KEY_INSTALLATION_ITEM_APPLY_MEMORY_SETTINGS,
    label="Apply Memory Settings For Opensearch and Logstash",
    default_value=True,
    validator=lambda x: isinstance(x, bool),
    question=f"Apply calculated memory and worker settings for OpenSearch and Logstash?",
    widget_type=WidgetType.CHECKBOX,
)


def get_shared_installation_config_item_dict():
    """Get all shared installation ConfigItem objects from this module.

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
ALL_SHARED_INSTALLATION_CONFIG_ITEMS_DICT = get_shared_installation_config_item_dict()

if __name__ == "__main__":
    print("Shared installation config items:")
    print(list(ALL_SHARED_INSTALLATION_CONFIG_ITEMS_DICT.keys()))
