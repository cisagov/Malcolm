#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2025 Battelle Energy Alliance, LLC.  All rights reserved.

"""
Cross-platform installation configuration items for Malcolm installer.

This module contains all configuration items related to the installation process
that are shared across all platforms (Linux, macOS, Windows).
"""

from scripts.malcolm_constants import WidgetType
from scripts.installer.core.config_item import ConfigItem
from scripts.installer.configs.constants.installation_item_keys import (
    KEY_INSTALLATION_ITEM_AUTO_TWEAKS,
    KEY_INSTALLATION_ITEM_LOAD_MALCOLM_IMAGES,
    KEY_INSTALLATION_ITEM_PULL_MALCOLM_IMAGES,
)

CONFIG_ITEM_AUTO_TWEAKS = ConfigItem(
    key=KEY_INSTALLATION_ITEM_AUTO_TWEAKS,
    label="Automatically Apply System Tweaks",
    default_value=True,
    validator=lambda x: isinstance(x, bool),
    question="Apply recommended system tweaks automatically without confirmation?",
    widget_type=WidgetType.CHECKBOX,
)

CONFIG_ITEM_LOAD_MALCOLM_IMAGES = ConfigItem(
    key=KEY_INSTALLATION_ITEM_LOAD_MALCOLM_IMAGES,
    label="Load Malcolm Images From Provided Image File",
    default_value=False,
    validator=lambda x: isinstance(x, bool),
    question="Load Malcolm container images from provided image file?",
    widget_type=WidgetType.CHECKBOX,
)

CONFIG_ITEM_PULL_MALCOLM_IMAGES = ConfigItem(
    key=KEY_INSTALLATION_ITEM_PULL_MALCOLM_IMAGES,
    label="Pull Malcolm Images",
    default_value=False,
    validator=lambda x: isinstance(x, bool),
    question="Pull Malcolm images from container registry?",
    widget_type=WidgetType.CHECKBOX,
    metadata={
        "visible_when_runtime": "docker",
    },
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
