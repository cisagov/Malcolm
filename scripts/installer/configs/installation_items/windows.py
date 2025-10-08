#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2025 Battelle Energy Alliance, LLC.  All rights reserved.

"""
Windows-specific installation configuration items for Malcolm installer.

This module contains all configuration items related to the installation process
that are specific to Windows platforms.
"""

from scripts.installer.core.config_item import ConfigItem

# TODO: Add Windows-specific installation ConfigItems here


def get_windows_installation_config_item_dict():
    """Get all Windows-specific installation ConfigItem objects from this module.

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
ALL_WINDOWS_INSTALLATION_CONFIG_ITEMS_DICT = get_windows_installation_config_item_dict()

if __name__ == "__main__":
    print("Windows installation config items:")
    print(list(ALL_WINDOWS_INSTALLATION_CONFIG_ITEMS_DICT.keys()))
