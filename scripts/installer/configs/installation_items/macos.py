#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2025 Battelle Energy Alliance, LLC.  All rights reserved.

"""
macOS-specific installation configuration items for Malcolm installer.

This module contains all configuration items related to the installation process
that are specific to macOS platforms, including Homebrew usage and macOS-specific
system configuration options.
"""

from scripts.installer.core.config_item import ConfigItem
from scripts.installer.configs.constants.installation_item_keys import (
    KEY_INSTALLATION_ITEM_CONFIGURE_DOCKER_RESOURCES,
    KEY_INSTALLATION_ITEM_INSTALL_DOCKER_IF_MISSING,
    KEY_INSTALLATION_ITEM_USE_HOMEBREW,
)
from scripts.malcolm_constants import WidgetType

CONFIG_ITEM_USE_HOMEBREW = ConfigItem(
    key=KEY_INSTALLATION_ITEM_USE_HOMEBREW,
    label="Use Homebrew",
    default_value=True,
    validator=lambda x: isinstance(x, bool),
    question="Use Homebrew for package installation on macOS?",
    widget_type=WidgetType.CHECKBOX,
)

CONFIG_ITEM_INSTALL_DOCKER_IF_MISSING_MACOS = ConfigItem(
    key=KEY_INSTALLATION_ITEM_INSTALL_DOCKER_IF_MISSING,
    label="Install Docker",
    default_value=True,
    validator=lambda x: isinstance(x, bool),
    question='"docker info" failed, attempt to install Docker?',
    widget_type=WidgetType.CHECKBOX,
    metadata={
        "visible_when_runtime": "docker",
    },
)

CONFIG_ITEM_CONFIGURE_DOCKER_RESOURCES = ConfigItem(
    key=KEY_INSTALLATION_ITEM_CONFIGURE_DOCKER_RESOURCES,
    label="Configure Docker Resources",
    default_value=True,
    validator=lambda x: isinstance(x, bool),
    question="Configure Docker resource usage in settings file?",
    widget_type=WidgetType.CHECKBOX,
    metadata={
        "visible_when_runtime": "docker",
    },
)


def get_macos_installation_config_item_dict():
    """Get all macOS-specific installation ConfigItem objects from this module.

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
ALL_MACOS_INSTALLATION_CONFIG_ITEMS_DICT = get_macos_installation_config_item_dict()

if __name__ == "__main__":
    print("macOS installation config items:")
    print(list(ALL_MACOS_INSTALLATION_CONFIG_ITEMS_DICT.keys()))
