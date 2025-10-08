#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2025 Battelle Energy Alliance, LLC.  All rights reserved.

"""Runtime configuration items for Malcolm installer.

This module contains all configuration items related to runtime settings,
including container runtime, profiles, and UI preferences.
"""

import os

from scripts.malcolm_constants import (
    PROFILE_HEDGEHOG,
    PROFILE_MALCOLM,
    ImageArchitecture,
    WidgetType,
)
from scripts.malcolm_utils import SYSTEM_INFO

from scripts.installer.configs.constants.enums import ContainerRuntime
from scripts.installer.core.config_item import ConfigItem
from scripts.installer.configs.constants.configuration_item_keys import (
    KEY_CONFIG_ITEM_RUNTIME_BIN,
    KEY_CONFIG_ITEM_MALCOLM_PROFILE,
    KEY_CONFIG_ITEM_DASHBOARDS_DARK_MODE,
    KEY_CONFIG_ITEM_IMAGE_ARCH,
)

CONFIG_ITEM_RUNTIME_BIN = ConfigItem(
    key=KEY_CONFIG_ITEM_RUNTIME_BIN,
    label="Container Runtime",
    default_value=os.getenv("MALCOLM_CONTAINER_RUNTIME", "docker"),
    choices=[x.value for x in ContainerRuntime],
    validator=lambda x: isinstance(x, str) and x in [v.value for v in ContainerRuntime],
    question=f"Select container runtime binary:",
    widget_type=WidgetType.SELECT,
)

CONFIG_ITEM_MALCOLM_PROFILE = ConfigItem(
    key=KEY_CONFIG_ITEM_MALCOLM_PROFILE,
    label="Malcolm Profile",
    default_value=PROFILE_MALCOLM,
    choices=[PROFILE_MALCOLM, PROFILE_HEDGEHOG],
    validator=lambda x: x in [PROFILE_MALCOLM, PROFILE_HEDGEHOG],
    question=f"Select the installation profile: a full Malcolm suite or a capture-only sensor (Hedgehog).",
    widget_type=WidgetType.SELECT,
)

CONFIG_ITEM_DASHBOARDS_DARK_MODE = ConfigItem(
    key=KEY_CONFIG_ITEM_DASHBOARDS_DARK_MODE,
    label="Dark Mode for Dashboards",
    default_value=True,
    validator=lambda x: isinstance(x, bool),
    question=f"Enable dark mode for OpenSearch Dashboards",
    widget_type=WidgetType.CHECKBOX,
)

_arch_default = SYSTEM_INFO.get("image_architecture", ImageArchitecture.AMD64)
CONFIG_ITEM_IMAGE_ARCH = ConfigItem(
    key=KEY_CONFIG_ITEM_IMAGE_ARCH,
    label="Image Architecture",
    # normalize enum default to its label value for consistent validation/prompting
    default_value=(
        _arch_default.value
        if isinstance(_arch_default, ImageArchitecture)
        else _arch_default
    ),
    choices=[x.value for x in ImageArchitecture],
    validator=lambda x: isinstance(x, str)
    and x in [v.value for v in ImageArchitecture],
    question=f"Architecture for container image (amd64 or arm64)",
    widget_type=WidgetType.SELECT,
)


def get_runtime_config_item_dict():
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
ALL_RUNTIME_CONFIG_ITEMS_DICT = get_runtime_config_item_dict()

if __name__ == "__main__":
    # print(globals().items())
    print(ALL_RUNTIME_CONFIG_ITEMS_DICT.keys())
