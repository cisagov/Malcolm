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
from scripts.malcolm_common import SYSTEM_INFO
from scripts.malcolm_utils import isipaddress

from scripts.installer.configs.constants.enums import ContainerRuntime
from scripts.installer.core.config_item import ConfigItem, ListOfStringsConfigItem
from scripts.installer.configs.constants.configuration_item_keys import (
    KEY_CONFIG_ITEM_DASHBOARDS_DARK_MODE,
    KEY_CONFIG_ITEM_IMAGE_ARCH,
    KEY_CONFIG_ITEM_MALCOLM_PROFILE,
    KEY_CONFIG_ITEM_RUNTIME_BIN,
    # these ones are ONLY visible/used in the "Malcolm ISO Installed" environment
    KEY_CONFIG_ITEM_REACHBACK_REQUEST_ACL,
    KEY_CONFIG_ITEM_AUX_FW_AIDE,
    KEY_CONFIG_ITEM_AUX_FW_AUDITLOG,
    KEY_CONFIG_ITEM_AUX_FW_CPU,
    KEY_CONFIG_ITEM_AUX_FW_DF,
    KEY_CONFIG_ITEM_AUX_FW_DISK,
    KEY_CONFIG_ITEM_AUX_FW_KMSG,
    KEY_CONFIG_ITEM_AUX_FW_MEM,
    KEY_CONFIG_ITEM_AUX_FW_NETWORK,
    KEY_CONFIG_ITEM_AUX_FW_SYSTEMD,
    KEY_CONFIG_ITEM_AUX_FW_THERMAL,
)

CONFIG_ITEM_RUNTIME_BIN = ConfigItem(
    key=KEY_CONFIG_ITEM_RUNTIME_BIN,
    label="Container Runtime",
    default_value=os.getenv("MALCOLM_CONTAINER_RUNTIME", "docker"),
    choices=[x.value for x in ContainerRuntime],
    validator=lambda x: isinstance(x, str) and x in [v.value for v in ContainerRuntime],
    question="Select container runtime",
    widget_type=WidgetType.SELECT,
)

CONFIG_ITEM_MALCOLM_PROFILE = ConfigItem(
    key=KEY_CONFIG_ITEM_MALCOLM_PROFILE,
    label="Run Profile",
    default_value=PROFILE_MALCOLM,
    choices=[PROFILE_MALCOLM, PROFILE_HEDGEHOG],
    validator=lambda x: x in [PROFILE_MALCOLM, PROFILE_HEDGEHOG],
    question='Select the run profile: full Malcolm suite or capture-only ("Hedgehog mode")',
    widget_type=WidgetType.SELECT,
)

CONFIG_ITEM_DASHBOARDS_DARK_MODE = ConfigItem(
    key=KEY_CONFIG_ITEM_DASHBOARDS_DARK_MODE,
    label="Dark Mode for Dashboards",
    default_value=True,
    validator=lambda x: isinstance(x, bool),
    question="Enable dark mode for OpenSearch Dashboards?",
    widget_type=WidgetType.CHECKBOX,
)

_arch_default = SYSTEM_INFO.get("image_architecture", ImageArchitecture.AMD64)
CONFIG_ITEM_IMAGE_ARCH = ConfigItem(
    key=KEY_CONFIG_ITEM_IMAGE_ARCH,
    label="Image Architecture",
    # normalize enum default to its label value for consistent validation/prompting
    default_value=(_arch_default.value if isinstance(_arch_default, ImageArchitecture) else _arch_default),
    choices=[x.value for x in ImageArchitecture],
    validator=lambda x: isinstance(x, str) and x in [v.value for v in ImageArchitecture],
    question="Select architecture for container images (amd64 or arm64)",
    widget_type=WidgetType.SELECT,
)

CONFIG_ITEM_REACHBACK_REQUEST_ACL = ListOfStringsConfigItem(
    key=KEY_CONFIG_ITEM_REACHBACK_REQUEST_ACL,
    label="Malcolm Reachback ACL",
    default_value=[],
    accept_blank=True,
    validator=lambda x: (isinstance(x, list) and all(isinstance(addr, str) and isipaddress(addr) for addr in x)),
    question="Comma-separated list of IP addresses for ACL for artifact reachback from Malcolm",
    widget_type=WidgetType.TEXT,
)

CONFIG_ITEM_AUX_FW_AIDE = ConfigItem(
    key=KEY_CONFIG_ITEM_AUX_FW_AIDE,
    label="Forward AIDE Results",
    default_value=False,
    validator=lambda x: isinstance(x, bool),
    question="Forward AIDE file system integrity check results?",
    widget_type=WidgetType.CHECKBOX,
)

CONFIG_ITEM_AUX_FW_AUDITLOG = ConfigItem(
    key=KEY_CONFIG_ITEM_AUX_FW_AUDITLOG,
    label="Forward Audit Log",
    default_value=False,
    validator=lambda x: isinstance(x, bool),
    question="Forward audit logs?",
    widget_type=WidgetType.CHECKBOX,
)

CONFIG_ITEM_AUX_FW_CPU = ConfigItem(
    key=KEY_CONFIG_ITEM_AUX_FW_CPU,
    label="Forward CPU Utilization",
    default_value=False,
    validator=lambda x: isinstance(x, bool),
    question="Forward CPU utilization statistics?",
    widget_type=WidgetType.CHECKBOX,
)

CONFIG_ITEM_AUX_FW_DF = ConfigItem(
    key=KEY_CONFIG_ITEM_AUX_FW_DF,
    label="Forward Disk Utilization",
    default_value=False,
    validator=lambda x: isinstance(x, bool),
    question="Forward disk utilization statistics?",
    widget_type=WidgetType.CHECKBOX,
)

CONFIG_ITEM_AUX_FW_DISK = ConfigItem(
    key=KEY_CONFIG_ITEM_AUX_FW_DISK,
    label="Forward Disk Operation Statistics",
    default_value=False,
    validator=lambda x: isinstance(x, bool),
    question="Forward disk operation statistics?",
    widget_type=WidgetType.CHECKBOX,
)

CONFIG_ITEM_AUX_FW_KMSG = ConfigItem(
    key=KEY_CONFIG_ITEM_AUX_FW_KMSG,
    label="Forward Kernel Messages",
    default_value=False,
    validator=lambda x: isinstance(x, bool),
    question="Forward kernel messages?",
    widget_type=WidgetType.CHECKBOX,
)

CONFIG_ITEM_AUX_FW_MEM = ConfigItem(
    key=KEY_CONFIG_ITEM_AUX_FW_MEM,
    label="Forward Memory Utilization",
    default_value=False,
    validator=lambda x: isinstance(x, bool),
    question="Forward memory utilization statistics?",
    widget_type=WidgetType.CHECKBOX,
)

CONFIG_ITEM_AUX_FW_NETWORK = ConfigItem(
    key=KEY_CONFIG_ITEM_AUX_FW_NETWORK,
    label="Forward Network Activity",
    default_value=False,
    validator=lambda x: isinstance(x, bool),
    question="Forward network activity statistics?",
    widget_type=WidgetType.CHECKBOX,
)

CONFIG_ITEM_AUX_FW_SYSTEMD = ConfigItem(
    key=KEY_CONFIG_ITEM_AUX_FW_SYSTEMD,
    label="Forward Systemd Journal Logs",
    default_value=False,
    validator=lambda x: isinstance(x, bool),
    question="Forward systemd journal logs?",
    widget_type=WidgetType.CHECKBOX,
)

CONFIG_ITEM_AUX_FW_THERMAL = ConfigItem(
    key=KEY_CONFIG_ITEM_AUX_FW_THERMAL,
    label="Forward Thermal Readings",
    default_value=False,
    validator=lambda x: isinstance(x, bool),
    question="Forward thermal readings?",
    widget_type=WidgetType.CHECKBOX,
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
