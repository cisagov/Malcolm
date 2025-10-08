#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2025 Battelle Energy Alliance, LLC.  All rights reserved.

"""Filebeat configuration items for Malcolm installer.

This module contains all configuration items related to Filebeat settings, including TCP listener options.
"""

from scripts.malcolm_constants import WidgetType
from scripts.malcolm_utils import str2bool as str_to_bool
from scripts.installer.core.config_item import ConfigItem

from scripts.installer.configs.constants.enums import FilebeatLogFormat
from scripts.installer.configs.constants.configuration_item_keys import (
    KEY_CONFIG_ITEM_EXPOSE_FILEBEAT_TCP,
    KEY_CONFIG_ITEM_FILEBEAT_TCP_LOG_FORMAT,
    KEY_CONFIG_ITEM_FILEBEAT_TCP_PARSE_SOURCE_FIELD,
    KEY_CONFIG_ITEM_FILEBEAT_TCP_PARSE_TARGET_FIELD,
    KEY_CONFIG_ITEM_FILEBEAT_TCP_PARSE_DROP_FIELD,
    KEY_CONFIG_ITEM_FILEBEAT_TCP_TAG,
    KEY_CONFIG_ITEM_FILEBEAT_TCP_OPEN,
)


CONFIG_ITEM_FILEBEAT_TCP_LISTEN = ConfigItem(
    key=KEY_CONFIG_ITEM_FILEBEAT_TCP_OPEN,
    label="Use Default Filebeat TCP Listener Settings",
    default_value=True,
    validator=lambda x: isinstance(x, bool),
    question=f"Use default field values for Filebeat TCP listener?",
    widget_type=WidgetType.CHECKBOX,
)

CONFIG_ITEM_EXPOSE_FILEBEAT_TCP = ConfigItem(
    key=KEY_CONFIG_ITEM_EXPOSE_FILEBEAT_TCP,
    label="Expose Filebeat TCP Listener",
    default_value=False,
    validator=lambda x: isinstance(x, bool),
    question=f"Expose a Filebeat TCP input listener for log ingestion.",
    widget_type=WidgetType.CHECKBOX,
)

# Filebeat TCP log format
CONFIG_ITEM_FILEBEAT_TCP_LOG_FORMAT = ConfigItem(
    key=KEY_CONFIG_ITEM_FILEBEAT_TCP_LOG_FORMAT,
    label="Filebeat TCP Log Format",
    default_value="json",
    choices=[x.value for x in FilebeatLogFormat],
    validator=lambda x: isinstance(x, str)
    and x in [v.value for v in FilebeatLogFormat],
    question=f"Select log format for messages sent to Filebeat TCP listener",
    widget_type=WidgetType.SELECT,
)

# Default value handled in MalcolmConfig based on FILEBEAT_TCP_LOG_FORMAT
CONFIG_ITEM_FILEBEAT_TCP_PARSE_SOURCE_FIELD = ConfigItem(
    key=KEY_CONFIG_ITEM_FILEBEAT_TCP_PARSE_SOURCE_FIELD,
    label="Filebeat TCP Source Field",
    default_value=None,
    validator=lambda x: isinstance(x, str),
    question=f"Source field name to parse for events sent to the Filebeat TCP input listener:",
    widget_type=WidgetType.TEXT,
)

# Default value handled in MalcolmConfig based on FILEBEAT_TCP_LOG_FORMAT
CONFIG_ITEM_FILEBEAT_TCP_PARSE_TARGET_FIELD = ConfigItem(
    key=KEY_CONFIG_ITEM_FILEBEAT_TCP_PARSE_TARGET_FIELD,
    label="Filebeat TCP Target Field",
    default_value=None,
    validator=lambda x: isinstance(x, str),
    question=f"Target field name to store decoded JSON fields for events sent to the Filebeat TCP input listener:",
    widget_type=WidgetType.TEXT,
)

# Default value handled in MalcolmConfig based on FILEBEAT_TCP_LOG_FORMAT
CONFIG_ITEM_FILEBEAT_TCP_PARSE_DROP_FIELD = ConfigItem(
    key=KEY_CONFIG_ITEM_FILEBEAT_TCP_PARSE_DROP_FIELD,
    label="Filebeat TCP Drop Field",
    default_value=None,
    validator=lambda x: isinstance(x, str),
    question=f"Field to drop in events sent to the Filebeat TCP input listener.",
    widget_type=WidgetType.TEXT,
)

CONFIG_ITEM_FILEBEAT_TCP_TAG = ConfigItem(
    key=KEY_CONFIG_ITEM_FILEBEAT_TCP_TAG,
    label="Filebeat TCP Tag",
    default_value="_malcolm_beats",
    validator=lambda x: isinstance(x, str),
    question=f"Tag to append to events sent to the Filebeat TCP input listener.",
    widget_type=WidgetType.TEXT,
)


def get_filebeat_config_item_dict():
    """Get all ConfigItem objects from this module.
    Returns:
        Dict mapping configuration key strings to their ConfigItem objects
    """
    config_items = {}
    for key_name, key_value in globals().items():
        if isinstance(key_value, ConfigItem):
            config_items[key_value.key] = key_value
    return config_items


ALL_FILEBEAT_CONFIG_ITEMS_DICT = get_filebeat_config_item_dict()
