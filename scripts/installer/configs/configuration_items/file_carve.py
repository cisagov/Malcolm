#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2026 Battelle Energy Alliance, LLC.  All rights reserved.

"""File carve configuration items for Malcolm installer.

This module contains all configuration items related to file carve settings,
including file extraction and preservation configuration.
"""

from typing import Tuple


from scripts.installer.core.config_item import ConfigItem
from scripts.installer.configs.constants.enums import (
    FileExtractionMode,
    FilePreservationMode,
)
from scripts.malcolm_constants import WidgetType
from scripts.installer.configs.constants.configuration_item_keys import (
    KEY_CONFIG_ITEM_PIPELINE_ENABLED,
    KEY_CONFIG_ITEM_PIPELINE_WORKERS,
    KEY_CONFIG_ITEM_FILE_CARVE_HTTP_SERVE_ENCRYPT_KEY,
    KEY_CONFIG_ITEM_FILE_CARVE_HTTP_SERVER,
    KEY_CONFIG_ITEM_FILE_CARVE_HTTP_SERVER_ZIP,
    KEY_CONFIG_ITEM_FILE_CARVE_MODE,
    KEY_CONFIG_ITEM_FILE_PRESERVE_MODE,
    KEY_CONFIG_ITEM_FILE_SCAN_RULE_UPDATE,
)


def validate_file_extraction_mode(value: str) -> Tuple[bool, str]:
    """Validate file extraction mode selection.

    Args:
        value: File extraction mode to validate

    Returns:
        Tuple of (is_valid, error_message)
    """
    valid_modes = ["none", "known", "mapped", "all", "interesting", "notcommtxt"]
    if value not in valid_modes:
        return False, f"File extraction mode must be one of: {', '.join(valid_modes)}"
    return True, ""


def validate_file_preservation(value: str) -> Tuple[bool, str]:
    """Validate file preservation mode selection.

    Args:
        value: File preservation mode to validate

    Returns:
        Tuple of (is_valid, error_message)
    """
    valid_modes = ["quarantined", "all", "none"]
    if value not in valid_modes:
        return False, f"File preservation mode must be one of: {', '.join(valid_modes)}"
    return True, ""


# File Extraction Configuration
CONFIG_ITEM_FILE_EXTRACTION_MODE = ConfigItem(
    key=KEY_CONFIG_ITEM_FILE_CARVE_MODE,
    label="File Extraction Mode",
    default_value="none",
    choices=[x.value for x in FileExtractionMode],
    validator=lambda x: isinstance(x, str) and x in [v.value for v in FileExtractionMode],
    question="Select which files Zeek should extract from network traffic",
    widget_type=WidgetType.SELECT,
)

CONFIG_ITEM_FILE_PRESERVATION = ConfigItem(
    key=KEY_CONFIG_ITEM_FILE_PRESERVE_MODE,
    label="File Preservation",
    default_value="quarantined",
    choices=[x.value for x in FilePreservationMode],
    validator=lambda x: isinstance(x, str) and x in [v.value for v in FilePreservationMode],
    question="Determine which files extracted by Zeek should be preserved",
    widget_type=WidgetType.SELECT,
)

CONFIG_ITEM_FILE_CARVE_HTTP_SERVER = ConfigItem(
    key=KEY_CONFIG_ITEM_FILE_CARVE_HTTP_SERVER,
    label="Preserved Files HTTP Server",
    default_value=False,
    validator=lambda x: isinstance(x, bool),
    question="Enable web interface for downloading preserved files?",
    widget_type=WidgetType.CHECKBOX,
)

CONFIG_ITEM_FILE_CARVE_HTTP_SERVER_ZIP = ConfigItem(
    key=KEY_CONFIG_ITEM_FILE_CARVE_HTTP_SERVER_ZIP,
    label="Zip Downloads",
    default_value=False,
    validator=lambda x: isinstance(x, bool),
    question="Zip preserved files on download?",
    widget_type=WidgetType.CHECKBOX,
)

CONFIG_ITEM_FILE_CARVE_HTTP_SERVE_ENCRYPT_KEY = ConfigItem(
    key=KEY_CONFIG_ITEM_FILE_CARVE_HTTP_SERVE_ENCRYPT_KEY,
    label="Downloaded Preserved File Password",
    default_value="",
    validator=lambda x: isinstance(x, str),
    question="ZIP archive or AES-256-CBC encryption password for downloaded preserved files (blank for unencrypted)",
    accept_blank=True,
    widget_type=WidgetType.PASSWORD,
)

CONFIG_ITEM_PIPELINE_ENABLED = ConfigItem(
    key=KEY_CONFIG_ITEM_PIPELINE_ENABLED,
    label="Scan with Strelka",
    default_value=True,
    validator=lambda x: isinstance(x, bool),
    question="Scan extracted files with Strelka?",
    widget_type=WidgetType.CHECKBOX,
)

CONFIG_ITEM_PIPELINE_WORKERS = ConfigItem(
    key=KEY_CONFIG_ITEM_PIPELINE_WORKERS,
    label="File scanning workers",
    default_value=1,
    validator=lambda x: isinstance(x, int) and x > 0,
    question="Number of Strelka file scanning workers (e.g., 1, 4, etc.)",
    widget_type=WidgetType.NUMBER,
)

CONFIG_ITEM_FILE_SCAN_RULE_UPDATE = ConfigItem(
    key=KEY_CONFIG_ITEM_FILE_SCAN_RULE_UPDATE,
    label="Update Scan Rules",
    default_value=False,
    validator=lambda x: isinstance(x, bool),
    question="Periodically pull file scanning signature/rule updates?",
    widget_type=WidgetType.CHECKBOX,
)


def get_file_carve_config_item_dict():
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
ALL_FILE_CARVE_CONFIG_ITEMS_DICT = get_file_carve_config_item_dict()

if __name__ == "__main__":
    # print(globals().items())
    print(ALL_FILE_CARVE_CONFIG_ITEMS_DICT.keys())
