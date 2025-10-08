#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2025 Battelle Energy Alliance, LLC.  All rights reserved.

"""File carve configuration items for Malcolm installer.

This module contains all configuration items related to file carve settings,
including file extraction and preservation configuration.
"""

from typing import Any, Tuple


from scripts.malcolm_utils import str2bool as str_to_bool

from scripts.installer.core.config_item import ConfigItem
from scripts.installer.configs.constants.enums import (
    FileExtractionMode,
    FilePreservationMode,
)
from scripts.malcolm_constants import WidgetType
from scripts.installer.configs.constants.configuration_item_keys import (
    KEY_CONFIG_ITEM_FILE_CARVE_MODE,
    KEY_CONFIG_ITEM_FILE_PRESERVE_MODE,
    KEY_CONFIG_ITEM_FILE_CARVE_HTTP_SERVER,
    KEY_CONFIG_ITEM_FILE_CARVE_HTTP_SERVER_ZIP,
    KEY_CONFIG_ITEM_FILE_CARVE_HTTP_SERVE_ENCRYPT_KEY,
    KEY_CONFIG_ITEM_CLAM_AV_SCAN,
    KEY_CONFIG_ITEM_YARA_SCAN,
    KEY_CONFIG_ITEM_CAPA_SCAN,
    KEY_CONFIG_ITEM_VTOT_API_KEY,
    KEY_CONFIG_ITEM_FILE_SCAN_RULE_UPDATE,
    KEY_CONFIG_ITEM_FILE_CARVE_ENABLED,
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


CONFIG_ITEM_FILE_CARVE_ENABLED = ConfigItem(
    key=KEY_CONFIG_ITEM_FILE_CARVE_ENABLED,
    label="Enable Zeek File Extraction",
    default_value=False,
    validator=lambda x: isinstance(x, bool),
    question=f"Enable file extraction with Zeek",
    widget_type=WidgetType.CHECKBOX,
)

# File Extraction Configuration
CONFIG_ITEM_FILE_EXTRACTION_MODE = ConfigItem(
    key=KEY_CONFIG_ITEM_FILE_CARVE_MODE,
    label="File Extraction Mode",
    default_value="none",
    choices=[x.value for x in FileExtractionMode],
    validator=lambda x: isinstance(x, str)
    and x in [v.value for v in FileExtractionMode],
    question=f"Choose how Zeek should extract files from network traffic. Depends on Zeek analysis. 'Interesting' is a common default.",
    widget_type=WidgetType.SELECT,
)

CONFIG_ITEM_FILE_PRESERVATION = ConfigItem(
    key=KEY_CONFIG_ITEM_FILE_PRESERVE_MODE,
    label="File Preservation",
    default_value="quarantined",
    choices=[x.value for x in FilePreservationMode],
    validator=lambda x: isinstance(x, str)
    and x in [v.value for v in FilePreservationMode],
    question=f"Determine which files extracted by Zeek should be preserved. Depends on Zeek analysis and file extraction. 'Quarantined' is common.",
    widget_type=WidgetType.SELECT,
)

CONFIG_ITEM_FILE_CARVE_HTTP_SERVER = ConfigItem(
    key=KEY_CONFIG_ITEM_FILE_CARVE_HTTP_SERVER,
    label="File Carve HTTP Server",
    default_value=False,
    validator=lambda x: isinstance(x, bool),
    question=f"Enable web interface for downloading preserved files",
    widget_type=WidgetType.CHECKBOX,
)

CONFIG_ITEM_FILE_CARVE_HTTP_SERVER_ZIP = ConfigItem(
    key=KEY_CONFIG_ITEM_FILE_CARVE_HTTP_SERVER_ZIP,
    label="Zip Downloads",
    default_value=False,
    validator=lambda x: isinstance(x, bool),
    question=f"ZIP downloaded preserved files",
    widget_type=WidgetType.CHECKBOX,
)

CONFIG_ITEM_FILE_CARVE_HTTP_SERVE_ENCRYPT_KEY = ConfigItem(
    key=KEY_CONFIG_ITEM_FILE_CARVE_HTTP_SERVE_ENCRYPT_KEY,
    label="Download Password",
    default_value="",
    validator=lambda x: isinstance(x, str),
    question=f"ZIP archive or AES-256-CBC encryption password for downloaded preserved files (blank for unencrypted)",
    widget_type=WidgetType.PASSWORD,
)

CONFIG_ITEM_CLAM_AV_SCAN = ConfigItem(
    key=KEY_CONFIG_ITEM_CLAM_AV_SCAN,
    label="ClamAV Scan",
    default_value=True,
    validator=lambda x: isinstance(x, bool),
    question=f"Scan extracted files with ClamAV",
    widget_type=WidgetType.CHECKBOX,
)

CONFIG_ITEM_YARA_SCAN = ConfigItem(
    key=KEY_CONFIG_ITEM_YARA_SCAN,
    label="Yara Scan",
    default_value=True,
    validator=lambda x: isinstance(x, bool),
    question=f"Scan extracted files with Yara",
    widget_type=WidgetType.CHECKBOX,
)

CONFIG_ITEM_CAPA_SCAN = ConfigItem(
    key=KEY_CONFIG_ITEM_CAPA_SCAN,
    label="Capa Scan",
    default_value=True,
    validator=lambda x: isinstance(x, bool),
    question=f"Scan extracted files with Capa",
    widget_type=WidgetType.CHECKBOX,
)

CONFIG_ITEM_VTOT_API_KEY = ConfigItem(
    key=KEY_CONFIG_ITEM_VTOT_API_KEY,
    label="VirusTotal API Key",
    default_value="",
    validator=lambda x: isinstance(x, str),
    question=f"VirusTotal API key to scan extracted files with VirusTotal",
    widget_type=WidgetType.PASSWORD,
)

CONFIG_ITEM_FILE_SCAN_RULE_UPDATE = ConfigItem(
    key=KEY_CONFIG_ITEM_FILE_SCAN_RULE_UPDATE,
    label="Update Scan Rules",
    default_value=True,
    validator=lambda x: isinstance(x, bool),
    question=f"Periodically pull ClamAV/Yara/Capa signatures/rules updates",
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
