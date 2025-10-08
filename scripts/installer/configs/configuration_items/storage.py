#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2025 Battelle Energy Alliance, LLC.  All rights reserved.

"""Storage configuration items for Malcolm installer.

This module contains all configuration items related to storage settings,
including directories, data retention policies, and index management.
"""

from scripts.malcolm_constants import WidgetType
from scripts.malcolm_utils import (
    str2bool as str_to_bool,
    str2percent as str_to_percent,
    get_malcolm_dir,
)

from scripts.installer.core.config_item import ConfigItem
from scripts.installer.configs.constants.configuration_item_keys import (
    KEY_CONFIG_ITEM_USE_DEFAULT_STORAGE_LOCATIONS,
    KEY_CONFIG_ITEM_PCAP_DIR,
    KEY_CONFIG_ITEM_ZEEK_LOG_DIR,
    KEY_CONFIG_ITEM_SURICATA_LOG_DIR,
    KEY_CONFIG_ITEM_ARKIME_MANAGE_PCAP,
    KEY_CONFIG_ITEM_ARKIME_FREESPACEG,
    KEY_CONFIG_ITEM_EXTRACTED_FILE_MAX_SIZE_THRESHOLD,
    KEY_CONFIG_ITEM_EXTRACTED_FILE_MAX_PERCENT_THRESHOLD,
    KEY_CONFIG_ITEM_INDEX_PRUNE_SIZE_LIMIT,
    KEY_CONFIG_ITEM_INDEX_MANAGEMENT_POLICY,
    KEY_CONFIG_ITEM_INDEX_MANAGEMENT_HOT_WARM,
    KEY_CONFIG_ITEM_INDEX_MANAGEMENT_OPTIMIZATION_TIME_PERIOD,
    KEY_CONFIG_ITEM_INDEX_MANAGEMENT_SPI_DATA_RETENTION,
    KEY_CONFIG_ITEM_INDEX_MANAGEMENT_REPLICAS,
    KEY_CONFIG_ITEM_INDEX_MANAGEMENT_HISTORY_IN_WEEKS,
    KEY_CONFIG_ITEM_INDEX_MANAGEMENT_OPTIMIZE_SESSION_SEGMENTS,
    KEY_CONFIG_ITEM_INDEX_PRUNE_NAME_SORT,
    KEY_CONFIG_ITEM_CLEAN_UP_OLD_INDICES,
)

CONFIG_ITEM_CLEAN_UP_OLD_INDICES = ConfigItem(
    key=KEY_CONFIG_ITEM_CLEAN_UP_OLD_INDICES,
    label="Clean Up Old Artifacts",
    default_value=False,
    validator=lambda x: isinstance(x, bool),
    question=f"Should Malcolm delete the oldest database indices and capture artifacts based on available storage?",
    widget_type=WidgetType.CHECKBOX,
)

CONFIG_ITEM_USE_DEFAULT_STORAGE_LOCATIONS = ConfigItem(
    key=KEY_CONFIG_ITEM_USE_DEFAULT_STORAGE_LOCATIONS,
    label="Use Default Storage Locations",
    default_value=True,
    validator=lambda x: isinstance(x, bool),
    question=f"Store pcap, log, and index files in {get_malcolm_dir()}",
    widget_type=WidgetType.CHECKBOX,
)

CONFIG_ITEM_PCAP_DIR = ConfigItem(
    key=KEY_CONFIG_ITEM_PCAP_DIR,
    label="PCAP Directory",
    default_value="",
    validator=lambda x: isinstance(x, str),
    question=f"PCAP storage directory",
    widget_type=WidgetType.DIRECTORY,
)

CONFIG_ITEM_ZEEK_LOG_DIR = ConfigItem(
    key=KEY_CONFIG_ITEM_ZEEK_LOG_DIR,
    label="Zeek Log Directory",
    default_value="",
    validator=lambda x: isinstance(x, str),
    question=f"Zeek log storage directory",
    widget_type=WidgetType.DIRECTORY,
)

CONFIG_ITEM_SURICATA_LOG_DIR = ConfigItem(
    key=KEY_CONFIG_ITEM_SURICATA_LOG_DIR,
    label="Suricata Log Directory",
    default_value="",
    validator=lambda x: isinstance(x, str),
    question=f"Suricata log storage directory",
    widget_type=WidgetType.DIRECTORY,
)

CONFIG_ITEM_ARKIME_MANAGE_PCAP = ConfigItem(
    key=KEY_CONFIG_ITEM_ARKIME_MANAGE_PCAP,
    label="Delete Old PCAP",
    default_value=False,
    validator=lambda x: isinstance(x, bool),
    question=f"Arkime should delete PCAP files based on available storage (see https://arkime.com/faq#pcap-deletion)",
    widget_type=WidgetType.CHECKBOX,
)

CONFIG_ITEM_ARKIME_FREE_SPACE_G = ConfigItem(
    key=KEY_CONFIG_ITEM_ARKIME_FREESPACEG,
    label="Delete PCAP Threshold",
    default_value="",
    validator=lambda x: isinstance(x, str),
    question=f"Threshold for Arkime PCAP deletion (see https://arkime.com/faq#pcap-deletion)",
    widget_type=WidgetType.TEXT,
)

CONFIG_ITEM_EXTRACTED_FILE_MAX_SIZE_THRESHOLD = ConfigItem(
    key=KEY_CONFIG_ITEM_EXTRACTED_FILE_MAX_SIZE_THRESHOLD,
    label="Extracted File Size Threshold",
    default_value="",
    validator=lambda x: isinstance(x, str),
    question=f"Delete zeek-extracted files when they consume this much disk space (e.g., 250GB, 1TB, etc.)",
    widget_type=WidgetType.TEXT,
)

CONFIG_ITEM_EXTRACTED_FILE_MAX_PERCENT_THRESHOLD = ConfigItem(
    key=KEY_CONFIG_ITEM_EXTRACTED_FILE_MAX_PERCENT_THRESHOLD,
    label="Extracted File Percent Threshold",
    default_value=0,
    validator=lambda x: isinstance(x, int),
    question=f"Delete zeek-extracted files when the file system exceeds this percentage full (e.g., 90%, etc.)",
    widget_type=WidgetType.NUMBER,
)

CONFIG_ITEM_INDEX_PRUNE_SIZE_LIMIT = ConfigItem(
    key=KEY_CONFIG_ITEM_INDEX_PRUNE_SIZE_LIMIT,
    label="Index Prune Size Limit",
    default_value="",
    validator=lambda x: isinstance(x, str),
    question=f"Delete the oldest indices when the database exceeds this threshold (e.g., 250GB, 1TB, 60%, etc.)",
    widget_type=WidgetType.TEXT,
)

CONFIG_ITEM_INDEX_PRUNE_NAME_SORT = ConfigItem(
    key=KEY_CONFIG_ITEM_INDEX_PRUNE_NAME_SORT,
    label="Prune by Name",
    default_value=False,
    validator=lambda x: isinstance(x, bool),
    question=f"Determine oldest indices by name (instead of creation time)?",
    widget_type=WidgetType.CHECKBOX,
)

CONFIG_ITEM_INDEX_MANAGEMENT_POLICY = ConfigItem(
    key=KEY_CONFIG_ITEM_INDEX_MANAGEMENT_POLICY,
    label="Arkime: Enable Index Management",
    default_value=False,
    validator=lambda x: isinstance(x, bool),
    question=f"Enable index management policies (ILM/ISM) in Arkime? (see https://https://arkime.com/faq#ilm)",
    widget_type=WidgetType.CHECKBOX,
)

CONFIG_ITEM_INDEX_MANAGEMENT_HOT_WARM = ConfigItem(
    key=KEY_CONFIG_ITEM_INDEX_MANAGEMENT_HOT_WARM,
    label="Arkime: Use Hot/Warm Indexing",
    default_value=False,
    validator=lambda x: isinstance(x, bool),
    question=f"Should Arkime use a hot/warm design in which non-session data is stored in a warm index?",
    widget_type=WidgetType.CHECKBOX,
)

CONFIG_ITEM_INDEX_MANAGEMENT_OPTIMIZATION_TIME_PERIOD = ConfigItem(
    key=KEY_CONFIG_ITEM_INDEX_MANAGEMENT_OPTIMIZATION_TIME_PERIOD,
    label="Arkime: Hot Node Time Period",
    default_value="30d",
    validator=lambda x: isinstance(x, str),
    question=f"How long should Arkime keep an index in the hot node? (e.g. 25h, 5d, etc.)",
    widget_type=WidgetType.TEXT,
)

CONFIG_ITEM_INDEX_MANAGEMENT_SPI_DATA_RETENTION = ConfigItem(
    key=KEY_CONFIG_ITEM_INDEX_MANAGEMENT_SPI_DATA_RETENTION,
    label="Arkime: SPI Data Retention",
    default_value="90d",
    validator=lambda x: isinstance(x, str),
    question=f"How long should Arkime retain SPI data before deleting it? (e.g. 25h, 90d, etc.)",
    widget_type=WidgetType.TEXT,
)

CONFIG_ITEM_INDEX_MANAGEMENT_REPLICAS = ConfigItem(
    key=KEY_CONFIG_ITEM_INDEX_MANAGEMENT_REPLICAS,
    label="Arkime: Replica Count (Warm)",
    default_value=0,
    validator=lambda x: isinstance(x, int),
    question=f"How many replicas should Arkime maintain for older session indices?",
    widget_type=WidgetType.NUMBER,
)

CONFIG_ITEM_INDEX_MANAGEMENT_HISTORY_IN_WEEKS = ConfigItem(
    key=KEY_CONFIG_ITEM_INDEX_MANAGEMENT_HISTORY_IN_WEEKS,
    label="Arkime: History Retention (Weeks)",
    default_value=13,
    validator=lambda x: isinstance(x, int),
    question=f"How many weeks of history should Arkime keep?",
    widget_type=WidgetType.NUMBER,
)

CONFIG_ITEM_INDEX_MANAGEMENT_OPTIMIZE_SESSION_SEGMENTS = ConfigItem(
    key=KEY_CONFIG_ITEM_INDEX_MANAGEMENT_OPTIMIZE_SESSION_SEGMENTS,
    label="Arkime: Optimize Segments",
    default_value=1,
    validator=lambda x: isinstance(x, int),
    question=f"How many segments should Arkime use to optimize?",
    widget_type=WidgetType.NUMBER,
)


def get_storage_config_item_dict():
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
ALL_STORAGE_CONFIG_ITEMS_DICT = get_storage_config_item_dict()

if __name__ == "__main__":
    # print(globals().items())
    print(ALL_STORAGE_CONFIG_ITEMS_DICT.keys())
