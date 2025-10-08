#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2025 Battelle Energy Alliance, LLC.  All rights reserved.

"""OpenSearch configuration items for Malcolm installer.

This module contains all configuration items related to OpenSearch settings,
including connection modes, memory allocation, and remote connectivity options.
"""

from typing import Any, Tuple

from scripts.malcolm_constants import (
    DATABASE_MODE_ENUMS,
    DATABASE_MODE_LABELS,
    DatabaseMode,
    WidgetType,
)
from scripts.malcolm_utils import SYSTEM_INFO

from scripts.installer.core.config_item import ConfigItem
from scripts.installer.configs.constants.configuration_item_keys import (
    KEY_CONFIG_ITEM_OPENSEARCH_PRIMARY_MODE,
    KEY_CONFIG_ITEM_OS_MEMORY,
    KEY_CONFIG_ITEM_OPENSEARCH_PRIMARY_URL,
    KEY_CONFIG_ITEM_OPENSEARCH_PRIMARY_SSL_VERIFY,
    KEY_CONFIG_ITEM_OPENSEARCH_SECONDARY_MODE,
    KEY_CONFIG_ITEM_OPENSEARCH_SECONDARY_URL,
    KEY_CONFIG_ITEM_OPENSEARCH_SECONDARY_SSL_VERIFY,
    KEY_CONFIG_ITEM_DASHBOARDS_URL,
    KEY_CONFIG_ITEM_SECONDARY_DOCUMENT_STORE,
    KEY_CONFIG_ITEM_MALCOLM_MAINTAIN_OPENSEARCH,
    KEY_CONFIG_ITEM_INDEX_DIR,
    KEY_CONFIG_ITEM_INDEX_SNAPSHOT_DIR,
)

CONFIG_ITEM_MALCOLM_MAINTAIN_OPENSEARCH = ConfigItem(
    key=KEY_CONFIG_ITEM_MALCOLM_MAINTAIN_OPENSEARCH,
    label="Malcolm: Maintain OpenSearch Instance?",
    default_value=True,
    validator=lambda x: isinstance(x, bool),
    question=f"Should Malcolm maintain its own opensearch instance?",
    widget_type=WidgetType.CHECKBOX,
)

CONFIG_ITEM_OPENSEARCH_PRIMARY_MODE = ConfigItem(
    key=KEY_CONFIG_ITEM_OPENSEARCH_PRIMARY_MODE,
    label="Primary Malcolm Document Store",
    default_value=DATABASE_MODE_LABELS[DatabaseMode.OpenSearchLocal],
    choices=list(DATABASE_MODE_ENUMS.keys()),
    validator=lambda x: x in DATABASE_MODE_ENUMS.keys(),
    question=f"Select primary Malcolm document store",
    widget_type=WidgetType.SELECT,
)

CONFIG_ITEM_OS_MEMORY = ConfigItem(
    key=KEY_CONFIG_ITEM_OS_MEMORY,
    label="OpenSearch Memory",
    default_value=SYSTEM_INFO.get("suggested_os_memory", "8g"),
    validator=lambda x: isinstance(x, str),
    question=f"Memory allocation for OpenSearch (e.g., 16g, 9500m, etc.)",
    widget_type=WidgetType.TEXT,
)

CONFIG_ITEM_INDEX_DIR = ConfigItem(
    key=KEY_CONFIG_ITEM_INDEX_DIR,
    label="OpenSearch Index Directory",
    default_value="",
    validator=lambda x: isinstance(x, str),
    question=f"OpenSearch index directory",
    widget_type=WidgetType.DIRECTORY,
)

CONFIG_ITEM_INDEX_SNAPSHOT_DIR = ConfigItem(
    key=KEY_CONFIG_ITEM_INDEX_SNAPSHOT_DIR,
    label="OpenSearch Snapshot Directory",
    default_value="",
    validator=lambda x: isinstance(x, str),
    question=f"Store OpenSearch index snapshots in ./opensearch-backup?",
    widget_type=WidgetType.DIRECTORY,
)

CONFIG_ITEM_OPENSEARCH_PRIMARY_URL = ConfigItem(
    key=KEY_CONFIG_ITEM_OPENSEARCH_PRIMARY_URL,
    label="OpenSearch URL",
    default_value=None,
    validator=lambda x: isinstance(x, str),
    question=f"Primary remote OpenSearch connection URL",
    widget_type=WidgetType.TEXT,
)

CONFIG_ITEM_OPENSEARCH_PRIMARY_SSL_VERIFY = ConfigItem(
    key=KEY_CONFIG_ITEM_OPENSEARCH_PRIMARY_SSL_VERIFY,
    label="Verify SSL for Primary",
    default_value=False,
    validator=lambda x: isinstance(x, bool),
    question=f"Require SSL certificate validation for communication with primary OpenSearch instance",
    widget_type=WidgetType.CHECKBOX,
)

CONFIG_ITEM_OPENSEARCH_SECONDARY_MODE = ConfigItem(
    key=KEY_CONFIG_ITEM_OPENSEARCH_SECONDARY_MODE,
    label="Secondary OpenSearch Mode",
    default_value="",
    choices=list(DATABASE_MODE_ENUMS.keys()),
    validator=lambda x: x in DATABASE_MODE_ENUMS.keys(),
    question=f"Secondary OpenSearch mode to forward Logstash logs to a remote OpenSearch instance",
    widget_type=WidgetType.TEXT,
)

CONFIG_ITEM_OPENSEARCH_SECONDARY_URL = ConfigItem(
    key=KEY_CONFIG_ITEM_OPENSEARCH_SECONDARY_URL,
    label="Secondary OpenSearch URL",
    default_value=None,
    validator=lambda x: isinstance(x, str),
    question=f"Secondary remote OpenSearch connection URL",
    widget_type=WidgetType.TEXT,
)

CONFIG_ITEM_OPENSEARCH_SECONDARY_SSL_VERIFY = ConfigItem(
    key=KEY_CONFIG_ITEM_OPENSEARCH_SECONDARY_SSL_VERIFY,
    label="Verify SSL for Secondary",
    default_value=False,
    validator=lambda x: isinstance(x, bool),
    question=f"Require SSL certificate validation for communication with secondary OpenSearch instance",
    widget_type=WidgetType.CHECKBOX,
)

CONFIG_ITEM_DASHBOARDS_URL = ConfigItem(
    key=KEY_CONFIG_ITEM_DASHBOARDS_URL,
    label="Dashboards URL",
    default_value=None,
    validator=lambda x: isinstance(x, str),
    question=f"Remote OpenSearch Dashboards connection URL",
    widget_type=WidgetType.TEXT,
)

CONFIG_ITEM_SECONDARY_DOCUMENT_STORE = ConfigItem(
    key=KEY_CONFIG_ITEM_SECONDARY_DOCUMENT_STORE,
    label="Forward Logstash Logs to Secondary",
    default_value=False,
    question=f"Forward Logstash logs to a secondary remote document store?",
    widget_type=WidgetType.CHECKBOX,
)


def get_opensearch_config_item_dict():
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
ALL_OPENSEARCH_CONFIG_ITEMS_DICT = get_opensearch_config_item_dict()

if __name__ == "__main__":
    # print(globals().items())
    print(ALL_OPENSEARCH_CONFIG_ITEMS_DICT.keys())
