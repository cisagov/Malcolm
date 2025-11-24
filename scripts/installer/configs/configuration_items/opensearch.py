#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2025 Battelle Energy Alliance, LLC.  All rights reserved.

"""OpenSearch configuration items for Malcolm installer.

This module contains all configuration items related to OpenSearch settings,
including connection modes, memory allocation, and remote connectivity options.
"""

import re

from scripts.malcolm_constants import (
    DATABASE_MODE_ENUMS,
    DATABASE_MODE_LABELS,
    DatabaseMode,
    WidgetType,
)
from scripts.malcolm_common import SYSTEM_INFO

from scripts.installer.core.config_item import ConfigItem
from scripts.installer.configs.constants.configuration_item_keys import (
    KEY_CONFIG_ITEM_DASHBOARDS_URL,
    KEY_CONFIG_ITEM_INDEX_DIR,
    KEY_CONFIG_ITEM_INDEX_SNAPSHOT_DIR,
    KEY_CONFIG_ITEM_OPENSEARCH_PRIMARY_MODE,
    KEY_CONFIG_ITEM_OPENSEARCH_PRIMARY_SSL_VERIFY,
    KEY_CONFIG_ITEM_OPENSEARCH_PRIMARY_URL,
    KEY_CONFIG_ITEM_OPENSEARCH_SECONDARY_MODE,
    KEY_CONFIG_ITEM_OPENSEARCH_SECONDARY_SSL_VERIFY,
    KEY_CONFIG_ITEM_OPENSEARCH_SECONDARY_URL,
    KEY_CONFIG_ITEM_OS_MEMORY,
    KEY_CONFIG_ITEM_REMOTE_MALCOLM_HOST,
    KEY_CONFIG_ITEM_SECONDARY_DOCUMENT_STORE,
)

CONFIG_ITEM_OPENSEARCH_PRIMARY_MODE = ConfigItem(
    key=KEY_CONFIG_ITEM_OPENSEARCH_PRIMARY_MODE,
    label="Primary Document Store",
    default_value=DATABASE_MODE_LABELS[DatabaseMode.OpenSearchLocal],
    choices=list(DATABASE_MODE_ENUMS.keys()),
    validator=lambda x: x in DATABASE_MODE_ENUMS.keys(),
    question="Select primary Malcolm document store",
    widget_type=WidgetType.SELECT,
)

CONFIG_ITEM_REMOTE_MALCOLM_HOST = ConfigItem(
    key=KEY_CONFIG_ITEM_REMOTE_MALCOLM_HOST,
    label="Remote Malcolm Hostname or IP",
    default_value="",
    accept_blank=True,
    validator=lambda x: isinstance(x, str),
    question='Hostname or IP address of remote "parent" Malcolm instance (without protocol or port number)',
    widget_type=WidgetType.TEXT,
)

CONFIG_ITEM_OS_MEMORY = ConfigItem(
    key=KEY_CONFIG_ITEM_OS_MEMORY,
    label="OpenSearch Memory",
    default_value=SYSTEM_INFO.get("suggested_os_memory", "16g"),
    validator=lambda x: isinstance(x, str) and bool(re.fullmatch(r'\d+([kKmMgG])?', x)),
    question="Memory allocation for OpenSearch (e.g., 16g, 9500m, etc.)",
    widget_type=WidgetType.TEXT,
)

CONFIG_ITEM_INDEX_DIR = ConfigItem(
    key=KEY_CONFIG_ITEM_INDEX_DIR,
    label="OpenSearch Index Directory",
    default_value="",
    validator=lambda x: isinstance(x, str),
    question="OpenSearch index directory",
    widget_type=WidgetType.DIRECTORY,
)

CONFIG_ITEM_INDEX_SNAPSHOT_DIR = ConfigItem(
    key=KEY_CONFIG_ITEM_INDEX_SNAPSHOT_DIR,
    label="OpenSearch Snapshot Directory",
    default_value="",
    validator=lambda x: isinstance(x, str),
    question="OpenSearch index snapshots directory",
    widget_type=WidgetType.DIRECTORY,
)

CONFIG_ITEM_OPENSEARCH_PRIMARY_URL = ConfigItem(
    key=KEY_CONFIG_ITEM_OPENSEARCH_PRIMARY_URL,
    label="Primary OpenSearch/Elasticsearch URL",
    default_value=None,
    validator=lambda x: isinstance(x, str),
    question="Primary remote OpenSearch/Elasticsearch connection URL",
    widget_type=WidgetType.TEXT,
)

CONFIG_ITEM_OPENSEARCH_PRIMARY_SSL_VERIFY = ConfigItem(
    key=KEY_CONFIG_ITEM_OPENSEARCH_PRIMARY_SSL_VERIFY,
    label="Verify SSL for Primary Document Store",
    default_value=False,
    validator=lambda x: isinstance(x, bool),
    question="Require SSL certificate validation for communication with primary document store?",
    widget_type=WidgetType.CHECKBOX,
)

CONFIG_ITEM_OPENSEARCH_SECONDARY_MODE = ConfigItem(
    key=KEY_CONFIG_ITEM_OPENSEARCH_SECONDARY_MODE,
    label="Secondary Document Store",
    default_value="",
    choices=list([k for k in DATABASE_MODE_ENUMS.keys() if k != DATABASE_MODE_LABELS[DatabaseMode.OpenSearchLocal]]),
    validator=lambda x: x
    in [k for k in DATABASE_MODE_ENUMS.keys() if k != DATABASE_MODE_LABELS[DatabaseMode.OpenSearchLocal]],
    question="Secondary mode to forward Logstash logs to a remote document store",
    widget_type=WidgetType.TEXT,
)

CONFIG_ITEM_OPENSEARCH_SECONDARY_URL = ConfigItem(
    key=KEY_CONFIG_ITEM_OPENSEARCH_SECONDARY_URL,
    label="Secondary OpenSearch/Elasticsearch URL",
    default_value=None,
    validator=lambda x: isinstance(x, str),
    question="Secondary remote OpenSearch/Elasticsearch connection URL",
    widget_type=WidgetType.TEXT,
)

CONFIG_ITEM_OPENSEARCH_SECONDARY_SSL_VERIFY = ConfigItem(
    key=KEY_CONFIG_ITEM_OPENSEARCH_SECONDARY_SSL_VERIFY,
    label="Verify SSL for Secondary Document Store",
    default_value=False,
    validator=lambda x: isinstance(x, bool),
    question="Require SSL certificate validation for communication with secondary document store?",
    widget_type=WidgetType.CHECKBOX,
)

CONFIG_ITEM_DASHBOARDS_URL = ConfigItem(
    key=KEY_CONFIG_ITEM_DASHBOARDS_URL,
    label="Dashboards/Kibana URL",
    default_value=None,
    validator=lambda x: isinstance(x, str),
    question="Remote OpenSearch Dashboards/Kibana connection URL",
    widget_type=WidgetType.TEXT,
)

CONFIG_ITEM_SECONDARY_DOCUMENT_STORE = ConfigItem(
    key=KEY_CONFIG_ITEM_SECONDARY_DOCUMENT_STORE,
    label="Forward Logs to Remote Secondary Store",
    default_value=False,
    question="Forward Logstash logs to a secondary remote document store?",
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
