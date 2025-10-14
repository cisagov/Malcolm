#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2025 Battelle Energy Alliance, LLC.  All rights reserved.

"""
Configuration Items for the Malcolm installer
===============================================

This package contains all of the definitions for individual configuration items (ConfigItem).

All configuration item management is handled by the MalcolmConfig class.
Individual configuration items are exposed here for initialization purposes,
but their state should be managed through a MalcolmConfig instance.
"""

from importlib import import_module

from scripts.installer.core.config_item import ConfigItem

from .analysis import ALL_ANALYSIS_CONFIG_ITEMS_DICT
from .capture import ALL_CAPTURE_CONFIG_ITEMS_DICT
from .docker import ALL_DOCKER_CONFIG_ITEMS_DICT
from .file_carve import ALL_FILE_CARVE_CONFIG_ITEMS_DICT
from .filebeat import ALL_FILEBEAT_CONFIG_ITEMS_DICT

from .logstash import ALL_LOGSTASH_CONFIG_ITEMS_DICT
from .network import ALL_NETWORK_CONFIG_ITEMS_DICT
from .netbox import ALL_NETBOX_CONFIG_ITEMS_DICT
from .open_ports import ALL_OPEN_PORTS_CONFIG_ITEMS_DICT
from .opensearch import ALL_OPENSEARCH_CONFIG_ITEMS_DICT
from .runtime import ALL_RUNTIME_CONFIG_ITEMS_DICT
from .storage import ALL_STORAGE_CONFIG_ITEMS_DICT
from .zeek_intel import ALL_ZEEK_INTEL_CONFIG_ITEMS_DICT

# Combine all config item dictionaries into a single dictionary
ALL_CONFIG_ITEMS_DICT = {
    **ALL_ANALYSIS_CONFIG_ITEMS_DICT,
    **ALL_CAPTURE_CONFIG_ITEMS_DICT,
    **ALL_DOCKER_CONFIG_ITEMS_DICT,  # these map to docker-compose.yml via MalcolmConfig.generate_docker_compose_file()
    **ALL_FILE_CARVE_CONFIG_ITEMS_DICT,
    **ALL_FILEBEAT_CONFIG_ITEMS_DICT,
    **ALL_LOGSTASH_CONFIG_ITEMS_DICT,
    **ALL_NETWORK_CONFIG_ITEMS_DICT,
    **ALL_NETBOX_CONFIG_ITEMS_DICT,
    **ALL_OPEN_PORTS_CONFIG_ITEMS_DICT,
    **ALL_OPENSEARCH_CONFIG_ITEMS_DICT,
    **ALL_RUNTIME_CONFIG_ITEMS_DICT,
    **ALL_STORAGE_CONFIG_ITEMS_DICT,
    **ALL_ZEEK_INTEL_CONFIG_ITEMS_DICT,
}

# Map back to the CONFIG_ITEM_* constant name for search and debugging helpers.
_CONFIG_ITEM_MODULE_PATHS = (
    "scripts.installer.configs.configuration_items.analysis",
    "scripts.installer.configs.configuration_items.capture",
    "scripts.installer.configs.configuration_items.docker",
    "scripts.installer.configs.configuration_items.file_carve",
    "scripts.installer.configs.configuration_items.filebeat",
    "scripts.installer.configs.configuration_items.logstash",
    "scripts.installer.configs.configuration_items.network",
    "scripts.installer.configs.configuration_items.netbox",
    "scripts.installer.configs.configuration_items.open_ports",
    "scripts.installer.configs.configuration_items.opensearch",
    "scripts.installer.configs.configuration_items.runtime",
    "scripts.installer.configs.configuration_items.storage",
    "scripts.installer.configs.configuration_items.zeek_intel",
)


def _build_definition_name_map():
    mapping = {}
    for module_path in _CONFIG_ITEM_MODULE_PATHS:
        module = import_module(module_path)
        for attr_name, attr_value in vars(module).items():
            if not attr_name.startswith("CONFIG_ITEM_"):
                continue
            if not isinstance(attr_value, ConfigItem):
                continue
            attr_value.metadata.setdefault("definition_name", attr_name)
            mapping[attr_value.key] = attr_name
    return mapping


CONFIG_ITEM_DEFINITION_NAME_BY_KEY = _build_definition_name_map()

# Expose ALL_CONFIG_ITEMS_DICT for test discovery
__all__ = [
    "ALL_CONFIG_ITEMS_DICT",
    "CONFIG_ITEM_DEFINITION_NAME_BY_KEY",
]
