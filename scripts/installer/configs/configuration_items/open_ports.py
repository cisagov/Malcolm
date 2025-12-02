#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2025 Battelle Energy Alliance, LLC.  All rights reserved.

"""Expose ports configuration items for Malcolm installer.

This module contains all configuration items related to exposing ports,
including Logstash, OpenSearch, Filebeat, SFTP, and Syslog ports.
"""
from scripts.malcolm_constants import WidgetType
from scripts.installer.core.config_item import ConfigItem
from scripts.installer.configs.constants.enums import OpenPortsChoices
from scripts.installer.configs.constants.configuration_item_keys import (
    KEY_CONFIG_ITEM_EXPOSE_FILEBEAT_TCP,
    KEY_CONFIG_ITEM_EXPOSE_LOGSTASH,
    KEY_CONFIG_ITEM_EXPOSE_OPENSEARCH,
    KEY_CONFIG_ITEM_EXPOSE_SFTP,
    KEY_CONFIG_ITEM_OPEN_PORTS,
    KEY_CONFIG_ITEM_SYSLOG_TCP_PORT,
    KEY_CONFIG_ITEM_SYSLOG_UDP_PORT,
)

CONFIG_ITEM_OPEN_PORTS = ConfigItem(
    key=KEY_CONFIG_ITEM_OPEN_PORTS,
    label="Expose Malcolm Service Ports",
    default_value=OpenPortsChoices.NO.value,
    choices=[x.value for x in OpenPortsChoices],
    validator=lambda x: isinstance(x, str) and (x in [v.value for v in OpenPortsChoices]),
    question="Should Malcolm accept logs and metrics from a Hedgehog sensor or other forwarder?",
    widget_type=WidgetType.SELECT,
)

CONFIG_ITEM_EXPOSE_LOGSTASH = ConfigItem(
    key=KEY_CONFIG_ITEM_EXPOSE_LOGSTASH,
    label="Expose Logstash",
    default_value=False,
    validator=lambda x: isinstance(x, bool),
    question="Expose Logstash service to external hosts?",
    widget_type=WidgetType.CHECKBOX,
)

CONFIG_ITEM_EXPOSE_OPENSEARCH = ConfigItem(
    key=KEY_CONFIG_ITEM_EXPOSE_OPENSEARCH,
    label="Expose OpenSearch",
    default_value=False,
    validator=lambda x: isinstance(x, bool),
    question="Expose OpenSearch service to external hosts?",
    widget_type=WidgetType.CHECKBOX,
)

CONFIG_ITEM_EXPOSE_FILEBEAT_TCP = ConfigItem(
    key=KEY_CONFIG_ITEM_EXPOSE_FILEBEAT_TCP,
    label="Expose Filebeat TCP",
    default_value=False,
    validator=lambda x: isinstance(x, bool),
    question="Expose Filebeat TCP service to external hosts?",
    widget_type=WidgetType.CHECKBOX,
)

CONFIG_ITEM_EXPOSE_SFTP = ConfigItem(
    key=KEY_CONFIG_ITEM_EXPOSE_SFTP,
    label="Expose SFTP",
    default_value=False,
    validator=lambda x: isinstance(x, bool),
    question="Expose SFTP server (for PCAP upload) to external hosts?",
    widget_type=WidgetType.CHECKBOX,
)

CONFIG_ITEM_SYSLOG_TCP_PORT = ConfigItem(
    key=KEY_CONFIG_ITEM_SYSLOG_TCP_PORT,
    label="Syslog TCP Port",
    default_value=None,
    validator=lambda x: isinstance(x, int),
    question="Listen for standard Syslog (TCP) on this port (0 for disabled)",
    widget_type=WidgetType.NUMBER,
)

CONFIG_ITEM_SYSLOG_UDP_PORT = ConfigItem(
    key=KEY_CONFIG_ITEM_SYSLOG_UDP_PORT,
    label="Syslog UDP Port",
    default_value=None,
    validator=lambda x: isinstance(x, int),
    question="Listen for standard Syslog (UDP) on this port (0 for disabled)",
    widget_type=WidgetType.NUMBER,
)


def get_open_ports_config_item_dict():
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
ALL_OPEN_PORTS_CONFIG_ITEMS_DICT = get_open_ports_config_item_dict()

if __name__ == "__main__":
    # print(globals().items())
    print(ALL_OPEN_PORTS_CONFIG_ITEMS_DICT.keys())
