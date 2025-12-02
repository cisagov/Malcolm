#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2025 Battelle Energy Alliance, LLC.  All rights reserved.


"""Map configuration items to .env files and variables.

Includes reverse import from existing env files and lookup helpers.
"""

try:
    from collections.abc import Iterable
except ImportError:
    from collections import Iterable
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

import os

from scripts.installer.utils.logger_utils import InstallerLogger
from scripts.installer.utils.exceptions import FileOperationError
from ..utils.custom_transforms import *

from scripts.malcolm_utils import (
    str2bool as str_to_bool,
    true_or_false_no_quotes,
    bool_to_str,
)
from scripts.malcolm_common import get_default_config_dir, DotEnvDynamic
from scripts.installer.configs.constants.configuration_item_keys import *
from scripts.installer.configs.constants.config_env_var_keys import *


def _default_string_transform(value: Any) -> str:
    """Strip quotes from string value"""
    if value is None:
        return ""
    return true_or_false_no_quotes(value)


def _default_string_reverse_transform(value: str):
    """Default reverse transform.

    * Numeric strings (e.g., "42") are converted to `int` 42 so numeric config
      items validate correctly.
    * All other values are returned as-is (string).
    """
    if isinstance(value, str) and value.isdigit():
        try:
            return int(value)
        except ValueError:
            pass  # fall through to return original value
    return value


def _default_list_of_strings_transform(value: Any) -> List[str]:
    if value is None:
        result = []
    elif isinstance(value, str):
        result = [value]
    elif isinstance(value, Iterable):
        result = [str(v) for v in value]
    else:
        result = [str(value)]

    return ",".join([true_or_false_no_quotes(x).strip() for x in result])


def _default_list_of_strings_reverse_transform(value: str) -> List[str]:
    return [s.strip() for s in value.split(",") if s.strip()] if value.strip() else []


# 1. Boolean transform logic (single config item only)
_BOOLEAN_VARS = [
    KEY_ENV_ARKIME_ALLOW_WISE_CONFIG,
    KEY_ENV_ARKIME_AUTO_ANALYZE_PCAP_FILES,
    KEY_ENV_ARKIME_EXPOSE_WISE,
    KEY_ENV_ARKIME_INDEX_MANAGEMENT_ENABLED,
    KEY_ENV_ARKIME_INDEX_MANAGEMENT_HOT_WARM_ENABLED,
    KEY_ENV_ARKIME_MANAGE_PCAP_FILES,
    KEY_ENV_FILEBEAT_TCP_LISTEN,
    KEY_ENV_FREQ_LOOKUP,
    KEY_ENV_LOGSTASH_OUI_LOOKUP,
    KEY_ENV_LOGSTASH_REVERSE_DNS,
    KEY_ENV_NETBOX_AUTO_CREATE_PREFIX,
    KEY_ENV_NETBOX_AUTO_POPULATE,
    KEY_ENV_NETBOX_ENRICHMENT,
    KEY_ENV_NGINX_RESOLVER_IPV4,
    KEY_ENV_NGINX_RESOLVER_IPV6,
    KEY_ENV_NGINX_SSL,
    KEY_ENV_OPENSEARCH_DASHBOARDS_DARKMODE,
    KEY_ENV_OPENSEARCH_INDEX_SIZE_PRUNE_NAME_SORT,
    KEY_ENV_OPENSEARCH_SECONDARY_SSL_CERTIFICATE_VERIFICATION,
    KEY_ENV_OPENSEARCH_SSL_CERTIFICATE_VERIFICATION,
    KEY_ENV_PCAP_IFACE_TWEAK,
    KEY_ENV_SURICATA_AUTO_ANALYZE_PCAP_FILES,
    KEY_ENV_SURICATA_STATS_ENABLED,
    KEY_ENV_SURICATA_STATS_EVE_ENABLED,
    KEY_ENV_SURICATA_UPDATE_RULES,
    KEY_ENV_ZEEK_AUTO_ANALYZE_PCAP_FILES,
    KEY_ENV_ZEEK_FILE_ENABLE_CAPA,
    KEY_ENV_ZEEK_FILE_ENABLE_CLAMAV,
    KEY_ENV_ZEEK_FILE_ENABLE_YARA,
    KEY_ENV_ZEEK_FILE_HTTP_SERVER_ENABLE,
    KEY_ENV_ZEEK_FILE_HTTP_SERVER_ZIP,
    KEY_ENV_ZEEK_FILE_UPDATE_RULES,
    KEY_ENV_ZEEK_INTEL_REFRESH_ON_STARTUP,
]

# 2. String transform logic
_STRING_VARS = [
    KEY_ENV_ARKIME_FREESPACEG,
    KEY_ENV_ARKIME_INDEX_MANAGEMENT_HISTORY_RETENTION_WEEKS,
    KEY_ENV_ARKIME_INDEX_MANAGEMENT_OLDER_SESSION_REPLICAS,
    KEY_ENV_ARKIME_INDEX_MANAGEMENT_OPTIMIZATION_PERIOD,
    KEY_ENV_ARKIME_INDEX_MANAGEMENT_RETENTION_TIME,
    KEY_ENV_ARKIME_INDEX_MANAGEMENT_SEGMENTS,
    KEY_ENV_ARKIME_LIVE_NODE_HOST,
    KEY_ENV_ARKIME_LIVE_COMP_TYPE,
    KEY_ENV_ARKIME_LIVE_COMP_LEVEL,
    KEY_ENV_ARKIME_WISE_URL,
    KEY_ENV_CONTAINER_RUNTIME_KEY,
    KEY_ENV_FILEBEAT_SYSLOG_TCP_PORT,
    KEY_ENV_FILEBEAT_SYSLOG_UDP_PORT,
    KEY_ENV_FILEBEAT_TCP_LOG_FORMAT,
    KEY_ENV_FILEBEAT_TCP_PARSE_DROP_FIELD,
    KEY_ENV_FILEBEAT_TCP_PARSE_SOURCE_FIELD,
    KEY_ENV_FILEBEAT_TCP_PARSE_TARGET_FIELD,
    KEY_ENV_FILEBEAT_TCP_TAG,
    KEY_ENV_LOGSTASH_HOST,
    KEY_ENV_LOGSTASH_PIPELINE_WORKERS,
    KEY_ENV_NETBOX_DEFAULT_SITE,
    KEY_ENV_NETBOX_MODE,
    KEY_ENV_OPENSEARCH_DASHBOARDS_URL,
    KEY_ENV_OPENSEARCH_INDEX_PRUNE_THRESHOLD,
    KEY_ENV_OPENSEARCH_PRIMARY,
    KEY_ENV_OPENSEARCH_SECONDARY,
    KEY_ENV_OPENSEARCH_SECONDARY_URL,
    KEY_ENV_OPENSEARCH_URL,
    KEY_ENV_PCAP_FILTER,
    KEY_ENV_PCAP_IFACE,
    KEY_ENV_PCAP_NODE_NAME,
    KEY_ENV_PGID,
    KEY_ENV_PROFILE_KEY,
    KEY_ENV_PUID,
    KEY_ENV_ZEEK_EXTRACTOR_MODE,
    KEY_ENV_ZEEK_FILE_HTTP_SERVER_KEY,
    KEY_ENV_ZEEK_FILE_PRESERVATION,
    KEY_ENV_ZEEK_FILE_PRUNE_THRESHOLD_MAX_SIZE,
    KEY_ENV_ZEEK_FILE_PRUNE_THRESHOLD_TOTAL_DISK_USAGE_PERCENT,
    KEY_ENV_ZEEK_INTEL_FEED_SINCE,
    KEY_ENV_ZEEK_INTEL_ITEM_EXPIRATION,
    KEY_ENV_ZEEK_INTEL_REFRESH_CRON_EXPRESSION,
    KEY_ENV_ZEEK_VTOT_API2_KEY,
]

# 3. List-of-strings transform logic
_LIST_OF_STRING_VARS = [
    KEY_ENV_EXTRA_TAGS,
]


# 4. Custom transform logic
@dataclass(frozen=True)
class TransformHook:
    forward: Callable
    reverse: Optional[Callable] = None
    reverse_noop: bool = False


CUSTOM_TRANSFORM_HANDLERS: Dict[str, TransformHook] = {
    KEY_ENV_LOGSTASH_JAVA_OPTS: TransformHook(
        forward=custom_transform_logstash_java_opts,
        reverse=custom_reverse_transform_logstash_java_opts,
    ),
    KEY_ENV_ZEEK_DISABLE_ICS_ALL: TransformHook(
        forward=custom_transform_zeek_disable_ics_all,
        reverse=custom_reverse_transform_zeek_disable_ics_all,
    ),
    KEY_ENV_ZEEK_DISABLE_BEST_GUESS_ICS: TransformHook(
        forward=custom_transform_zeek_disable_best_guess_ics,
        reverse=custom_reverse_transform_zeek_disable_best_guess_ics,
    ),
    KEY_ENV_NETBOX_URL: TransformHook(
        forward=custom_transform_netbox_url,
        reverse=custom_reverse_transform_netbox_url,
    ),
    KEY_ENV_NETBOX_AUTO_POPULATE_SUBNET_FILTER: TransformHook(
        forward=custom_transform_netbox_auto_populate_subnet_filter,
        reverse=custom_reverse_transform_netbox_auto_populate_subnet_filter,
    ),
    KEY_ENV_LOGSTASH_HOST: TransformHook(
        forward=custom_transform_logstash_host,
        reverse=custom_reverse_transform_logstash_host,
    ),
    KEY_ENV_OPENSEARCH_PRIMARY: TransformHook(
        forward=custom_transform_opensearch_primary,
        reverse=custom_reverse_transform_opensearch_primary,
    ),
    KEY_ENV_OPENSEARCH_SECONDARY: TransformHook(
        forward=custom_transform_opensearch_secondary,
        reverse=custom_reverse_transform_opensearch_secondary,
    ),
    KEY_ENV_OPENSEARCH_URL: TransformHook(
        forward=custom_transform_opensearch_url,
        reverse=custom_reverse_transform_opensearch_url,
    ),
    KEY_ENV_OPENSEARCH_JAVA_OPTS: TransformHook(
        forward=custom_transform_opensearch_java_opts,
        reverse=custom_reverse_transform_opensearch_java_opts,
    ),
    KEY_ENV_PCAP_ENABLE_TCPDUMP: TransformHook(
        forward=custom_transform_pcap_enable_tcpdump,
        reverse=custom_reverse_transform_pcap_enable_tcpdump,
    ),
    KEY_ENV_CONTAINER_RUNTIME_KEY: TransformHook(
        forward=custom_transform_container_runtime_key,
        reverse=custom_reverse_transform_container_runtime_key,
    ),
    KEY_ENV_ARKIME_ROTATED_PCAP: TransformHook(
        forward=custom_transform_arkime_rotated_pcap,
        reverse=custom_reverse_transform_arkime_rotated_pcap,
    ),
    KEY_ENV_SURICATA_DISABLE_ICS_ALL: TransformHook(
        forward=custom_transform_suricata_disable_ics_all,
        reverse=custom_reverse_transform_suricata_disable_ics_all,
    ),
    KEY_ENV_SURICATA_ROTATED_PCAP: TransformHook(
        forward=custom_transform_suricata_rotated_pcap,
        reverse=custom_reverse_transform_suricata_rotated_pcap,
    ),
    KEY_ENV_ZEEK_FILE_ENABLE_VTOT: TransformHook(
        forward=custom_transform_zeek_file_enable_vtot,
        reverse=custom_reverse_transform_zeek_file_enable_vtot,
    ),
    # Preserve secret as string; treat '0' as unset
    KEY_ENV_ZEEK_VTOT_API2_KEY: TransformHook(
        forward=custom_transform_zeek_vtot_api2_key,
        reverse=custom_reverse_transform_zeek_vtot_api2_key,
    ),
    KEY_ENV_FILEBEAT_SYSLOG_TCP_LISTEN: TransformHook(
        forward=custom_transform_filebeat_syslog_tcp_listen,
        reverse=custom_reverse_transform_filebeat_syslog_tcp_listen,
        reverse_noop=True,
    ),
    KEY_ENV_ZEEK_DISABLE_STATS: TransformHook(
        forward=custom_transform_zeek_disable_stats,
        reverse=custom_reverse_transform_zeek_disable_stats,
    ),
    KEY_ENV_ZEEK_ROTATED_PCAP: TransformHook(
        forward=custom_transform_zeek_rotated_pcap,
        reverse=custom_reverse_transform_zeek_rotated_pcap,
    ),
    KEY_ENV_ZEEK_FILE_WATCHER_POLLING: TransformHook(
        forward=custom_transform_zeek_file_watcher_polling,
        reverse=custom_reverse_transform_zeek_file_watcher_polling,
    ),
    KEY_ENV_PCAP_PIPELINE_POLLING: TransformHook(
        forward=custom_transform_pcap_pipeline_polling,
        reverse=custom_reverse_transform_pcap_pipeline_polling,
    ),
    KEY_ENV_FILEBEAT_WATCHER_POLLING: TransformHook(
        forward=custom_transform_filebeat_watcher_polling,
        reverse=custom_reverse_transform_filebeat_watcher_polling,
    ),
    KEY_ENV_FILEBEAT_SYSLOG_UDP_LISTEN: TransformHook(
        forward=custom_transform_filebeat_syslog_udp_listen,
        reverse=custom_reverse_transform_filebeat_syslog_udp_listen,
        reverse_noop=True,
    ),
    # Live capture transforms
    KEY_ENV_ARKIME_LIVE_CAPTURE: TransformHook(
        forward=custom_transform_arkime_live_capture,
        reverse=custom_reverse_transform_arkime_live_capture,
    ),
    KEY_ENV_ZEEK_LIVE_CAPTURE: TransformHook(
        forward=custom_transform_zeek_live_capture,
        reverse=custom_reverse_transform_zeek_live_capture,
    ),
    KEY_ENV_SURICATA_LIVE_CAPTURE: TransformHook(
        forward=custom_transform_suricata_live_capture,
        reverse=custom_reverse_transform_suricata_live_capture,
    ),
    KEY_ENV_PCAP_ENABLE_NETSNIFF: TransformHook(
        forward=custom_transform_pcap_enable_netsniff,
        reverse=custom_reverse_transform_pcap_enable_netsniff,
    ),
    # Keep human-readable size/percent strings; write '0' when unset
    KEY_ENV_OPENSEARCH_INDEX_PRUNE_THRESHOLD: TransformHook(
        forward=custom_transform_opensearch_index_prune_threshold,
        reverse=custom_reverse_transform_opensearch_index_prune_threshold,
    ),
}

_CUSTOM_VARS = frozenset(CUSTOM_TRANSFORM_HANDLERS.keys())


@dataclass()
class EnvVariable:
    """
    Defines a specific environment variable name within a .env file,
    along with its transformation functions and requirement status.
    The transformation functions operate on the caller's provided argument to write to/from the .env file.
    """

    key: str
    file_name: str  # Name of the .env file that owns this environment variable (e.g., "common.env")
    variable_name: str  # The actual environment variable name (e.g., "OPENSEARCH_HOST")
    required: bool = False  # Whether the variable is required for the corresponding service to start
    config_items: List[str] = field(
        default_factory=list
    )  # List of config item keys that map to this environment variable
    transform: Callable = field(default=str_to_bool)
    reverse_transform: Callable = field(default=bool_to_str)
    # when true, reverse import skips setting values from this env var
    reverse_noop: bool = False
    # Per-item authority tags. Default behavior (both empty) => authoritative for all mapped items.
    authoritative_items: List[str] = field(default_factory=list)
    derived_items: List[str] = field(default_factory=list)

    def is_authoritative_for(self, item_key: str) -> bool:
        """Return True if this env var is authoritative for the given item.

        Rules:
        - If authoritative_items or derived_items are specified, explicit tags apply.
        - If neither list is specified, treat as authoritative for all mapped items.
        - If item_key is explicitly in derived_items, return False.
        - If authoritative_items is non-empty, only those items are authoritative.
        """
        if self.authoritative_items or self.derived_items:
            if item_key in self.derived_items:
                return False
            if self.authoritative_items:
                return item_key in self.authoritative_items
            # Only derived list provided; others are authoritative
            return True
        # No explicit tags provided => default authoritative
        return True


@dataclass()
class EnvMapper:
    """
    Maps environment variables to their corresponding .env files.
    The mapping is based on the .env.example files in the config/ directory and the env keys python constants.
    Provides methods to retrieve information about these definitions.
    """

    env_vars_by_file: Dict[str, List[EnvVariable]] = field(default_factory=lambda: defaultdict(list))
    env_var_by_map_key: Dict[str, EnvVariable] = field(default_factory=dict)
    # config item key -> ordered list of env map keys for reverse precedence (highest priority first)
    _reverse_precedence_by_item: Dict[str, List[str]] = field(default_factory=dict)

    def __init__(self):
        """
        Initialize the EnvMapper by scanning .env.example files.

        Args:
            None

        Note: config/ and the .env.example files are REQUIRED in order for the mapping to work.
        """
        self.env_vars_by_file = defaultdict(list)
        self.env_var_by_map_key = {}
        self._reverse_precedence_by_item = {}

        config_dir = get_default_config_dir()
        if not os.path.isdir(config_dir):
            InstallerLogger.warning(f"Configuration directory '{config_dir}' not found. EnvMapper will be empty.")
            return

        if dotenv_lib := DotEnvDynamic():
            # Scan .env.example files for environment variable mappings
            for dirpath, _, filenames in os.walk(config_dir):
                for example_filename in filenames:
                    if example_filename.endswith(".env.example"):
                        current_env_file_name_str = example_filename.replace(".example", "")
                        filepath = os.path.join(dirpath, example_filename)
                        if os.path.isfile(filepath):
                            try:
                                for env_var_name_from_file in dotenv_lib.dotenv_values(filepath).keys():
                                    map_key_constant_value = None

                                    # Do an exact dictionary lookup
                                    if env_var_name_from_file != ALL_ENV_KEYS_DICT.get(env_var_name_from_file):
                                        continue

                                    map_key_constant_value = ALL_ENV_KEYS_DICT.get(env_var_name_from_file)

                                    # Create the EnvVariable instance
                                    env_var_instance = EnvVariable(
                                        key=map_key_constant_value,
                                        file_name=current_env_file_name_str,
                                        variable_name=env_var_name_from_file,
                                        required=False,
                                        transform=None,
                                        reverse_transform=None,
                                    )

                                    if map_key_constant_value in _CUSTOM_VARS:
                                        self._handle_custom_transform(env_var_instance, map_key_constant_value)
                                    elif map_key_constant_value in _LIST_OF_STRING_VARS:
                                        env_var_instance.transform = _default_list_of_strings_transform
                                        env_var_instance.reverse_transform = _default_list_of_strings_reverse_transform
                                    elif map_key_constant_value in _STRING_VARS:
                                        env_var_instance.transform = _default_string_transform
                                        env_var_instance.reverse_transform = _default_string_reverse_transform
                                    elif map_key_constant_value in _BOOLEAN_VARS:
                                        # Booleans should be written to .env files as lowercase strings ("true"/"false")
                                        # and parsed back from strings to native Python bools when loading.
                                        env_var_instance.transform = bool_to_str
                                        env_var_instance.reverse_transform = str_to_bool
                                    else:
                                        InstallerLogger.error(f"Invalid env map key constant: {map_key_constant_value}")
                                        raise ValueError(f"Invalid map key constant value: {map_key_constant_value}")

                                    # populate maps
                                    self.env_vars_by_file[current_env_file_name_str].append(env_var_instance)
                                    self.env_var_by_map_key[map_key_constant_value] = env_var_instance

                                    # else:
                                    # print(f"Debug: Variable '{env_var_name_from_file}' in '{filepath}' not a managed key in env_keys.")

                            except Exception as e:
                                InstallerLogger.error(f"EnvMapper error processing '{filepath}': {e}")

                        else:
                            InstallerLogger.warning(f"EnvMapper scan skipped missing file: {filepath}")

        try:
            # Arkime
            self.env_var_by_map_key[KEY_ENV_ARKIME_MANAGE_PCAP_FILES].config_items = [
                KEY_CONFIG_ITEM_ARKIME_MANAGE_PCAP
            ]
            self.env_var_by_map_key[KEY_ENV_ARKIME_MANAGE_PCAP_FILES].derived_items = [
                KEY_CONFIG_ITEM_CLEAN_UP_OLD_ARTIFACTS,
            ]
            self.env_var_by_map_key[KEY_ENV_ARKIME_FREESPACEG].config_items = [KEY_CONFIG_ITEM_ARKIME_FREESPACEG]
            self.env_var_by_map_key[KEY_ENV_ARKIME_LIVE_CAPTURE].config_items = [
                KEY_CONFIG_ITEM_LIVE_ARKIME,
                KEY_CONFIG_ITEM_CAPTURE_LIVE_NETWORK_TRAFFIC,
            ]
            # CAPTURE_LIVE_NETWORK_TRAFFIC is derived/managed by dependency system
            self.env_var_by_map_key[KEY_ENV_ARKIME_LIVE_CAPTURE].derived_items = [
                KEY_CONFIG_ITEM_CAPTURE_LIVE_NETWORK_TRAFFIC
            ]
            self.env_var_by_map_key[KEY_ENV_ARKIME_LIVE_NODE_HOST].config_items = [
                KEY_CONFIG_ITEM_LIVE_ARKIME_NODE_HOST
            ]
            self.env_var_by_map_key[KEY_ENV_ARKIME_LIVE_COMP_TYPE].config_items = [
                KEY_CONFIG_ITEM_LIVE_ARKIME_COMP_TYPE
            ]
            self.env_var_by_map_key[KEY_ENV_ARKIME_LIVE_COMP_LEVEL].config_items = [
                KEY_CONFIG_ITEM_LIVE_ARKIME_COMP_LEVEL
            ]
            self.env_var_by_map_key[KEY_ENV_ARKIME_ROTATED_PCAP].config_items = [
                KEY_CONFIG_ITEM_AUTO_ARKIME,
                KEY_CONFIG_ITEM_LIVE_ARKIME,
            ]
            # Rotated flag is derived; do not treat it as authoritative for either item
            self.env_var_by_map_key[KEY_ENV_ARKIME_ROTATED_PCAP].derived_items = [
                KEY_CONFIG_ITEM_AUTO_ARKIME,
                KEY_CONFIG_ITEM_LIVE_ARKIME,
            ]
            self.env_var_by_map_key[KEY_ENV_ARKIME_AUTO_ANALYZE_PCAP_FILES].config_items = [KEY_CONFIG_ITEM_AUTO_ARKIME]
            self.env_var_by_map_key[KEY_ENV_ARKIME_INDEX_MANAGEMENT_ENABLED].config_items = [
                KEY_CONFIG_ITEM_INDEX_MANAGEMENT_POLICY
            ]
            self.env_var_by_map_key[KEY_ENV_ARKIME_INDEX_MANAGEMENT_HOT_WARM_ENABLED].config_items = [
                KEY_CONFIG_ITEM_INDEX_MANAGEMENT_HOT_WARM
            ]
            self.env_var_by_map_key[KEY_ENV_ARKIME_INDEX_MANAGEMENT_OPTIMIZATION_PERIOD].config_items = [
                KEY_CONFIG_ITEM_INDEX_MANAGEMENT_OPTIMIZATION_TIME_PERIOD
            ]
            self.env_var_by_map_key[KEY_ENV_ARKIME_INDEX_MANAGEMENT_RETENTION_TIME].config_items = [
                KEY_CONFIG_ITEM_INDEX_MANAGEMENT_SPI_DATA_RETENTION
            ]
            self.env_var_by_map_key[KEY_ENV_ARKIME_INDEX_MANAGEMENT_OLDER_SESSION_REPLICAS].config_items = [
                KEY_CONFIG_ITEM_INDEX_MANAGEMENT_REPLICAS
            ]
            self.env_var_by_map_key[KEY_ENV_ARKIME_INDEX_MANAGEMENT_HISTORY_RETENTION_WEEKS].config_items = [
                KEY_CONFIG_ITEM_INDEX_MANAGEMENT_HISTORY_IN_WEEKS
            ]
            self.env_var_by_map_key[KEY_ENV_ARKIME_INDEX_MANAGEMENT_SEGMENTS].config_items = [
                KEY_CONFIG_ITEM_INDEX_MANAGEMENT_OPTIMIZE_SESSION_SEGMENTS
            ]

            # Logstash
            self.env_var_by_map_key[KEY_ENV_LOGSTASH_HOST].config_items = [
                KEY_CONFIG_ITEM_LOGSTASH_HOST,
                KEY_CONFIG_ITEM_REMOTE_MALCOLM_HOST,
            ]
            self.env_var_by_map_key[KEY_ENV_LOGSTASH_HOST].derived_items = [KEY_CONFIG_ITEM_REMOTE_MALCOLM_HOST]
            self.env_var_by_map_key[KEY_ENV_LOGSTASH_PIPELINE_WORKERS].config_items = [KEY_CONFIG_ITEM_LS_WORKERS]
            self.env_var_by_map_key[KEY_ENV_LOGSTASH_REVERSE_DNS].config_items = [KEY_CONFIG_ITEM_REVERSE_DNS]
            self.env_var_by_map_key[KEY_ENV_LOGSTASH_OUI_LOOKUP].config_items = [KEY_CONFIG_ITEM_AUTO_OUI]
            self.env_var_by_map_key[KEY_ENV_LOGSTASH_JAVA_OPTS].config_items = [KEY_CONFIG_ITEM_LS_MEMORY]
            self.env_var_by_map_key[KEY_ENV_FREQ_LOOKUP].config_items = [KEY_CONFIG_ITEM_AUTO_FREQ]

            # Filebeat
            self.env_var_by_map_key[KEY_ENV_FILEBEAT_TCP_LISTEN].config_items = [KEY_CONFIG_ITEM_EXPOSE_FILEBEAT_TCP]
            self.env_var_by_map_key[KEY_ENV_FILEBEAT_TCP_LOG_FORMAT].config_items = [
                KEY_CONFIG_ITEM_FILEBEAT_TCP_LOG_FORMAT
            ]
            self.env_var_by_map_key[KEY_ENV_FILEBEAT_TCP_PARSE_SOURCE_FIELD].config_items = [
                KEY_CONFIG_ITEM_FILEBEAT_TCP_PARSE_SOURCE_FIELD
            ]
            self.env_var_by_map_key[KEY_ENV_FILEBEAT_TCP_PARSE_TARGET_FIELD].config_items = [
                KEY_CONFIG_ITEM_FILEBEAT_TCP_PARSE_TARGET_FIELD
            ]
            self.env_var_by_map_key[KEY_ENV_FILEBEAT_TCP_PARSE_DROP_FIELD].config_items = [
                KEY_CONFIG_ITEM_FILEBEAT_TCP_PARSE_DROP_FIELD
            ]
            self.env_var_by_map_key[KEY_ENV_FILEBEAT_TCP_TAG].config_items = [KEY_CONFIG_ITEM_FILEBEAT_TCP_TAG]
            self.env_var_by_map_key[KEY_ENV_FILEBEAT_WATCHER_POLLING].config_items = [
                KEY_CONFIG_ITEM_DOCKER_ORCHESTRATION_MODE
            ]
            self.env_var_by_map_key[KEY_ENV_FILEBEAT_SYSLOG_TCP_LISTEN].config_items = [KEY_CONFIG_ITEM_SYSLOG_TCP_PORT]
            # Derived: listen is implied by port; do not set port from listen
            self.env_var_by_map_key[KEY_ENV_FILEBEAT_SYSLOG_TCP_LISTEN].derived_items = [
                KEY_CONFIG_ITEM_SYSLOG_TCP_PORT
            ]
            self.env_var_by_map_key[KEY_ENV_FILEBEAT_SYSLOG_TCP_PORT].config_items = [
                KEY_CONFIG_ITEM_SYSLOG_TCP_PORT,
            ]
            self.env_var_by_map_key[KEY_ENV_FILEBEAT_SYSLOG_UDP_LISTEN].config_items = [KEY_CONFIG_ITEM_SYSLOG_UDP_PORT]
            # Derived: listen is implied by port; do not set port from listen
            self.env_var_by_map_key[KEY_ENV_FILEBEAT_SYSLOG_UDP_LISTEN].derived_items = [
                KEY_CONFIG_ITEM_SYSLOG_UDP_PORT
            ]
            self.env_var_by_map_key[KEY_ENV_FILEBEAT_SYSLOG_UDP_PORT].config_items = [
                KEY_CONFIG_ITEM_SYSLOG_UDP_PORT,
            ]

            # NetBox
            self.env_var_by_map_key[KEY_ENV_NETBOX_ENRICHMENT].config_items = [KEY_CONFIG_ITEM_NETBOX_LOGSTASH_ENRICH]
            self.env_var_by_map_key[KEY_ENV_NETBOX_AUTO_CREATE_PREFIX].config_items = [
                KEY_CONFIG_ITEM_NETBOX_LOGSTASH_AUTO_CREATE_PREFIX
            ]
            self.env_var_by_map_key[KEY_ENV_NETBOX_AUTO_POPULATE].config_items = [KEY_CONFIG_ITEM_NETBOX_AUTO_POPULATE]
            self.env_var_by_map_key[KEY_ENV_NETBOX_DEFAULT_SITE].config_items = [KEY_CONFIG_ITEM_NETBOX_SITE_NAME]
            self.env_var_by_map_key[KEY_ENV_NETBOX_AUTO_POPULATE_SUBNET_FILTER].config_items = [
                KEY_CONFIG_ITEM_NETBOX_AUTO_POPULATE_SUBNET_FILTER
            ]
            self.env_var_by_map_key[KEY_ENV_NETBOX_URL].config_items = [
                KEY_CONFIG_ITEM_NETBOX_MODE,
                KEY_CONFIG_ITEM_NETBOX_URL,
            ]
            # Treat NETBOX_URL as authoritative for URL, derived for mode (NETBOX_MODE env is authoritative for mode)
            self.env_var_by_map_key[KEY_ENV_NETBOX_URL].authoritative_items = [KEY_CONFIG_ITEM_NETBOX_URL]
            self.env_var_by_map_key[KEY_ENV_NETBOX_URL].derived_items = [KEY_CONFIG_ITEM_NETBOX_MODE]
            self.env_var_by_map_key[KEY_ENV_NETBOX_MODE].config_items = [KEY_CONFIG_ITEM_NETBOX_MODE]

            # Nginx
            self.env_var_by_map_key[KEY_ENV_NGINX_SSL].config_items = [KEY_CONFIG_ITEM_NGINX_SSL]
            self.env_var_by_map_key[KEY_ENV_NGINX_RESOLVER_IPV4].config_items = [KEY_CONFIG_ITEM_NGINX_RESOLVER_IPV4]
            self.env_var_by_map_key[KEY_ENV_NGINX_RESOLVER_IPV6].config_items = [KEY_CONFIG_ITEM_NGINX_RESOLVER_IPV6]

            # OpenSearch
            self.env_var_by_map_key[KEY_ENV_OPENSEARCH_INDEX_PRUNE_THRESHOLD].config_items = [
                KEY_CONFIG_ITEM_INDEX_PRUNE_THRESHOLD
            ]
            self.env_var_by_map_key[KEY_ENV_OPENSEARCH_INDEX_PRUNE_THRESHOLD].derived_items = [
                KEY_CONFIG_ITEM_CLEAN_UP_OLD_INDICES,
                KEY_CONFIG_ITEM_CLEAN_UP_OLD_ARTIFACTS,
            ]
            self.env_var_by_map_key[KEY_ENV_OPENSEARCH_INDEX_SIZE_PRUNE_NAME_SORT].config_items = [
                KEY_CONFIG_ITEM_INDEX_PRUNE_NAME_SORT
            ]
            self.env_var_by_map_key[KEY_ENV_OPENSEARCH_PRIMARY].config_items = [KEY_CONFIG_ITEM_OPENSEARCH_PRIMARY_MODE]
            self.env_var_by_map_key[KEY_ENV_OPENSEARCH_URL].config_items = [
                KEY_CONFIG_ITEM_OPENSEARCH_PRIMARY_MODE,
                KEY_CONFIG_ITEM_OPENSEARCH_PRIMARY_URL,
            ]
            self.env_var_by_map_key[KEY_ENV_OPENSEARCH_SSL_CERTIFICATE_VERIFICATION].config_items = [
                KEY_CONFIG_ITEM_OPENSEARCH_PRIMARY_SSL_VERIFY
            ]
            self.env_var_by_map_key[KEY_ENV_OPENSEARCH_SECONDARY_URL].config_items = [
                KEY_CONFIG_ITEM_OPENSEARCH_SECONDARY_URL
            ]
            self.env_var_by_map_key[KEY_ENV_OPENSEARCH_SECONDARY_SSL_CERTIFICATE_VERIFICATION].config_items = [
                KEY_CONFIG_ITEM_OPENSEARCH_SECONDARY_SSL_VERIFY
            ]
            self.env_var_by_map_key[KEY_ENV_OPENSEARCH_SECONDARY].config_items = [
                KEY_CONFIG_ITEM_OPENSEARCH_SECONDARY_MODE
            ]
            self.env_var_by_map_key[KEY_ENV_OPENSEARCH_JAVA_OPTS].config_items = [KEY_CONFIG_ITEM_OS_MEMORY]
            self.env_var_by_map_key[KEY_ENV_OPENSEARCH_DASHBOARDS_URL].config_items = [KEY_CONFIG_ITEM_DASHBOARDS_URL]
            self.env_var_by_map_key[KEY_ENV_OPENSEARCH_DASHBOARDS_DARKMODE].config_items = [
                KEY_CONFIG_ITEM_DASHBOARDS_DARK_MODE
            ]

            # PCAP capture
            self.env_var_by_map_key[KEY_ENV_PCAP_ENABLE_NETSNIFF].config_items = [
                KEY_CONFIG_ITEM_PCAP_NETSNIFF,
                KEY_CONFIG_ITEM_CAPTURE_LIVE_NETWORK_TRAFFIC,
            ]
            # CAPTURE_LIVE_NETWORK_TRAFFIC is derived/managed by dependency system
            self.env_var_by_map_key[KEY_ENV_PCAP_ENABLE_NETSNIFF].derived_items = [
                KEY_CONFIG_ITEM_CAPTURE_LIVE_NETWORK_TRAFFIC
            ]
            self.env_var_by_map_key[KEY_ENV_PCAP_ENABLE_TCPDUMP].config_items = [
                KEY_CONFIG_ITEM_PCAP_TCPDUMP,
                KEY_CONFIG_ITEM_PCAP_NETSNIFF,
                KEY_CONFIG_ITEM_CAPTURE_LIVE_NETWORK_TRAFFIC,
            ]
            # Only authoritative for tcpdump; derived (non-authoritative) for netsniff and live capture
            self.env_var_by_map_key[KEY_ENV_PCAP_ENABLE_TCPDUMP].authoritative_items = [KEY_CONFIG_ITEM_PCAP_TCPDUMP]
            self.env_var_by_map_key[KEY_ENV_PCAP_ENABLE_TCPDUMP].derived_items = [
                KEY_CONFIG_ITEM_PCAP_NETSNIFF,
                KEY_CONFIG_ITEM_CAPTURE_LIVE_NETWORK_TRAFFIC,
            ]
            self.env_var_by_map_key[KEY_ENV_PCAP_IFACE_TWEAK].config_items = [KEY_CONFIG_ITEM_TWEAK_IFACE]
            self.env_var_by_map_key[KEY_ENV_PCAP_IFACE].config_items = [KEY_CONFIG_ITEM_PCAP_IFACE]
            self.env_var_by_map_key[KEY_ENV_PCAP_FILTER].config_items = [KEY_CONFIG_ITEM_PCAP_FILTER]
            self.env_var_by_map_key[KEY_ENV_PCAP_NODE_NAME].config_items = [KEY_CONFIG_ITEM_PCAP_NODE_NAME]
            self.env_var_by_map_key[KEY_ENV_EXTRA_TAGS].config_items = [KEY_CONFIG_ITEM_EXTRA_TAGS]
            self.env_var_by_map_key[KEY_ENV_PCAP_PIPELINE_POLLING].config_items = [
                KEY_CONFIG_ITEM_DOCKER_ORCHESTRATION_MODE
            ]

            self.env_var_by_map_key[KEY_ENV_ARKIME_EXPOSE_WISE].config_items = [KEY_CONFIG_ITEM_ARKIME_EXPOSE_WISE]
            self.env_var_by_map_key[KEY_ENV_ARKIME_ALLOW_WISE_CONFIG].config_items = [
                KEY_CONFIG_ITEM_ARKIME_ALLOW_WISE_CONFIG
            ]
            self.env_var_by_map_key[KEY_ENV_ARKIME_WISE_URL].config_items = [KEY_CONFIG_ITEM_ARKIME_WISE_URL]

            # Malcolm
            self.env_var_by_map_key[KEY_ENV_PGID].config_items = [KEY_CONFIG_ITEM_PROCESS_GROUP_ID]
            self.env_var_by_map_key[KEY_ENV_PUID].config_items = [KEY_CONFIG_ITEM_PROCESS_USER_ID]
            self.env_var_by_map_key[KEY_ENV_PROFILE_KEY].config_items = [KEY_CONFIG_ITEM_MALCOLM_PROFILE]
            self.env_var_by_map_key[KEY_ENV_CONTAINER_RUNTIME_KEY].config_items = [
                KEY_CONFIG_ITEM_DOCKER_ORCHESTRATION_MODE,
                KEY_CONFIG_ITEM_RUNTIME_BIN,
            ]

            # Suricata
            self.env_var_by_map_key[KEY_ENV_SURICATA_UPDATE_RULES].config_items = [KEY_CONFIG_ITEM_SURICATA_RULE_UPDATE]
            self.env_var_by_map_key[KEY_ENV_SURICATA_DISABLE_ICS_ALL].config_items = [KEY_CONFIG_ITEM_MALCOLM_ICS]
            self.env_var_by_map_key[KEY_ENV_SURICATA_LIVE_CAPTURE].config_items = [
                KEY_CONFIG_ITEM_LIVE_SURICATA,
                KEY_CONFIG_ITEM_CAPTURE_LIVE_NETWORK_TRAFFIC,
            ]
            # CAPTURE_LIVE_NETWORK_TRAFFIC is derived/managed by dependency system
            self.env_var_by_map_key[KEY_ENV_SURICATA_LIVE_CAPTURE].derived_items = [
                KEY_CONFIG_ITEM_CAPTURE_LIVE_NETWORK_TRAFFIC
            ]
            self.env_var_by_map_key[KEY_ENV_SURICATA_STATS_ENABLED].config_items = [KEY_CONFIG_ITEM_CAPTURE_STATS]
            self.env_var_by_map_key[KEY_ENV_SURICATA_STATS_EVE_ENABLED].config_items = [KEY_CONFIG_ITEM_CAPTURE_STATS]
            self.env_var_by_map_key[KEY_ENV_SURICATA_ROTATED_PCAP].config_items = [
                KEY_CONFIG_ITEM_AUTO_SURICATA,
                KEY_CONFIG_ITEM_LIVE_SURICATA,
            ]
            self.env_var_by_map_key[KEY_ENV_SURICATA_AUTO_ANALYZE_PCAP_FILES].config_items = [
                KEY_CONFIG_ITEM_AUTO_SURICATA
            ]

            # Zeek
            self.env_var_by_map_key[KEY_ENV_ZEEK_FILE_ENABLE_VTOT].config_items = [KEY_CONFIG_ITEM_VTOT_API_KEY]
            # This env var signals presence of a key but cannot reconstruct it; treat as derived
            self.env_var_by_map_key[KEY_ENV_ZEEK_FILE_ENABLE_VTOT].derived_items = [KEY_CONFIG_ITEM_VTOT_API_KEY]
            self.env_var_by_map_key[KEY_ENV_ZEEK_EXTRACTOR_MODE].config_items = [KEY_CONFIG_ITEM_FILE_CARVE_MODE]
            self.env_var_by_map_key[KEY_ENV_ZEEK_FILE_PRESERVATION].config_items = [KEY_CONFIG_ITEM_FILE_PRESERVE_MODE]
            self.env_var_by_map_key[KEY_ENV_ZEEK_DISABLE_ICS_ALL].config_items = [KEY_CONFIG_ITEM_MALCOLM_ICS]
            self.env_var_by_map_key[KEY_ENV_ZEEK_DISABLE_BEST_GUESS_ICS].config_items = [
                KEY_CONFIG_ITEM_ZEEK_ICS_BEST_GUESS
            ]
            self.env_var_by_map_key[KEY_ENV_ZEEK_LIVE_CAPTURE].config_items = [
                KEY_CONFIG_ITEM_LIVE_ZEEK,
                KEY_CONFIG_ITEM_CAPTURE_LIVE_NETWORK_TRAFFIC,
            ]
            # CAPTURE_LIVE_NETWORK_TRAFFIC is derived/managed by dependency system
            self.env_var_by_map_key[KEY_ENV_ZEEK_LIVE_CAPTURE].derived_items = [
                KEY_CONFIG_ITEM_CAPTURE_LIVE_NETWORK_TRAFFIC
            ]
            self.env_var_by_map_key[KEY_ENV_ZEEK_DISABLE_STATS].config_items = [KEY_CONFIG_ITEM_CAPTURE_STATS]
            self.env_var_by_map_key[KEY_ENV_ZEEK_ROTATED_PCAP].config_items = [
                KEY_CONFIG_ITEM_AUTO_ZEEK,
                KEY_CONFIG_ITEM_LIVE_ZEEK,
            ]
            # Rotated flag is derived; do not treat it as authoritative for either item
            self.env_var_by_map_key[KEY_ENV_ZEEK_ROTATED_PCAP].derived_items = [
                KEY_CONFIG_ITEM_AUTO_ZEEK,
                KEY_CONFIG_ITEM_LIVE_ZEEK,
            ]
            self.env_var_by_map_key[KEY_ENV_ZEEK_AUTO_ANALYZE_PCAP_FILES].config_items = [KEY_CONFIG_ITEM_AUTO_ZEEK]
            self.env_var_by_map_key[KEY_ENV_ZEEK_INTEL_REFRESH_ON_STARTUP].config_items = [
                KEY_CONFIG_ITEM_ZEEK_INTEL_ON_STARTUP
            ]
            self.env_var_by_map_key[KEY_ENV_ZEEK_INTEL_REFRESH_CRON_EXPRESSION].config_items = [
                KEY_CONFIG_ITEM_ZEEK_INTEL_CRON_EXPRESSION
            ]
            self.env_var_by_map_key[KEY_ENV_ZEEK_INTEL_FEED_SINCE].config_items = [
                KEY_CONFIG_ITEM_ZEEK_INTEL_FEED_SINCE
            ]
            self.env_var_by_map_key[KEY_ENV_ZEEK_INTEL_ITEM_EXPIRATION].config_items = [
                KEY_CONFIG_ITEM_ZEEK_INTEL_ITEM_EXPIRATION
            ]
            self.env_var_by_map_key[KEY_ENV_ZEEK_VTOT_API2_KEY].config_items = [KEY_CONFIG_ITEM_VTOT_API_KEY]
            self.env_var_by_map_key[KEY_ENV_ZEEK_FILE_PRUNE_THRESHOLD_TOTAL_DISK_USAGE_PERCENT].config_items = [
                KEY_CONFIG_ITEM_EXTRACTED_FILE_MAX_PERCENT_THRESHOLD
            ]
            self.env_var_by_map_key[KEY_ENV_ZEEK_FILE_PRUNE_THRESHOLD_MAX_SIZE].config_items = [
                KEY_CONFIG_ITEM_EXTRACTED_FILE_MAX_SIZE_THRESHOLD
            ]
            self.env_var_by_map_key[KEY_ENV_ZEEK_FILE_HTTP_SERVER_ENABLE].config_items = [
                KEY_CONFIG_ITEM_FILE_CARVE_HTTP_SERVER
            ]
            self.env_var_by_map_key[KEY_ENV_ZEEK_FILE_HTTP_SERVER_ZIP].config_items = [
                KEY_CONFIG_ITEM_FILE_CARVE_HTTP_SERVER_ZIP
            ]
            self.env_var_by_map_key[KEY_ENV_ZEEK_FILE_HTTP_SERVER_KEY].config_items = [
                KEY_CONFIG_ITEM_FILE_CARVE_HTTP_SERVE_ENCRYPT_KEY
            ]
            self.env_var_by_map_key[KEY_ENV_ZEEK_FILE_ENABLE_YARA].config_items = [KEY_CONFIG_ITEM_YARA_SCAN]
            self.env_var_by_map_key[KEY_ENV_ZEEK_FILE_ENABLE_CAPA].config_items = [KEY_CONFIG_ITEM_CAPA_SCAN]
            self.env_var_by_map_key[KEY_ENV_ZEEK_FILE_ENABLE_CLAMAV].config_items = [KEY_CONFIG_ITEM_CLAM_AV_SCAN]
            self.env_var_by_map_key[KEY_ENV_ZEEK_FILE_UPDATE_RULES].config_items = [
                KEY_CONFIG_ITEM_FILE_SCAN_RULE_UPDATE
            ]
            self.env_var_by_map_key[KEY_ENV_ZEEK_FILE_WATCHER_POLLING].config_items = [
                KEY_CONFIG_ITEM_DOCKER_ORCHESTRATION_MODE
            ]
            # Polling flags are derived from orchestration mode
            self.env_var_by_map_key[KEY_ENV_ZEEK_FILE_WATCHER_POLLING].derived_items = [
                KEY_CONFIG_ITEM_DOCKER_ORCHESTRATION_MODE
            ]

            # reverse precedence configuration (conflict-prone items)

            # orchestration mode: authoritative CONTAINER_RUNTIME_KEY
            self._reverse_precedence_by_item[KEY_CONFIG_ITEM_DOCKER_ORCHESTRATION_MODE] = [
                KEY_ENV_CONTAINER_RUNTIME_KEY,
                # We don't derive orchestration mode from polling, they could have reason
                #   to set polling = false without using kubernetes. runtime is enough.
                # KEY_ENV_ZEEK_FILE_WATCHER_POLLING,
                # KEY_ENV_PCAP_PIPELINE_POLLING,
                # KEY_ENV_FILEBEAT_WATCHER_POLLING,
            ]

            # live capture flags: direct live capture beats rotated-pcap derived value
            self._reverse_precedence_by_item[KEY_CONFIG_ITEM_LIVE_ARKIME] = [
                KEY_ENV_ARKIME_LIVE_CAPTURE,
                KEY_ENV_ARKIME_ROTATED_PCAP,
            ]
            self._reverse_precedence_by_item[KEY_CONFIG_ITEM_LIVE_SURICATA] = [
                KEY_ENV_SURICATA_LIVE_CAPTURE,
                KEY_ENV_SURICATA_ROTATED_PCAP,
            ]
            self._reverse_precedence_by_item[KEY_CONFIG_ITEM_LIVE_ZEEK] = [
                KEY_ENV_ZEEK_LIVE_CAPTURE,
                KEY_ENV_ZEEK_ROTATED_PCAP,
            ]

            # netbox: explicit mode overrides URL-implied remote
            self._reverse_precedence_by_item[KEY_CONFIG_ITEM_NETBOX_MODE] = [
                KEY_ENV_NETBOX_MODE,
                KEY_ENV_NETBOX_URL,
            ]

            # Mark remaining polling flags as derived for orchestration as well
            self.env_var_by_map_key[KEY_ENV_PCAP_PIPELINE_POLLING].derived_items = [
                KEY_CONFIG_ITEM_DOCKER_ORCHESTRATION_MODE
            ]
            self.env_var_by_map_key[KEY_ENV_FILEBEAT_WATCHER_POLLING].derived_items = [
                KEY_CONFIG_ITEM_DOCKER_ORCHESTRATION_MODE
            ]

        except KeyError as ke:
            InstallerLogger.error(
                f"Error setting up default .env mappings ({ke}), likely missing .env.example template files"
            )
            raise FileOperationError(f"Failed to load {ke} from .env.example template files")

    # Convenience APIs used by MalcolmConfig and tests
    def has_env_mapping(self, item_key: str) -> bool:
        """Return True if any EnvVariable maps to the given item key."""
        for ev in self.env_var_by_map_key.values():
            if item_key in ev.config_items:
                return True
        return False

    def get_item_to_env_mapping(self) -> Dict[str, List[EnvVariable]]:
        """Return mapping of item key -> list of EnvVariable that map to it."""
        mapping: Dict[str, List[EnvVariable]] = defaultdict(list)
        for ev in self.env_var_by_map_key.values():
            for item_key in ev.config_items:
                mapping[item_key].append(ev)
        return mapping

    def _handle_custom_transform(self, env_var_instance: EnvVariable, key: str):
        """
        Handles custom transformations for environment variables.

        Args:
            env_var_instance: The EnvVariable instance to modify
            key: The Python constant for the environment variable key
        """
        hook = CUSTOM_TRANSFORM_HANDLERS.get(key)
        if not hook:
            raise ValueError(f"No custom transform handler registered for {key}")

        env_var_instance.transform = hook.forward
        if hook.reverse is not None:
            env_var_instance.reverse_transform = hook.reverse
        if hook.reverse_noop:
            env_var_instance.reverse_noop = True

    def get_env_variable(self, map_key_constant_value: str) -> Optional[EnvVariable]:
        """
        Retrieves a specific EnvVariable object by its map key constant.
        Args:
            map_key_constant_value: The Python constant for the environment variable key
                              (e.g., env_keys.KEY_ENV_...).
        Returns:
            The EnvVariable object if found, otherwise None.
        """
        return self.env_var_by_map_key.get(map_key_constant_value)

    def get_file_for_variable(self, variable_name: str) -> Optional[str]:
        """
        Retrieves the .env file name that contains a specific environment variable.

        Args:
            variable_name: The name of the environment variable to search for.

        Returns:
            The name of the .env file containing the variable if found, otherwise None.
        """
        for file_name, var_list in self.env_vars_by_file.items():
            for var_instance in var_list:
                if var_instance.variable_name == variable_name:
                    return file_name
        return None

    def get_variables_for_file(self, file_name: str) -> Optional[List[EnvVariable]]:
        """
        Retrieves all EnvVariable objects for a specific .env file.

        Args:
            file_name: The name of the .env file.

        Returns:
            A list of EnvVariable objects if the file is found, otherwise None.
            Returns a copy of the list; empty if the file exists but has no variables.
        """
        variables_list = self.env_vars_by_file.get(file_name)
        if variables_list is not None:
            return list(variables_list)  # Return a copy
        return None

    def get_all_file_names(self) -> List[str]:
        """
        Retrieves a list of all configured .env file names.

        Returns:
            A list of strings, where each string is a configured .env file name.
        """
        return list(self.env_vars_by_file.keys())

    def get_env_vars_by_item_key(self, item_key: str):
        """Return a list of EnvVariable instances mapped to the given ConfigItem key."""
        result = []
        for env_var in self.env_var_by_map_key.values():
            if item_key in env_var.config_items:
                result.append(env_var)
        return result

    def get_item_keys_by_env_var(self, variable_name: str):
        """Return the list of ConfigItem keys associated with a raw environment variable name."""
        # First, locate the EnvVariable object with this variable name
        for env_var in self.env_var_by_map_key.values():
            if env_var.variable_name == variable_name:
                return list(env_var.config_items)
        return []

    def get_reverse_precedence_for_item(self, item_key: str) -> List[str]:
        """Return ordered env map keys that can set this item during reverse mapping.

        Highest priority first. Empty when no explicit precedence is defined.
        """
        return list(self._reverse_precedence_by_item.get(item_key, []))
