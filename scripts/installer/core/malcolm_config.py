#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2025 Battelle Energy Alliance, LLC.  All rights reserved.

"""Configuration store for Malcolm installer settings."""

import glob
import os
import re
import sys
import copy
import shutil

from collections import defaultdict
from enum import Enum
from typing import Dict, Any, Callable, List, Tuple, Optional

from scripts.malcolm_constants import (
    COMPOSE_MALCOLM_EXTENSION,
    COMPOSE_MALCOLM_EXTENSION_HEDGEHOG,
    COMPOSE_MALCOLM_EXTENSION_HEDGEHOG_REACHBACK_REQUEST_ACL,
    COMPOSE_MALCOLM_EXTENSION_AUX_FW,
    COMPOSE_MALCOLM_EXTENSION_AUX_FW_AIDE,
    COMPOSE_MALCOLM_EXTENSION_AUX_FW_AUDITLOG,
    COMPOSE_MALCOLM_EXTENSION_AUX_FW_CPU,
    COMPOSE_MALCOLM_EXTENSION_AUX_FW_DF,
    COMPOSE_MALCOLM_EXTENSION_AUX_FW_DISK,
    COMPOSE_MALCOLM_EXTENSION_AUX_FW_KMSG,
    COMPOSE_MALCOLM_EXTENSION_AUX_FW_MEM,
    COMPOSE_MALCOLM_EXTENSION_AUX_FW_NETWORK,
    COMPOSE_MALCOLM_EXTENSION_AUX_FW_SYSTEMD,
    COMPOSE_MALCOLM_EXTENSION_AUX_FW_THERMAL,
    COMPOSE_MALCOLM_EXTENSION_PRUNE,
    COMPOSE_MALCOLM_EXTENSION_PRUNE_PCAP,
    COMPOSE_MALCOLM_EXTENSION_PRUNE_LOGS,
)
from scripts.malcolm_common import (
    DEFAULT_INDEX_DIR,
    DEFAULT_INDEX_SNAPSHOT_DIR,
    DEFAULT_PCAP_DIR,
    DEFAULT_SURICATA_LOG_DIR,
    DEFAULT_ZEEK_LOG_DIR,
    DotEnvDynamic,
    FILEBEAT_ZEEK_LOG_CONTAINER_PATH,
    get_default_config_dir,
    LocalPathForContainerBindMount,
    OPENSEARCH_BACKUP_CONTAINER_PATH,
    OPENSEARCH_DATA_CONTAINER_PATH,
    PCAP_DATA_CONTAINER_PATH,
    SURICATA_LOG_CONTAINER_PATH,
    YAMLDynamic,
)
from scripts.malcolm_utils import deep_get, get_main_script_path, same_file_or_dir, touch, unwrap_method

from scripts.installer.configs.constants.config_env_var_keys import *
from scripts.installer.configs.constants.configuration_item_keys import *
from scripts.installer.configs.configuration_items import (
    ALL_CONFIG_ITEMS_DICT,
    CONFIG_ITEM_DEFINITION_NAME_BY_KEY,
)
from scripts.installer.configs.constants.constants import (
    COMPOSE_FILENAME,
    LABEL_MALCOLM_CERTRESOLVER,
    LABEL_MALCOLM_ENTRYPOINTS,
    LABEL_MALCOLM_RULE,
    LABEL_OS_RULE,
    SERVICE_IP_EXPOSED,
    SERVICE_PORT_LOGSTASH,
    SERVICE_PORT_SFTP_INTERNAL,
    SERVICE_PORT_TCP_JSON,
    SERVICE_PORT_OSMALCOLM,
    SERVICE_PORT_OSMALCOLM_NO_SSL,
    SYSLOG_DEFAULT_PORT,
    TRAEFIK_ENABLE,
    USERNS_MODE_KEEP_ID,
)
from scripts.installer.configs.constants.enums import ContainerRuntime, OpenPortsChoices
from scripts.installer.utils.logger_utils import InstallerLogger
from scripts.installer.core.config_item import ConfigItem
from scripts.installer.core.config_env_mapper import EnvMapper, EnvVariable
from scripts.installer.utils.exceptions import (
    ConfigItemNotFoundError,
    ConfigValueValidationError,
    DependencyError,
    FileOperationError,
)
from scripts.installer.core.observable import ObservableStoreMixin
from scripts.installer.core.transform_registry import apply_inbound


def overrides_set_value(obj):
    item_func = unwrap_method(obj.__class__.set_value)
    base_func = unwrap_method(ConfigItem.set_value)
    return item_func is not base_func


class MalcolmConfig(ObservableStoreMixin):
    """Configuration store managing items, dependencies, and env mapping."""

    def __init__(self):
        self.config_dir_loaded = None  # only set when items are loaded from .env files in a config_dir
        self.config_dir_written = None  # only set when items are written to .env files in a config_dir
        self._items: Dict[str, ConfigItem] = copy.deepcopy(ALL_CONFIG_ITEMS_DICT)
        self._env_mapper: EnvMapper = (
            EnvMapper()
        )  # contains the mapping of config items <--> environment variables as well as environment variables to .env files
        self._observers: Dict[str, List[Callable[[Any], None]]] = {}
        self._modified_keys: List[str] = []  # list instead of a set to preserve change order for display
        self._parent_map: Dict[str, List[str]] = {}

        # all items default to visible unless overridden
        for item in self._items.values():
            item._visible = True

        # initialize declarative dependency system
        from scripts.installer.core.dependency_manager import DependencyManager

        self._dependency_manager = DependencyManager(self)
        self._dependency_manager.register_all_dependencies()

    def _set_item_visible(self, key: str, visible: bool) -> None:
        """Set item visibility and propagate changes to dependents."""

        item = self._items.get(key)
        if not item:
            return

        if item.is_visible == visible:
            return

        item.set_visible(visible)

        # ensure parent map entries exist for ad-hoc relationships
        if item.ui_parent:
            children = self._parent_map.setdefault(item.ui_parent, [])
            if key not in children:
                children.append(key)

        if hasattr(self, "_dependency_manager") and self._dependency_manager is not None:
            self._dependency_manager.handle_parent_visibility_change(key, visible)

    def is_item_visible(self, key: str) -> bool:
        """Check if a configuration item should be visible based on observer-driven state."""
        if key in self._items:
            return self.get_item(key).is_visible
        return False

    def get_visible_items(self) -> Dict[str, ConfigItem]:
        """Get all configuration items that should be visible.

        Returns:
            Dictionary of visible configuration items
        """
        visible_items = {}
        for key, item in self._items.items():
            if self.is_item_visible(key):
                visible_items[key] = item
        return visible_items

    def get_hidden_items(self) -> Dict[str, ConfigItem]:
        """Get all configuration items that should be hidden.

        Returns:
            Dictionary of hidden configuration items
        """
        hidden_items = {}
        for key, item in self._items.items():
            if not self.is_item_visible(key):
                hidden_items[key] = item
        return hidden_items

    def get_dependency_info(self, key: str) -> Dict[str, Any]:
        """Get information about the dependency rule for a configuration item.

        Args:
            key: Configuration item key

        Returns:
            Dictionary with dependency information from the dependency manager
        """
        return self._dependency_manager.get_dependency_info(key)

    def get_env_var_by_item_key(self, key: str) -> List[EnvVariable]:
        """Lookup the environment variable(s) for a given configuration item key"""
        return self._env_mapper.get_env_var_by_item_key(key)

    def get_all_config_items(self, modified_only: bool = False) -> Dict[str, ConfigItem]:
        """Get all configuration items.

        Returns:
            Dictionary of all configuration items, where keys are item keys and
            values are ConfigItem instances.
        """
        if (result := copy.deepcopy(self._items)) and modified_only:
            result = {key: result[key] for key in self._modified_keys if key in result}
        return result

    def get_env_mapper(self) -> EnvMapper:
        """Get the environment variable mapper.

        Returns:
            The EnvMapper instance used by this configuration.
        """
        return self._env_mapper

    def get_item_to_env_mapping(self) -> Dict[str, List[EnvVariable]]:
        """Get the mapping between configuration items and environment variables."""
        return self._env_mapper.get_item_to_env_mapping()

    def has_env_mapping(self, key: str) -> bool:
        """Check if a configuration item has associated environment variables."""
        return self._env_mapper.has_env_mapping(key)

    def get_item(self, key: str) -> Optional[ConfigItem]:
        """Get a ConfigItem instance by its key.

        Args:
            key: Configuration item key

        Returns:
            ConfigItem instance or None if not found
        """
        return self._items.get(key)

    def get_value(self, key: str) -> Optional[Any]:
        """Get the current value of a configuration item.

        Args:
            key: Configuration item key

        Returns:
            Current value or None if not found
        """
        item = self.get_item(key)
        return item.get_value() if item else None

    def all_keys(self) -> List[str]:
        """Get a list of all configuration item keys."""
        return list(self._items.keys())

    def set_value(
        self,
        key: str,
        value: Any,
        ignore_errors: Optional[bool] = False,
    ) -> None:
        """Set the value of a configuration item.

        Args:
            key: Configuration item key
            value: New value to set
            ignore_errors: silently ignore errors rather than raising (meaning the
                           value may *not* have been set)

        Raises:
            ConfigItemNotFoundError: If the key does not exist.
            ConfigValueValidationError: If the value is invalid for the item.
        """
        try:
            item = self.get_item(key)
            if not item:
                raise ConfigItemNotFoundError(key)

            # Transform Registry for inbound normalization
            value = apply_inbound(key, value)

            success, error_message = item.set_value(value)

            if not success:
                raise ConfigValueValidationError(key, value, error_message)

            if key not in self._modified_keys:
                self._modified_keys.append(key)

            self._notify_observers(key, item.get_value())
        except Exception as e:
            if ignore_errors:
                InstallerLogger.error(f'Ignored exception setting "{key}"="{value}": "{e}"')
            else:
                raise

    def apply_default(
        self,
        key: str,
        value: Any,
        ignore_errors: Optional[bool] = False,
    ) -> None:
        """Apply a default value without marking the item as modified and notify observers.

        This is used by the dependency system to set computed defaults while
        keeping the item eligible for future automatic updates.

        Args:
            key: Configuration item key
            value: Default value to apply
        """
        try:
            item = self.get_item(key)
            if not item:
                InstallerLogger.warning(f'Cannot apply default for unknown item: "{key}"')
                return

            # Transform Registry for inbound normalization
            value = apply_inbound(key, value)

            # Validate before applying, mirroring set_value semantics but without marking modified
            if item.validator:
                result = item.validator(value)
                valid, error = result if isinstance(result, tuple) else (bool(result), "")
                if not valid:
                    InstallerLogger.warning(f'Failed to set default "{value}" for "{key}": "{error}"')
                    return

            # If value unchanged, avoid notifying to prevent observer loops
            if item.get_value() == value:
                return

            if not overrides_set_value(item):
                # set value directly without set_value (i.e., without flipping is_modified) so future syncs can adjust
                item.value = value
            else:
                # this config item overrides set_value so they must want to do something special,
                # so call its set_value but preserve its is_modified flag
                old_modified = item.is_modified
                item.set_value(value)
                item.is_modified = old_modified

            try:
                self._notify_observers(key, item.get_value())
            except Exception as e:
                # Avoid breaking dependency processing; surface the error
                InstallerLogger.error(f'Observer error applying default for "{key}"="{value}": "{e}"')
        except Exception as e:
            if ignore_errors:
                InstallerLogger.error(f'Ignored exception applying default for "{key}"="{value}": "{e}"')
            else:
                raise

    def generate_env_files(self, config_dir: str, templates_dir: Optional[str] = None):
        """Generate environment files from current configuration.

        Args:
            config_dir: Directory to write environment files to
            templates_dir: Directory containing .env.example template files

        Raises:
            FileOperationError: If there is an issue writing the files.
        """
        if not os.path.isdir(config_dir):
            raise FileOperationError(f"Configuration directory '{config_dir}' not found.")

        if not (dotenv_lib := DotEnvDynamic()):
            raise ImportError('Could not dynamically import dotenv library')

        # default templates directory if not provided
        if templates_dir is None:
            templates_dir = get_default_config_dir()

        if os.path.isdir(templates_dir):
            # if any *.env file doesn't exist, use the template *.env.example files as defaults
            for env_exampl_file in glob.glob(os.path.join(templates_dir, '*.env.example')):
                env_file = os.path.join(config_dir, os.path.basename(env_exampl_file[: -len('.example')]))
                if not os.path.isfile(env_file):
                    shutil.copyfile(env_exampl_file, env_file)
                    InstallerLogger.info(
                        f"Created {os.path.basename(env_file)} from {os.path.basename(env_exampl_file)}"
                    )

        else:
            # Suppress warning during unit tests
            if "unittest" not in sys.modules:
                InstallerLogger.warning(f"Could not find .env.example templates directory. Expected: {templates_dir}")

        env_files_content: Dict[str, Dict[str, str]] = defaultdict(dict)

        # iterate over all known environment variables
        for map_key, env_var_obj in self._env_mapper.env_var_by_map_key.items():
            value_to_write = None

            # gather the config items that map to this environment variable
            config_items = [self._items.get(item_key) for item_key in env_var_obj.config_items]

            # if a transform function is defined, always use it so that complex or type-specific
            # serialization logic is respected, even when only a single config item participates.
            if env_var_obj.transform:
                try:
                    value_to_write = env_var_obj.transform(*[ci.get_value() for ci in config_items])
                except Exception as e:
                    InstallerLogger.warning(f"Could not transform value for {env_var_obj.variable_name}: {e}")
                    value_to_write = None
            else:
                # error out if we dont have a transform function defined
                if not value_to_write:
                    raise ValueError(f"No transform function defined for {env_var_obj.variable_name}")

            # if a value was successfully determined, prepare to write it
            if value_to_write is not None:
                # Convert boolean values to lowercase strings for consistency
                if isinstance(value_to_write, bool):
                    value_to_write = str(value_to_write).lower()
                env_files_content[env_var_obj.file_name][env_var_obj.variable_name] = value_to_write

        try:
            for filename, values in env_files_content.items():
                filepath = os.path.join(config_dir, filename)
                try:
                    touch(filepath)
                except Exception:
                    pass

                for key, value in sorted(values.items()):
                    try:
                        old_dot_env_version = False
                        try:
                            dotenv_lib.set_key(
                                filepath,
                                key,
                                str(value),
                                quote_mode='never',
                                encoding='utf-8',
                            )
                        except TypeError:
                            old_dot_env_version = True

                        if old_dot_env_version:
                            dotenv_lib.set_key(
                                filepath,
                                key,
                                str(value),
                                quote_mode='never',
                            )

                    except Exception as e:
                        InstallerLogger.error(
                            f"Setting value for {key} in {os.path.basename(filepath)} failed ({type(e).__name__}): {e}"
                        )

                InstallerLogger.info(f"Wrote environment file: {os.path.basename(filepath)}")
            self.config_dir_written = config_dir

        except (IOError, OSError) as e:
            raise FileOperationError(f"Failed to write environment file(s): {e}") from e

    def load_from_env_files(self, config_dir: str):
        """Load configuration from environment files.

        Args:
            config_dir: Directory containing environment files
        """
        if not os.path.isdir(config_dir):
            return  # Nothing to load

        env_values = self._collect_env_values(config_dir)
        candidates = self._build_candidates_from_env(env_values)
        self._apply_env_candidates(candidates)
        self.config_dir_loaded = config_dir

    def _collect_env_values(self, config_dir: str) -> Dict[str, str]:
        env_values: Dict[str, str] = {}

        if dotenv_lib := DotEnvDynamic():
            for file_name in self._env_mapper.get_all_file_names():
                filepath = os.path.join(config_dir, file_name)
                if not os.path.exists(filepath):
                    continue
                try:
                    env_values.update(dotenv_lib.dotenv_values(filepath))
                except Exception as e:
                    InstallerLogger.warning(f"Could not read {filepath}: {e}")
                    # Continue to try and load from other files

        return env_values

    def _build_candidates_from_env(self, env_values: Dict[str, str]):
        candidates = defaultdict(list)
        for env_var_obj in self._env_mapper.env_var_by_map_key.values():
            if env_var_obj.variable_name not in env_values:
                continue
            raw_value_str = env_values[env_var_obj.variable_name]
            if not env_var_obj.reverse_transform:
                raise ValueError(f"No reverse transform function found for {env_var_obj.variable_name}")
            try:
                typed_value = env_var_obj.reverse_transform(raw_value_str)
            except (ValueError, TypeError) as e:
                InstallerLogger.warning(f"Could not process value for {env_var_obj.variable_name}: {e}")
                continue
            if isinstance(typed_value, (list, tuple)) and (len(typed_value) == len(env_var_obj.config_items)):
                for item_key, tv in zip(env_var_obj.config_items, typed_value):
                    if tv == "" or tv is None:
                        continue
                    candidates[item_key].append((env_var_obj.key, tv))
            else:
                for item_key in env_var_obj.config_items:
                    if typed_value == "" or typed_value is None:
                        continue
                    candidates[item_key].append((env_var_obj.key, typed_value))
        return candidates

    def _resolve_env_option(self, item_key: str, options: List[tuple]) -> Tuple[Optional[str], Optional[Any]]:
        if not options:
            return None, None
        precedence = self._env_mapper.get_reverse_precedence_for_item(item_key)
        winner_env_key = None
        winner_value = None
        authoritative_opts = []
        derived_opts = []
        for env_key, val in options:
            ev = self._env_mapper.get_env_variable(env_key)
            if ev and ev.is_authoritative_for(item_key):
                authoritative_opts.append((env_key, val))
            else:
                derived_opts.append((env_key, val))

        def _pick_by_precedence(opts: List[tuple]):
            nonlocal winner_env_key, winner_value
            if not opts:
                return
            if precedence:
                env_last_val = {}
                for env_key, val in opts:
                    env_last_val[env_key] = val
                for env_key in precedence:
                    if env_key in env_last_val:
                        winner_env_key = env_key
                        winner_value = env_last_val[env_key]
                        return
            winner_env_key, winner_value = opts[-1]

        if authoritative_opts:
            _pick_by_precedence(authoritative_opts)
        else:
            _pick_by_precedence(derived_opts)
        return winner_env_key, winner_value

    def _apply_env_candidates(self, candidates):
        for item_key, options in candidates.items():
            if not options:
                continue
            winner_env_key, winner_value = self._resolve_env_option(item_key, options)
            if len(options) > 1 and winner_env_key is not None:
                losers = [ek for (ek, _) in options if ek != winner_env_key]
                InstallerLogger.debug(f"env conflict for {item_key}: picked {winner_env_key} over {losers}")
            if winner_value is None or winner_value == "":
                continue
            try:
                self.apply_default(item_key, winner_value, ignore_errors=True)
            except (ConfigItemNotFoundError, ConfigValueValidationError) as e:
                if "unittest" not in sys.modules:
                    InstallerLogger.warning(f"Could not set config for {item_key} from env: {e}")

    def load_from_orchestration_file(
        self,
        config_dir: Optional[str] = None,
        orchestration_file: Optional[str] = None,
    ) -> Optional[str]:
        """Load configuration from docker-compose file.

        Args:
            orchestration_file: Path to docker-compose file, or will autodiscover if None
        """
        compose_file_name = next(
            (
                p
                for p in [
                    orchestration_file if orchestration_file and os.path.isfile(orchestration_file) else None,
                    os.path.join(os.path.dirname(config_dir), COMPOSE_FILENAME),
                    os.path.join(os.path.dirname(get_main_script_path()), COMPOSE_FILENAME),
                ]
                if p and os.path.isfile(p)
            ),
            None,
        )

        if not compose_file_name or not os.path.isfile(compose_file_name):
            return None  # Nothing to load

        if yamlImported := YAMLDynamic():
            try:
                with open(compose_file_name, 'r') as f:
                    if compose_data := yamlImported.YAML(typ='safe', pure=True).load(f):
                        # set settings from compose file, gracefully ignoring validation errors
                        #   (meaning we'll just end up with the defaults)

                        # container runtime docker vs. podman
                        self.apply_default(
                            KEY_CONFIG_ITEM_RUNTIME_BIN,
                            (
                                ContainerRuntime.PODMAN
                                if any(
                                    deep_get(config, ["userns_mode"]) == USERNS_MODE_KEEP_ID
                                    for config in deep_get(compose_data, ["services"], {}).values()
                                )
                                else ContainerRuntime.DOCKER
                            ),
                            ignore_errors=True,
                        )

                        # restart policy
                        self.apply_default(
                            KEY_CONFIG_ITEM_MALCOLM_RESTART_POLICY,
                            next(
                                iter(
                                    {
                                        deep_get(config, ["restart"])
                                        for config in deep_get(compose_data, ["services"], {}).values()
                                    }
                                ),
                                None,
                            ),
                            ignore_errors=True,
                        )

                        # network settings
                        if deep_get(compose_data, ["networks", "default", "external"], False):
                            self.apply_default(
                                KEY_CONFIG_ITEM_CONTAINER_NETWORK_NAME,
                                deep_get(compose_data, ["networks", "default", "name"]),
                                ignore_errors=True,
                            )

                        # exposed services
                        self._load_exposed_services_from_orchestration_file(compose_data)

                        # Malcolm x- extensions in compose file (except for reachback ACL which is done in _load_exposed_services_from_orchestration_file)
                        self._malcolm_extensions_from_orchestration_file(compose_data)

                        # traefik/reverse proxy stuff
                        self._load_traefik_settings_from_orchestration_file(compose_data)

                        # custom storage paths
                        self._load_custom_storage_paths_from_orchestration_file(compose_data, compose_file_name)

                return compose_file_name
            except Exception as e:
                InstallerLogger.error(f"Error deciphering '{compose_file_name}': {e}")

        return None

    def _get_traefik_labels(self, compose_data: Dict[Any, Any]) -> Dict[Any, Any]:
        return {
            k: v
            for k, v in deep_get(compose_data, ["services", "nginx-proxy", "labels"], {}).items()
            if k.startswith("traefik")
        }

    def _load_exposed_services_from_orchestration_file(self, compose_data: Dict[Any, Any]):
        exposed_services = {}

        service_ports_to_check = {
            KEY_CONFIG_ITEM_EXPOSE_FILEBEAT_TCP: (
                "filebeat",
                {SERVICE_PORT_TCP_JSON},
                "filebeat",
                True,  # authoritative
            ),
            KEY_CONFIG_ITEM_EXPOSE_LOGSTASH: (
                "logstash",
                {SERVICE_PORT_LOGSTASH},
                "logstash",
                True,  # authoritative
            ),
            KEY_CONFIG_ITEM_EXPOSE_OPENSEARCH: (
                "nginx-proxy",
                {SERVICE_PORT_OSMALCOLM, SERVICE_PORT_OSMALCOLM_NO_SSL},
                "opensearch",
                True,  # authoritative
            ),
            KEY_CONFIG_ITEM_EXPOSE_SFTP: (
                "upload",
                {SERVICE_PORT_SFTP_INTERNAL},
                "sftp",
                True,  # authoritative
            ),
            "nonauthoritative_syslog_check": (
                "filebeat",
                {
                    SYSLOG_DEFAULT_PORT,
                    self.get_value(KEY_CONFIG_ITEM_SYSLOG_TCP_PORT),
                    self.get_value(KEY_CONFIG_ITEM_SYSLOG_UDP_PORT),
                },
                "syslog",
                False,  # not authoritative (the .env files are)
            ),
        }

        # look in each `ports` section for 0.0.0.0:... exposed services
        for config_key, service_tuple in service_ports_to_check.items():
            for port in deep_get(compose_data, ["services", service_tuple[0], "ports"], []):
                port_parts = port.split(':')
                if (
                    (len(port_parts) == 3)
                    and (port_parts[0] == SERVICE_IP_EXPOSED)
                    and (port_parts[2].split('/')[0] in [str(x) for x in service_tuple[1] if x])
                ):
                    exposed_services[service_tuple[2]] = {config_key: service_tuple[3]}

        # opensearch could also be exposed via traefik instead of via `ports`:
        if (
            (traefik_labels := self._get_traefik_labels(compose_data))
            and (traefik_labels.get(TRAEFIK_ENABLE, False) is True)
            and traefik_labels.get(LABEL_OS_RULE)
        ):
            exposed_services["opensearch"] = {KEY_CONFIG_ITEM_EXPOSE_OPENSEARCH: True}

        if exposed_services:
            # set the overall "expose services" key
            # the "Yes" selection equates to filebeat, logstash, and opensearch; otherwise it's "customize"
            open_ports_choice = (
                OpenPortsChoices.YES
                if set(exposed_services.keys()) == {"filebeat", "logstash", "opensearch"}
                else OpenPortsChoices.CUSTOMIZE
            )
            self.apply_default(KEY_CONFIG_ITEM_OPEN_PORTS, open_ports_choice, ignore_errors=True)
            if open_ports_choice == OpenPortsChoices.CUSTOMIZE:
                # set the individual exposed services
                for expose_key in [k for v in exposed_services.values() for k, flag in v.items() if flag]:
                    self.apply_default(expose_key, True, ignore_errors=True)
        else:
            self.apply_default(KEY_CONFIG_ITEM_OPEN_PORTS, OpenPortsChoices.NO, ignore_errors=True)

        # for hedgehog mode, we have the request reachback ACL stored in an extension
        reachback_request_acl = deep_get(
            compose_data,
            [
                COMPOSE_MALCOLM_EXTENSION,
                COMPOSE_MALCOLM_EXTENSION_HEDGEHOG,
                COMPOSE_MALCOLM_EXTENSION_HEDGEHOG_REACHBACK_REQUEST_ACL,
            ],
            [],
        )
        if isinstance(reachback_request_acl, str):
            reachback_request_acl = [reachback_request_acl]
        elif not isinstance(reachback_request_acl, list):
            reachback_request_acl = []
        self.apply_default(KEY_CONFIG_ITEM_REACHBACK_REQUEST_ACL, reachback_request_acl, ignore_errors=True)

    def _malcolm_extensions_from_orchestration_file(self, compose_data: Dict[Any, Any]):
        # Malcolm x- extensions in compose file (except for reachback ACL which is done in _load_exposed_services_from_orchestration_file)
        ext_map = {
            # forwarders
            COMPOSE_MALCOLM_EXTENSION_AUX_FW: {
                COMPOSE_MALCOLM_EXTENSION_AUX_FW_AIDE: KEY_CONFIG_ITEM_AUX_FW_AIDE,
                COMPOSE_MALCOLM_EXTENSION_AUX_FW_AUDITLOG: KEY_CONFIG_ITEM_AUX_FW_AUDITLOG,
                COMPOSE_MALCOLM_EXTENSION_AUX_FW_CPU: KEY_CONFIG_ITEM_AUX_FW_CPU,
                COMPOSE_MALCOLM_EXTENSION_AUX_FW_DF: KEY_CONFIG_ITEM_AUX_FW_DF,
                COMPOSE_MALCOLM_EXTENSION_AUX_FW_DISK: KEY_CONFIG_ITEM_AUX_FW_DISK,
                COMPOSE_MALCOLM_EXTENSION_AUX_FW_KMSG: KEY_CONFIG_ITEM_AUX_FW_KMSG,
                COMPOSE_MALCOLM_EXTENSION_AUX_FW_MEM: KEY_CONFIG_ITEM_AUX_FW_MEM,
                COMPOSE_MALCOLM_EXTENSION_AUX_FW_NETWORK: KEY_CONFIG_ITEM_AUX_FW_NETWORK,
                COMPOSE_MALCOLM_EXTENSION_AUX_FW_SYSTEMD: KEY_CONFIG_ITEM_AUX_FW_SYSTEMD,
                COMPOSE_MALCOLM_EXTENSION_AUX_FW_THERMAL: KEY_CONFIG_ITEM_AUX_FW_THERMAL,
            },
            # prune operations external to containers
            COMPOSE_MALCOLM_EXTENSION_PRUNE: {
                COMPOSE_MALCOLM_EXTENSION_PRUNE_PCAP: KEY_CONFIG_ITEM_PRUNE_PCAP,
                COMPOSE_MALCOLM_EXTENSION_PRUNE_LOGS: KEY_CONFIG_ITEM_PRUNE_LOGS,
            },
        }
        for ext_key, ext_key_map in ext_map.items():
            if (
                ext_settings := deep_get(
                    compose_data,
                    [COMPOSE_MALCOLM_EXTENSION, ext_key],
                    {},
                )
            ) and isinstance(ext_settings, dict):
                for forwarder, enabled in ext_settings.items():
                    if isinstance(enabled, bool) and (key_config_item := ext_key_map.get(forwarder)):
                        self.apply_default(key_config_item, enabled, ignore_errors=True)

    def _load_traefik_settings_from_orchestration_file(self, compose_data: Dict[Any, Any]):
        # traefik/reverse proxy stuff
        traefik_labels = self._get_traefik_labels(compose_data)
        if traefik_labels.get(TRAEFIK_ENABLE, False) is True:
            self.apply_default(KEY_CONFIG_ITEM_TRAEFIK_LABELS, True, ignore_errors=True)
            self.apply_default(
                KEY_CONFIG_ITEM_TRAEFIK_HOST,
                (
                    re.findall(
                        r'Host\s*\(\s*[`"\']([^`"\']+)[`"\']',
                        traefik_labels.get(LABEL_MALCOLM_RULE, ""),
                    )
                    or [""]
                )[0],
                ignore_errors=True,
            )
            self.apply_default(
                KEY_CONFIG_ITEM_TRAEFIK_ENTRYPOINT, traefik_labels.get(LABEL_MALCOLM_ENTRYPOINTS), ignore_errors=True
            )
            self.apply_default(
                KEY_CONFIG_ITEM_TRAEFIK_RESOLVER, traefik_labels.get(LABEL_MALCOLM_CERTRESOLVER), ignore_errors=True
            )
            self.apply_default(
                KEY_CONFIG_ITEM_TRAEFIK_OPENSEARCH_HOST,
                (
                    re.findall(
                        r'Host\s*\(\s*[`"\']([^`"\']+)[`"\']',
                        traefik_labels.get(LABEL_OS_RULE, ""),
                    )
                    or [""]
                )[0],
                ignore_errors=True,
            )

    def _load_custom_storage_paths_from_orchestration_file(
        self,
        compose_data: Dict[Any, Any],
        compose_file_name: str,
    ):
        custom_path = False
        for config_key, service_tuple in {
            KEY_CONFIG_ITEM_PCAP_DIR: (
                "arkime",
                PCAP_DATA_CONTAINER_PATH,
                os.path.realpath(os.path.join(os.path.dirname(compose_file_name), DEFAULT_PCAP_DIR)),
            ),
            KEY_CONFIG_ITEM_ZEEK_LOG_DIR: (
                "filebeat",
                FILEBEAT_ZEEK_LOG_CONTAINER_PATH,
                os.path.realpath(os.path.join(os.path.dirname(compose_file_name), DEFAULT_ZEEK_LOG_DIR)),
            ),
            KEY_CONFIG_ITEM_SURICATA_LOG_DIR: (
                "suricata",
                SURICATA_LOG_CONTAINER_PATH,
                os.path.realpath(os.path.join(os.path.dirname(compose_file_name), DEFAULT_SURICATA_LOG_DIR)),
            ),
            KEY_CONFIG_ITEM_INDEX_DIR: (
                "opensearch",
                OPENSEARCH_DATA_CONTAINER_PATH,
                os.path.realpath(os.path.join(os.path.dirname(compose_file_name), DEFAULT_INDEX_DIR)),
            ),
            KEY_CONFIG_ITEM_INDEX_SNAPSHOT_DIR: (
                "opensearch",
                OPENSEARCH_BACKUP_CONTAINER_PATH,
                os.path.realpath(os.path.join(os.path.dirname(compose_file_name), DEFAULT_INDEX_SNAPSHOT_DIR)),
            ),
        }.items():
            if local_path := LocalPathForContainerBindMount(
                service_tuple[0],
                compose_data,
                service_tuple[1],
                os.path.dirname(compose_file_name),
            ):
                if not same_file_or_dir(local_path, service_tuple[2]):
                    self.apply_default(config_key, local_path, ignore_errors=True)
                    custom_path = True
        if custom_path:
            self.apply_default(KEY_CONFIG_ITEM_USE_DEFAULT_STORAGE_LOCATIONS, False, ignore_errors=True)

    def _notify_observers(self, key: str, value: Any):
        """Notify all registered observers for a given key."""
        if key in self._observers:
            for callback in list(self._observers[key]):
                try:
                    callback(value)
                except Exception as e:
                    InstallerLogger.error(f"Error in observer for key '{key}': {e}")
                    raise DependencyError(f"Observer for {key} failed: {e}") from e

    def search_items(self, search_term: str) -> List[Dict[str, Any]]:
        """Search for configuration items across key, label, question, and definition name.

        Args:
            search_term: The term to search for in item keys, labels, questions, or CONFIG_ITEM constants

        Returns:
            List of dictionaries containing search results with keys:
            - 'key': The item key
            - 'label': The item label
            - 'visible': Whether the item is currently visible
            - 'ui_parent': The parent item key if it has one
            - 'dependency_chain': List of keys that need to be enabled for this item to be visible
            - 'definition_name': CONFIG_ITEM_* constant associated with the item
            - 'question': The prompt/question text tied to the item (may be empty)
        """
        search_term = search_term.lower()
        results = []

        for key, item in self._items.items():
            label_text = item.label or ""
            question_text = item.question or ""
            definition_name = CONFIG_ITEM_DEFINITION_NAME_BY_KEY.get(key, "")
            search_targets = (
                key.lower(),
                label_text.lower(),
                question_text.lower(),
                definition_name.lower(),
            )

            if not any(search_term in target for target in search_targets if target):
                continue

            # Find dependency chain for invisible items
            dependency_chain = []
            if not item.is_visible:
                dependency_chain = self._get_dependency_chain(key)

            results.append(
                {
                    "key": key,
                    "label": item.label,
                    "visible": item.is_visible,
                    "ui_parent": item.ui_parent,
                    "dependency_chain": dependency_chain,
                    "definition_name": definition_name,
                    "question": question_text,
                }
            )

        return results

    def _get_dependency_chain(self, key: str) -> List[str]:
        """Get the chain of dependencies that need to be satisfied for an item to be visible.

        Args:
            key: The configuration item key

        Returns:
            List of keys representing the dependency chain from root to this item
        """
        chain = []
        current_key = key
        visited = set()  # Prevent infinite loops

        while current_key and current_key not in visited:
            visited.add(current_key)
            item = self.get_item(current_key)

            if item and item.ui_parent:
                chain.insert(0, item.ui_parent)
                current_key = item.ui_parent
            else:
                break

        return chain

    def to_dict_values_only(self) -> Dict[str, Any]:
        """Convert configuration to a nested dictionary of keys and their current values."""
        output: Dict[str, Any] = {}
        for key, item in self._items.items():
            value = item.get_value()

            # Skip None values and empty strings to avoid validation issues on import
            if value is None or (isinstance(value, str) and value == ""):
                continue

            # Convert Enum values to their string representation for serialization
            if isinstance(value, Enum):
                value = value.value

            parts = key.split(".")
            current_level = output
            for i, part in enumerate(parts):
                if i == len(parts) - 1:
                    current_level[part] = value
                else:
                    if part not in current_level:
                        current_level[part] = {}
                    current_level = current_level[part]
        return output
