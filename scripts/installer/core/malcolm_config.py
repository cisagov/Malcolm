#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2025 Battelle Energy Alliance, LLC.  All rights reserved.

"""Configuration store for Malcolm installer settings."""

import os
import sys
import datetime
import copy
import json
from ruamel.yaml import YAML

from collections import defaultdict
from enum import Enum, Flag
from typing import Dict, Any, Callable, List, Tuple, Optional, Set

from scripts.malcolm_common import DumpYaml
from scripts.malcolm_utils import SYSTEM_INFO, deep_set, deep_get

from scripts.installer.configs.constants.config_env_var_keys import *
from scripts.installer.configs.constants.configuration_item_keys import *
from scripts.installer.configs.configuration_items import (
    ALL_CONFIG_ITEMS_DICT,
    ALL_DOCKER_CONFIG_ITEMS_DICT,
    CONFIG_ITEM_DEFINITION_NAME_BY_KEY,
)

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


class MalcolmConfig(ObservableStoreMixin):
    """Configuration store managing items, dependencies, and env mapping."""

    def __init__(self):
        self._items: Dict[str, ConfigItem] = copy.deepcopy(ALL_CONFIG_ITEMS_DICT)
        self._env_mapper: EnvMapper = (
            EnvMapper()
        )  # contains the mapping of config items <--> environment variables as well as environment variables to .env files
        self._observers: Dict[str, List[Callable[[Any], None]]] = {}
        self._modified_keys: Set[str] = set()
        self._parent_map: Dict[str, List[str]] = {}

        # determine dynamic defaults that rely on system inspection (UID/GID)
        self._initialize_dynamic_defaults()

        # all items default to visible unless overridden
        for item in self._items.values():
            item._visible = True

        # initialize declarative dependency system
        from scripts.installer.core.dependency_manager import DependencyManager

        self._dependency_manager = DependencyManager(self)
        self._dependency_manager.register_all_dependencies()

    def _initialize_dynamic_defaults(self):
        """Set dynamic default values based on the system environment."""
        try:
            uid_val = SYSTEM_INFO.get("recommended_nonroot_uid")
            gid_val = SYSTEM_INFO.get("recommended_nonroot_gid")

            uid_item = self.get_item(KEY_CONFIG_ITEM_PROCESS_USER_ID)
            gid_item = self.get_item(KEY_CONFIG_ITEM_PROCESS_GROUP_ID)

            if uid_item and not uid_item.is_modified and uid_val is not None:
                uid_item.default_value = uid_val
            if gid_item and not gid_item.is_modified and gid_val is not None:
                gid_item.default_value = gid_val
        except (KeyError, TypeError) as e:
            InstallerLogger.warning(f"Could not set dynamic UID/GID defaults: {e}")

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

    def _calculate_ui_depths(self):
        """Calculate the UI depth for each config item based on the dependency graph."""
        memo = {}

        def get_depth(key: str) -> int:
            if key in memo:
                return memo[key]

            parents = self._parent_map.get(key)
            if not parents:
                return 0

            max_parent_depth = max(get_depth(parent) for parent in parents)
            depth = 1 + max_parent_depth
            memo[key] = depth
            return depth

        for key, item in self._items.items():
            item.ui_depth = get_depth(key)

    def get_parent_map(self) -> Dict[str, List[str]]:
        """Get the parent map for UI rendering."""
        return self._parent_map

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

    def get_all_config_items(self) -> Dict[str, ConfigItem]:
        """Get all configuration items.

        Returns:
            Dictionary of all configuration items, where keys are item keys and
            values are ConfigItem instances.
        """
        return copy.deepcopy(self._items)

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

    def set_value(self, key: str, value: Any):
        """Set the value of a configuration item.

        Args:
            key: Configuration item key
            value: New value to set

        Raises:
            ConfigItemNotFoundError: If the key does not exist.
            ConfigValueValidationError: If the value is invalid for the item.
        """
        item = self.get_item(key)
        if not item:
            raise ConfigItemNotFoundError(key)

        # First, delegate to the Transform Registry for inbound normalization
        try:
            from scripts.installer.core.transform_registry import apply_inbound

            value = apply_inbound(key, value)
        except Exception:
            # Safe fallback if registry is unavailable
            pass

        # normalization logic is centralized in the Transform Registry

        success, error_message = item.set_value(value)

        if not success:
            raise ConfigValueValidationError(key, value, error_message)

        self._modified_keys.add(key)
        self._notify_observers(key, item.get_value())

    def apply_default(self, key: str, value: Any) -> None:
        """Apply a default value without marking the item as modified and notify observers.

        This is used by the dependency system to set computed defaults while
        keeping the item eligible for future automatic updates.

        Args:
            key: Configuration item key
            value: Default value to apply
        """
        item = self.get_item(key)
        if not item:
            InstallerLogger.warning(f"Cannot apply default for unknown item: {key}")
            return

        # Normalize first for consistent comparison/validation
        try:
            from scripts.installer.core.transform_registry import apply_inbound

            value = apply_inbound(key, value)
        except Exception:
            pass

        # Validate before applying, mirroring set_value semantics but without marking modified
        if item.validator:
            result = item.validator(value)
            valid, error = result if isinstance(result, tuple) else (bool(result), "")
            if not valid:
                InstallerLogger.warning(f"Failed to set default for {key}: {error}")
                return

        # If value unchanged, avoid notifying to prevent observer loops
        if item.get_value() == value:
            return

        # Apply without flipping is_modified so future syncs can adjust
        item.value = value
        try:
            self._notify_observers(key, item.get_value())
        except Exception as e:
            # Avoid breaking dependency processing; surface the error
            InstallerLogger.error(
                f"Observer error after applying default for '{key}': {e}"
            )

    
    def validate_all(self) -> List[str]:
        """Validate all configuration items.

        Returns:
            List of error messages (empty if all valid)
        """
        errors = []
        for key, item in self._items.items():
            if item.validator:
                valid, error = item.validator(item.get_value())
                if not valid:
                    errors.append(f"{item.label} ({key}): {error}")
        return errors

    def get_modified_items(self) -> List[ConfigItem]:
        """Get all configuration items that differ from their defaults.

        Returns:
            List of modified ConfigItem instances
        """
        return [item for item in self._items.values() if item.is_modified]

    def reset_all(self):
        """Reset all configuration items to their default values."""
        keys_to_notify = list(self._items.keys())
        for item in self._items.values():
            item.reset()
        self._modified_keys.clear()
        for key in keys_to_notify:
            item = self.get_item(key)
            if item:
                self._notify_observers(key, item.get_value())

    def _validate_directory(self, path: str) -> Tuple[bool, str]:
        """Validate directory path.

        Args:
            path: Directory path to validate

        Returns:
            Tuple of (is_valid, error_message)
        """
        if not path:
            return False, "Path cannot be empty"

        path = os.path.expanduser(path)
        path = os.path.abspath(path)

        if os.path.exists(path):
            if not os.path.isdir(path):
                return False, "Path exists but is not a directory"
            if not os.access(path, os.W_OK):
                return False, "Directory exists but is not writable"
        else:
            parent = os.path.dirname(path)
            if not os.path.exists(parent):
                return False, f"Parent directory {parent} does not exist"
            if not os.access(parent, os.W_OK):
                return False, f"Parent directory {parent} is not writable"

        return True, ""

    def generate_env_files(self, config_dir: str, templates_dir: Optional[str] = None):
        """Generate environment files from current configuration.

        Args:
            config_dir: Directory to write environment files to
            templates_dir: Directory containing .env.example template files

        Raises:
            FileOperationError: If there is an issue writing the files.
        """
        if not os.path.isdir(config_dir):
            raise FileOperationError(
                f"Configuration directory '{config_dir}' not found."
            )

        # default templates directory if not provided
        if templates_dir is None:
            from scripts.malcolm_utils import get_default_config_dir

            templates_dir = get_default_config_dir()

        if not os.path.isdir(templates_dir):
            # Suppress warning during unit tests
            if "unittest" not in sys.modules:
                InstallerLogger.warning(
                    f"Could not find .env.example templates directory. Expected: {templates_dir}"
                )

        env_files_content: Dict[str, Dict[str, str]] = defaultdict(dict)

        # iterate over all known environment variables
        for map_key, env_var_obj in self._env_mapper.env_var_by_map_key.items():
            value_to_write = None

            # gather the config items that map to this environment variable
            config_items = [
                self._items.get(item_key) for item_key in env_var_obj.config_items
            ]

            # if a transform function is defined, always use it so that complex or type-specific
            # serialization logic is respected, even when only a single config item participates.
            if env_var_obj.transform:
                try:
                    value_to_write = env_var_obj.transform(
                        *[ci.get_value() for ci in config_items]
                    )
                except Exception as e:
                    InstallerLogger.warning(
                        f"Could not transform value for {env_var_obj.variable_name}: {e}"
                    )
                    value_to_write = None
            else:
                # error out if we dont have a transform function defined
                if not value_to_write:
                    raise ValueError(
                        f"No transform function defined for {env_var_obj.variable_name}"
                    )

            # if a value was successfully determined, prepare to write it
            if value_to_write is not None:
                # Convert boolean values to lowercase strings for consistency
                if isinstance(value_to_write, bool):
                    value_to_write = str(value_to_write).lower()
                env_files_content[env_var_obj.file_name][
                    env_var_obj.variable_name
                ] = value_to_write

        try:
            for filename, values in env_files_content.items():
                filepath = os.path.join(config_dir, filename)
                with open(filepath, "w") as f:
                    f.write(
                        f"# This file was auto-generated by the Malcolm installer on {datetime.datetime.now()}.\n"
                    )
                    f.write(
                        f"# It contains environment variables for the {filename.replace('.env', '')} service(s).\n\n"
                    )
                    for key, value in sorted(values.items()):
                        f.write(f"{key}={value}\n")
                from scripts.installer.utils.logger_utils import InstallerLogger as _IL
                try:
                    _IL.info(f"Wrote environment file: {filepath}")
                except Exception:
                    pass
        except (IOError, OSError) as e:
            raise FileOperationError(f"Failed to write environment file: {e}") from e

    def generate_docker_compose_file(
        self,
        config_dir: str,
        template_path: Optional[str] = None,
        output_filename: str = "docker-compose.yml",
    ):
        """Generate docker-compose.yml from configuration and template."""

        # If a template_path is provided, we will read from and write to that same path (in-place edit).
        # If not, we fall back to creating a new file in the config_dir.
        if template_path and os.path.isfile(template_path):
            target_path = template_path
        else:
            if not os.path.isdir(config_dir):
                raise FileOperationError(
                    f"Configuration directory '{config_dir}' not found."
                )
            target_path = os.path.join(config_dir, output_filename)

        if not os.path.exists(target_path):
            raise FileOperationError(
                f"Docker compose file not found to read from: {target_path}"
            )

        try:
            y = YAML(typ="safe", pure=True)
            with open(target_path, "r") as f:
                compose_data = y.load(f)
                if compose_data is None:
                    raise FileOperationError(
                        f"Docker compose file is empty or invalid: {target_path}"
                    )
        except (IOError, OSError, YAML.YAMLError) as e:
            raise FileOperationError(f"Failed to read docker-compose file: {e}") from e

        # apply docker configuration items to compose structure
        self._apply_docker_config_to_compose(compose_data)

        # write updated docker-compose.yml back to the target path
        try:
            import copy as _copy
            orig_uid = orig_gid = None
            if os.path.exists(target_path):
                stat_info = os.stat(target_path)
                orig_uid, orig_gid = stat_info.st_uid, stat_info.st_gid
            # detect change by reading again after applying config
            # (compose_data is our updated content; we need original for comparison)
            # We already loaded original above; re-open to capture raw for safety
            y2 = YAML(typ="safe", pure=True)
            with open(target_path, "r") as _f2:
                before_data = y2.load(_f2) or {}
            changed = before_data != compose_data
            if changed:
                DumpYaml(compose_data, target_path)
                from scripts.installer.utils.logger_utils import InstallerLogger as _IL
                try:
                    _IL.info(f"Updated docker-compose file: {target_path}")
                except Exception:
                    pass
                if orig_uid is not None and orig_gid is not None:
                    os.chown(target_path, orig_uid, orig_gid)
            else:
                from scripts.installer.utils.logger_utils import InstallerLogger as _IL
                try:
                    _IL.info(f"No changes needed for docker-compose file: {target_path}")
                except Exception:
                    pass

        except (IOError, OSError, YAML.YAMLError) as e:
            raise FileOperationError(f"Failed to write docker-compose file: {e}") from e

    def _apply_docker_config_to_compose(self, compose_data: Dict[str, Any]):
        """Apply docker configuration items to docker-compose structure using deep_set.

        This method applies docker config items that affect the docker-compose.yml structure.
        Items that have environment variable mappings will still be handled by generate_env_files().

        Args:
            compose_data: Docker compose data structure to modify
        """
        if "services" not in compose_data:
            return

        # get docker config items that affect docker-compose structure
        restart_policy = self.get_value(KEY_CONFIG_ITEM_MALCOLM_RESTART_POLICY)
        auto_restart = self.get_value(KEY_CONFIG_ITEM_MALCOLM_AUTO_RESTART)
        network_name = self.get_value(KEY_CONFIG_ITEM_CONTAINER_NETWORK_NAME)

        # determine restart policy to apply (following original installer logic)
        final_restart_policy = "no"  # default
        if restart_policy is not None:
            final_restart_policy = (
                restart_policy.value if isinstance(restart_policy, Enum) else str(restart_policy)
            )
        elif auto_restart:
            final_restart_policy = "unless-stopped"

        # apply configuration to all services using deep_set (like original installer)
        for service in compose_data["services"]:
            # apply restart policy to all services
            deep_set(
                compose_data,
                ["services", service, "restart"],
                final_restart_policy,
            )

        # apply network configuration if specified (following original installer logic)
        if network_name and network_name.strip():
            # re-write the network definition from scratch (like original installer)
            if "networks" in compose_data:
                del compose_data["networks"]
            network_def = {}
            network_def["external"] = True
            network_def["name"] = network_name.strip()
            compose_data["networks"] = {}
            compose_data["networks"]["default"] = network_def
        else:
            # ensure default network configuration if no external network
            if "networks" in compose_data:
                del compose_data["networks"]
            network_def = {"external": False}
            compose_data["networks"] = {}
            compose_data["networks"]["default"] = network_def

    def generate_all_config_files(
        self,
        config_dir: str,
        templates_dir: Optional[str] = None,
        docker_compose_template_path: Optional[str] = None,
    ):
        """Generate both environment files and docker-compose.yml from current configuration.

        Args:
            config_dir: Directory to write configuration files to
            templates_dir: Directory containing .env.example template files
            docker_compose_template_path: Path to docker-compose.yml template

        Raises:
            FileOperationError: If there is an issue writing the files.
        """
        # generate .env files
        self.generate_env_files(config_dir, templates_dir)

        # generate docker-compose.yml
        self.generate_docker_compose_file(
            config_dir, template_path=docker_compose_template_path
        )

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

    def _collect_env_values(self, config_dir: str) -> Dict[str, str]:
        env_values: Dict[str, str] = {}
        for file_name in self._env_mapper.get_all_file_names():
            filepath = os.path.join(config_dir, file_name)
            if not os.path.exists(filepath):
                continue
            try:
                with open(filepath, "r") as f:
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        parts = line.split("=", 1)
                        if len(parts) == 2:
                            env_values[parts[0].strip()] = parts[1].strip()
            except (IOError, OSError) as e:
                InstallerLogger.warning(f"Could not read {filepath}: {e}")
                # Continue to try and load from other files
        return env_values

    def _build_candidates_from_env(self, env_values: Dict[str, str]):
        from collections import defaultdict as _dd

        candidates = _dd(list)
        for env_var_obj in self._env_mapper.env_var_by_map_key.values():
            if env_var_obj.variable_name not in env_values:
                continue
            raw_value_str = env_values[env_var_obj.variable_name]
            if not env_var_obj.reverse_transform:
                raise ValueError(
                    f"No reverse transform function found for {env_var_obj.variable_name}"
                )
            try:
                typed_value = env_var_obj.reverse_transform(raw_value_str)
            except (ValueError, TypeError) as e:
                InstallerLogger.warning(
                    f"Could not process value for {env_var_obj.variable_name}: {e}"
                )
                continue
            if isinstance(typed_value, (list, tuple)) and (
                len(typed_value) == len(env_var_obj.config_items)
            ):
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
                InstallerLogger.debug(
                    f"env conflict for {item_key}: picked {winner_env_key} over {losers}"
                )
            if winner_value is None or winner_value == "":
                continue
            try:
                self.set_value(item_key, winner_value)
            except (ConfigItemNotFoundError, ConfigValueValidationError) as e:
                if "unittest" not in sys.modules:
                    InstallerLogger.warning(
                        f"Could not set config for {item_key} from env: {e}"
                    )

    

    def _notify_observers(self, key: str, value: Any):
        """Notify all registered observers for a given key."""
        if key in self._observers:
            for callback in list(self._observers[key]):
                try:
                    callback(value)
                except Exception as e:
                    InstallerLogger.error(f"Error in observer for key '{key}': {e}")
                    raise DependencyError(f"Observer for {key} failed: {e}") from e

    def get_unmapped_env_variables(self) -> List[EnvVariable]:
        """Get environment variables that don't have a mapping to any configuration item.

        Returns:
            List of EnvVariable instances that don't have a corresponding ConfigItem.
        """
        unmapped = []
        for env_var in self._env_mapper.env_var_by_map_key.values():
            if not env_var.config_items:
                unmapped.append(env_var)
        return unmapped

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

    def get_docker_config_items(self) -> Dict[str, ConfigItem]:
        """Get all docker-related configuration items.

        Returns:
            Dictionary of docker configuration items
        """
        return {
            key: item
            for key, item in self._items.items()
            if key in ALL_DOCKER_CONFIG_ITEMS_DICT
        }

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


# if __name__ == "__main__":
#     config = MalcolmConfig()

#     # List of ConfigItems with no ENV_VAR match
#     unmapped_config_items = [key for key in config._items if not config.has_env_mapping(key)]

#     # List of ENV_VARs with no ConfigItem match
#     unmapped_env_vars = config.get_unmapped_env_variables()

#     print("ConfigItems with no ENV_VAR match:")
#     for key in sorted(unmapped_config_items):
#         print(f"  {key}")

#     print("\nENV_VARs with no ConfigItem match:")
#     for env_var in sorted(unmapped_env_vars, key=lambda x: x.variable_name):
#         print(f"  {env_var.variable_name} (key: {env_var.key})")
