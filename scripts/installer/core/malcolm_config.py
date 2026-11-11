#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2026 Battelle Energy Alliance, LLC.  All rights reserved.

"""Configuration store for Malcolm installer settings."""

import glob
import os
import re
import sys
import copy
import shutil

from collections import defaultdict
from contextlib import contextmanager
from dataclasses import dataclass
from enum import Enum, IntEnum
from typing import Dict, Any, Callable, Iterator, List, Set, Tuple, Optional
from pathlib import Path

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
    DEFAULT_FILESCAN_LOG_DIR,
    DEFAULT_INDEX_DIR,
    DEFAULT_INDEX_SNAPSHOT_DIR,
    DEFAULT_PCAP_DIR,
    DEFAULT_SURICATA_LOG_DIR,
    DEFAULT_ZEEK_LOG_DIR,
    DotEnvDynamic,
    FILEBEAT_FILESCAN_LOG_PATH,
    FILEBEAT_ZEEK_LOG_CONTAINER_PATH,
    FILESCAN_LOG_CONTAINER_PATH,
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


class LoadSource(IntEnum):
    """Where a loaded value came from. A lower number takes precedence over a higher one.

    Sources can be loaded in any order: a value from one source never replaces a value already
    loaded from a source with higher precedence (see MalcolmConfig.load_value).
    """

    COMMAND_LINE = 0  # values determined from installer arguments (e.g., orchestration mode from -f)
    SETTINGS_FILE = 1  # the "configuration" section of a file given to --import-malcolm-config-file
    SETTINGS_FILE_RAW = 2  # the base64-encoded .env files backed up in the "raw" section of that file
    ENV_FILES = 3  # existing .env files in the configuration directory
    COMPOSE_FILE = 4  # the existing docker-compose file
    PRESEED = 5  # storage directory defaults from an ISO install (.os-disk-config-defaults)

    @property
    def label(self) -> str:
        return self.name.lower().replace("_", " ")


class _UseDefault:
    """Marker for load_value: the source explicitly says to use the item's default."""

    def __repr__(self) -> str:
        return "<USE_DEFAULT>"


USE_DEFAULT = _UseDefault()


@dataclass
class LoadIssue:
    """A value from a source that couldn't be used, so a lower-precedence value or the default was kept."""

    source: LoadSource
    message: str


def _ensure_trailing_newline(file_path: str) -> None:
    """Add a final newline to a non-empty file that lacks one.

    Several .env.example templates end without one, which would let a line appended later (by a
    person or a script) run onto the last variable.
    """
    with open(file_path, "rb+") as f:
        f.seek(0, os.SEEK_END)
        if f.tell() == 0:
            return
        f.seek(-1, os.SEEK_END)
        if f.read(1) != b"\n":
            f.write(b"\n")


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

        # load state (see bulk_load and load_value)
        self._load_depth = 0  # > 0 while inside bulk_load()
        self._loaded_from: Dict[str, Tuple[LoadSource, str]] = {}  # key -> (source, detail) of the winning value
        self._loaded_values: Dict[str, Any] = {}  # key -> the winning value as loaded, before any rules ran
        self._loaded_keys: Set[str] = set()  # keys whose loaded value is protected from value rules
        self._load_issues: Dict[str, LoadIssue] = {}  # key -> problem with a value that couldn't be used

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
        return self._env_mapper.get_env_vars_by_item_key(key)

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

    def is_loading(self) -> bool:
        """True while values are being loaded inside bulk_load(); value rules wait until it's done."""
        return self._load_depth > 0

    def is_loaded(self, key: str) -> bool:
        """True if the item's value came from a load (settings file, .env files, compose file, etc.)."""
        return key in self._loaded_keys

    def is_user_set(self, key: str) -> bool:
        """True if the user set this value, either in this session or through a load.

        Value rules marked only_if_unmodified leave these values alone. Loaded values don't
        count as "modified" for display purposes (see get_all_config_items(modified_only=True)).
        """
        item = self.get_item(key)
        return bool(item and item.is_modified) or (key in self._loaded_keys)

    def release_to_rules(self, key: str) -> None:
        """Let a setting follow its value rules again after a forced rule replaced its value.

        The value the user chose, in this session or through a load, is gone, and nobody chose the
        new one. For example, turning live capture off turns netsniff-ng off; turning capture back
        on should then pick the default engine again, as it would for a setting nobody had touched.
        """
        self._loaded_keys.discard(key)
        if (item := self.get_item(key)) and item.is_modified:
            item.is_modified = False
            if key in self._modified_keys:
                self._modified_keys.remove(key)

    def get_load_issues(self) -> Dict[str, LoadIssue]:
        """Values from a load that couldn't be used, by item key."""
        return dict(self._load_issues)

    @contextmanager
    def bulk_load(self) -> Iterator["MalcolmConfig"]:
        """Load values from one or more sources as a single operation.

        Value rules are paused until the outermost bulk_load() exits, then brought up to date in
        one pass (DependencyManager.refresh_after_load). Without this, each loaded value would
        fire the rules that depend on it and could overwrite values loaded before it (for example,
        re-enabling Arkime live capture that a Hedgehog's .env files had turned off).

        Nested bulk_load() calls are fine; only the outermost one runs the refresh. Visibility is
        kept up to date throughout.
        """
        self._load_depth += 1
        try:
            yield self
        finally:
            if self._load_depth == 1:
                # the refresh runs while is_loading() is still True, so that the values it changes
                #   don't set off the normal observers (which would let cascades overwrite loaded values)
                try:
                    self._dependency_manager.refresh_after_load()
                    # A loaded value only counts as a choice if its setting applies to the loaded configuration.
                    #   .env files hold every setting, including ones hidden because they don't apply (e.g., the
                    #   capture engines when live capture is off); those were never chosen, so they go back to
                    #   following their rules if the user later makes them apply.
                    self._loaded_keys = {key for key in self._loaded_keys if self.is_item_visible(key)}
                    self._log_loaded_values()
                finally:
                    self._load_depth = 0
            else:
                self._load_depth -= 1

    def load_value(
        self,
        key: str,
        value: Any,
        source: LoadSource,
        detail: str = "",
    ) -> bool:
        """Set a value read from a configuration source. Only valid inside bulk_load().

        A value from a source with lower precedence than the one the item was already loaded
        from is ignored. An invalid value is recorded as a load issue (see get_load_issues) and
        leaves the current value in place.

        Args:
            key: Configuration item key
            value: The value as read from the source. None means the source has no value for this
                   item (nothing is loaded); USE_DEFAULT means the source says to use the default.
            source: Where the value came from
            detail: Optional description of the source for the log (a file name, a variable name)

        Returns:
            True if the value was set.
        """
        if not self.is_loading():
            raise RuntimeError("load_value() must be called inside bulk_load()")

        if value is None:
            return False

        item = self.get_item(key)
        if not item:
            InstallerLogger.warning(f'Ignoring unknown configuration item "{key}" from {source.label}')
            return False

        if (value == "") and not item.accept_blank:
            # a blank for a setting that can't be blank means the source has no value for it (the same
            #   as a variable left empty in a .env file), so the installer's default or another source applies
            return False

        if (previous := self._loaded_from.get(key)) and (previous[0] < source):
            # already loaded from a source that takes precedence
            return False

        if value is USE_DEFAULT:
            value = None
        else:
            try:
                value = apply_inbound(key, value)
                valid, error = self._validate_for_item(item, value)
            except Exception as e:
                # a validator that can't handle the value's type (e.g., a list where a string belongs)
                valid, error = False, f"{type(e).__name__}: {e}"
            if not valid:
                shown = self.loggable_value(key, value)
                self._record_load_issue(
                    key, source, f'{self._describe_source(source, detail)}: "{shown}" is not valid ({error})'
                )
                return False

        old_value = item.get_value()
        self._store_without_modifying(item, value)

        self._loaded_from[key] = (source, detail)
        self._loaded_values[key] = item.get_value()
        if not self._dependency_manager.has_derived_rule(key):
            # values with a DERIVED rule are recomputed from their inputs rather than protected
            self._loaded_keys.add(key)
        # this source takes precedence over any that had a problem with this item
        if (issue := self._load_issues.get(key)) and (issue.source >= source):
            del self._load_issues[key]

        if item.get_value() != old_value:
            self._notify_observers(key, item.get_value())
        return True

    def _record_load_issue(self, key: str, source: LoadSource, message: str) -> None:
        """Remember that a value for key from source couldn't be used."""
        if (previous := self._loaded_from.get(key)) and (previous[0] < source):
            return  # a source with higher precedence already supplied a good value
        if (issue := self._load_issues.get(key)) and (issue.source < source):
            return  # keep the issue from the source with higher precedence
        InstallerLogger.warning(f"Could not load {key} from {message}")
        self._load_issues[key] = LoadIssue(source=source, message=message)

    @staticmethod
    def _validate_for_item(item: ConfigItem, value: Any) -> Tuple[bool, str]:
        """Check a value against an item's validator without storing it."""
        if overrides_set_value(item):
            # items that override set_value (e.g., ListOfStringsConfigItem) convert before validating,
            #   so validate on a copy to get the same result set_value would
            probe = copy.copy(item)
            return probe.set_value(value)
        if item.validator:
            result = item.validator(value)
            valid, error = result if isinstance(result, tuple) else (bool(result), "Invalid value")
            if not valid:
                return False, error
        return True, ""

    @staticmethod
    def _store_without_modifying(item: ConfigItem, value: Any) -> None:
        """Store an already-validated value without changing the item's is_modified flag."""
        if (value is not None) and overrides_set_value(item):
            old_modified = item.is_modified
            item.set_value(value)
            item.is_modified = old_modified
        else:
            item.value = value

    def loggable_value(self, key: str, value: Any) -> Any:
        """The value as it may appear in a log or message (masked for password items)."""
        item = self.get_item(key)
        return "********" if (item and item.is_password and value) else value

    @staticmethod
    def _describe_source(source: LoadSource, detail: str = "") -> str:
        """e.g. 'env files (ARKIME_LIVE_CAPTURE)'"""
        return f"{source.label} ({detail})" if detail else source.label

    def _log_loaded_values(self) -> None:
        """Log each loaded setting's value and where it came from (debug level).

        If the dependency rules changed a value after it was loaded, the line says so and shows
        what the source had, since the final value didn't come from that source.
        """
        for key in sorted(self._loaded_from):
            source, detail = self._loaded_from[key]
            final_value = self.get_value(key)
            loaded_value = self._loaded_values.get(key)
            line = f'Loaded {key} = "{self.loggable_value(key, final_value)}"'
            if final_value != loaded_value:
                how = "recomputed" if self._dependency_manager.has_derived_rule(key) else "changed by a dependency rule"
                line += (
                    f' ({how}; {self._describe_source(source, detail)} '
                    f'had "{self.loggable_value(key, loaded_value)}")'
                )
            else:
                line += f" from {self._describe_source(source, detail)}"
            InstallerLogger.debug(line)

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
            # the user has now chosen this value themselves, so any problem loading it no longer applies
            self._load_issues.pop(key, None)

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

        Every value is computed before any file is touched, and a value that can't be computed
        or written raises instead of being skipped, so a failure never leaves a stale value
        behind silently. To keep the files themselves all-or-nothing, write into a staging
        directory (see env_file_utils.write_configuration_files).

        Raises:
            FileOperationError: If a value can't be computed or a file can't be written.
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
            for env_example_file in glob.glob(os.path.join(templates_dir, '*.env.example')):
                env_file = os.path.join(config_dir, os.path.basename(env_example_file[: -len('.example')]))
                if not os.path.isfile(env_file):
                    shutil.copyfile(env_example_file, env_file)
                    _ensure_trailing_newline(env_file)
                    InstallerLogger.info(
                        f"Created {os.path.basename(env_file)} from {os.path.basename(env_example_file)}"
                    )

        else:
            # Suppress warning during unit tests
            if "unittest" not in sys.modules:
                InstallerLogger.warning(f"Could not find .env.example templates directory. Expected: {templates_dir}")

        env_files_content: Dict[str, Dict[str, str]] = defaultdict(dict)
        transform_errors: List[str] = []

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
                    transform_errors.append(f"{env_var_obj.variable_name}: {e}")
                    continue
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

        if transform_errors:
            raise FileOperationError(
                f"Could not compute environment variable value(s), nothing was written: {'; '.join(transform_errors)}"
            )

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
                        raise FileOperationError(
                            f"Setting value for {key} in {os.path.basename(filepath)} failed ({type(e).__name__}): {e}"
                        ) from e

                _ensure_trailing_newline(filepath)
                InstallerLogger.info(f"Wrote environment file: {os.path.basename(filepath)}")
            self.config_dir_written = config_dir

        except (IOError, OSError) as e:
            raise FileOperationError(f"Failed to write environment file(s): {e}") from e

    def load_from_env_files(self, config_dir: str, source: LoadSource = LoadSource.ENV_FILES):
        """Load configuration from environment files.

        Args:
            config_dir: Directory containing environment files
            source: Which configuration source these files are (existing .env files, or the
                    backup in an imported settings file)
        """
        if not os.path.isdir(config_dir):
            return  # Nothing to load

        with self.bulk_load():
            env_values = self._collect_env_values(config_dir)
            candidates = self._build_candidates_from_env(env_values, source)
            self._apply_env_candidates(candidates, source)
        if source == LoadSource.ENV_FILES:
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

    def _build_candidates_from_env(self, env_values: Dict[str, str], source: LoadSource = LoadSource.ENV_FILES):
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
                for item_key in env_var_obj.config_items:
                    if env_var_obj.is_authoritative_for(item_key):
                        self._record_load_issue(
                            item_key,
                            source,
                            f'{source.label} ({env_var_obj.variable_name}): "{raw_value_str}" could not be read ({e})',
                        )
                continue
            if isinstance(typed_value, (list, tuple)) and (len(typed_value) == len(env_var_obj.config_items)):
                for item_key, tv in zip(env_var_obj.config_items, typed_value):
                    if tv is None:
                        continue
                    if tv == "" and not ((item := self._items.get(item_key)) and item.accept_blank):
                        continue
                    candidates[item_key].append((env_var_obj.key, tv))
            else:
                for item_key in env_var_obj.config_items:
                    if typed_value is None:
                        continue
                    if typed_value == "" and not ((item := self._items.get(item_key)) and item.accept_blank):
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

    def _apply_env_candidates(self, candidates, source: LoadSource = LoadSource.ENV_FILES):
        for item_key, options in candidates.items():
            if not options:
                continue
            winner_env_key, winner_value = self._resolve_env_option(item_key, options)
            if len(options) > 1 and winner_env_key is not None:
                losers = [ek for (ek, _) in options if ek != winner_env_key]
                InstallerLogger.debug(f"env conflict for {item_key}: picked {winner_env_key} over {losers}")
            if winner_value is None:
                continue
            if winner_value == "" and not ((item := self._items.get(item_key)) and item.accept_blank):
                continue
            winner_env_var = self._env_mapper.get_env_variable(winner_env_key)
            self.load_value(
                item_key,
                winner_value,
                source,
                detail=winner_env_var.variable_name if winner_env_var else winner_env_key,
            )

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
                with open(compose_file_name, 'r') as f, self.bulk_load():
                    if compose_data := yamlImported.YAML(typ='safe', pure=True).load(f):
                        # set settings from compose file, gracefully ignoring validation errors
                        #   (meaning we'll just end up with the defaults)

                        # container runtime docker vs. podman
                        self._load_compose_value(
                            KEY_CONFIG_ITEM_RUNTIME_BIN,
                            (
                                ContainerRuntime.PODMAN
                                if any(
                                    deep_get(config, ["userns_mode"]) == USERNS_MODE_KEEP_ID
                                    for config in deep_get(compose_data, ["services"], {}).values()
                                )
                                else ContainerRuntime.DOCKER
                            )
                        )

                        # restart policy
                        self._load_compose_value(
                            KEY_CONFIG_ITEM_MALCOLM_RESTART_POLICY,
                            next(
                                iter(
                                    {
                                        deep_get(config, ["restart"])
                                        for config in deep_get(compose_data, ["services"], {}).values()
                                    }
                                ),
                                None,
                            )
                        )

                        # network settings
                        if deep_get(compose_data, ["networks", "default", "external"], False):
                            self._load_compose_value(
                                KEY_CONFIG_ITEM_CONTAINER_NETWORK_NAME,
                                deep_get(compose_data, ["networks", "default", "name"])
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

    def _load_compose_value(self, key: str, value: Any) -> None:
        """Load a value read from the compose file (must be called inside bulk_load())."""
        self.load_value(key, value, LoadSource.COMPOSE_FILE, detail=COMPOSE_FILENAME)

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
            self._load_compose_value(KEY_CONFIG_ITEM_OPEN_PORTS, open_ports_choice)
            if open_ports_choice == OpenPortsChoices.CUSTOMIZE:
                # set the individual exposed services
                for expose_key in [k for v in exposed_services.values() for k, flag in v.items() if flag]:
                    self._load_compose_value(expose_key, True)
        else:
            self._load_compose_value(KEY_CONFIG_ITEM_OPEN_PORTS, OpenPortsChoices.NO)

        # for hedgehog mode, we have the request reachback ACL stored in an extension
        #   (if it isn't there, the compose file has nothing to say about it and the dependency rules decide)
        reachback_request_acl = deep_get(
            compose_data,
            [
                COMPOSE_MALCOLM_EXTENSION,
                COMPOSE_MALCOLM_EXTENSION_HEDGEHOG,
                COMPOSE_MALCOLM_EXTENSION_HEDGEHOG_REACHBACK_REQUEST_ACL,
            ],
            None,
        )
        if isinstance(reachback_request_acl, str):
            reachback_request_acl = [reachback_request_acl]
        if isinstance(reachback_request_acl, list):
            self._load_compose_value(KEY_CONFIG_ITEM_REACHBACK_REQUEST_ACL, reachback_request_acl)

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
                        self._load_compose_value(key_config_item, enabled)

    def _load_traefik_settings_from_orchestration_file(self, compose_data: Dict[Any, Any]):
        # traefik/reverse proxy stuff
        traefik_labels = self._get_traefik_labels(compose_data)
        if traefik_labels.get(TRAEFIK_ENABLE, False) is True:
            self._load_compose_value(KEY_CONFIG_ITEM_TRAEFIK_LABELS, True)
            self._load_compose_value(
                KEY_CONFIG_ITEM_TRAEFIK_HOST,
                (
                    re.findall(
                        r'Host\s*\(\s*[`"\']([^`"\']+)[`"\']',
                        traefik_labels.get(LABEL_MALCOLM_RULE, ""),
                    )
                    or [""]
                )[0]
            )
            self._load_compose_value(
                KEY_CONFIG_ITEM_TRAEFIK_ENTRYPOINT, traefik_labels.get(LABEL_MALCOLM_ENTRYPOINTS)
            )
            self._load_compose_value(
                KEY_CONFIG_ITEM_TRAEFIK_RESOLVER, traefik_labels.get(LABEL_MALCOLM_CERTRESOLVER)
            )
            self._load_compose_value(
                KEY_CONFIG_ITEM_TRAEFIK_OPENSEARCH_HOST,
                (
                    re.findall(
                        r'Host\s*\(\s*[`"\']([^`"\']+)[`"\']',
                        traefik_labels.get(LABEL_OS_RULE, ""),
                    )
                    or [""]
                )[0]
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
            KEY_CONFIG_ITEM_FILESCAN_LOG_DIR: (
                "filescan",
                FILESCAN_LOG_CONTAINER_PATH,
                os.path.realpath(os.path.join(os.path.dirname(compose_file_name), DEFAULT_FILESCAN_LOG_DIR)),
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
                    self._load_compose_value(config_key, local_path)
                    custom_path = True
        if custom_path:
            self._load_compose_value(KEY_CONFIG_ITEM_USE_DEFAULT_STORAGE_LOCATIONS, False)

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

            # Skip None values and empty strings (for non-accept_blank items) to avoid validation issues on import
            if value is None or (isinstance(value, str) and value == "" and not item.accept_blank):
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
