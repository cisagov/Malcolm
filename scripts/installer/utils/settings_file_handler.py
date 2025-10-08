#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2025 Battelle Energy Alliance, LLC.  All rights reserved.

"""Read and write settings (JSON/YAML) for MalcolmConfig and InstallContext."""

import json
import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional
from ruamel.yaml import YAML

from scripts.installer.core.malcolm_config import MalcolmConfig
from scripts.installer.core.install_context import InstallContext
from scripts.installer.utils.exceptions import (
    FileOperationError,
    ConfigValueValidationError,
)
from scripts.installer.configs.constants.configuration_item_keys import (
    KEY_CONFIG_ITEM_MALCOLM_RESTART_POLICY,
    KEY_CONFIG_ITEM_RUNTIME_BIN,
    KEY_CONFIG_ITEM_FILEBEAT_TCP_LOG_FORMAT,
    KEY_CONFIG_ITEM_NETBOX_MODE,
    KEY_CONFIG_ITEM_IMAGE_ARCH,
    KEY_CONFIG_ITEM_DOCKER_ORCHESTRATION_MODE,
)
from scripts.installer.configs.constants.installation_item_keys import (
    KEY_INSTALLATION_ITEM_AUTO_TWEAKS,
    KEY_INSTALLATION_ITEM_APPLY_MEMORY_SETTINGS,
    KEY_INSTALLATION_ITEM_INSTALL_DOCKER_IF_MISSING,
    KEY_INSTALLATION_ITEM_USE_HOMEBREW,
    KEY_INSTALLATION_ITEM_CONTINUE_WITHOUT_HOMEBREW,
    KEY_INSTALLATION_ITEM_CONFIGURE_DOCKER_RESOURCES,
    KEY_INSTALLATION_ITEM_TRY_DOCKER_REPOSITORY,
    KEY_INSTALLATION_ITEM_TRY_DOCKER_CONVENIENCE_SCRIPT,
    KEY_INSTALLATION_ITEM_DOCKER_INSTALL_METHOD,
    get_set_of_installation_item_keys,
)
from scripts.malcolm_utils import get_config_file_version
from scripts.installer.utils.logger_utils import InstallerLogger
from enum import Enum, Flag

CONFIG_FILE_VERSION = get_config_file_version()

# Sentinel value for None/empty values that maintains format consistency
CONFIG_ITEM_NONE_SENTINEL = "<MALCOLM_CONFIG_NONE>"


class SettingsFileHandler:
    """Handler for loading and saving Malcolm installer settings files.

    This class coordinates between MalcolmConfig (runtime configuration) and
    InstallContext (installation decisions) to provide a unified interface
    for reading from and writing to JSON/YAML settings files.
    """

    def __init__(
        self,
        malcolm_config: MalcolmConfig,
        install_context: Optional[InstallContext] = None,
    ):
        """Initialize the settings file handler.

        Args:
            malcolm_config: MalcolmConfig instance for runtime configuration
            install_context: InstallContext instance for installation decisions (optional)
        """
        self.malcolm_config = malcolm_config
        self.install_context = install_context or InstallContext()

    def load_from_file(self, settings_file_path: str) -> Dict[str, List[str]]:
        """Load configuration from JSON/YAML settings file.

        This method loads settings from a file and applies them to both the
        MalcolmConfig and InstallContext instances. It returns information about
        any settings that were missing and used default values.

        Args:
            settings_file_path: Path to the settings file (JSON or YAML)

        Returns:
            Dictionary with keys 'missing_configuration' and 'missing_installation'
            containing lists of missing items that used defaults

        Raises:
            FileOperationError: If file cannot be read or parsed
            ConfigValueValidationError: If settings contain invalid values
        """
        settings_path = Path(settings_file_path)
        if not settings_path.exists():
            raise FileOperationError(f"Settings file not found: {settings_file_path}")

        # parse the file
        settings_data = self._parse_settings_file(settings_path)

        if not isinstance(settings_data, dict):
            raise ConfigValueValidationError(
                "Settings file must contain a dictionary/object at root level"
            )

        missing_items = {"missing_configuration": [], "missing_installation": []}

        # process configuration section
        configuration_section = settings_data.get("configuration", {})
        if isinstance(configuration_section, dict):
            missing_items["missing_configuration"] = self._load_configuration_section(
                configuration_section
            )

        # process installation section
        installation_section = settings_data.get("installation", {})
        if isinstance(installation_section, dict):
            missing_items["missing_installation"] = self._load_installation_section(
                installation_section
            )

        return missing_items

    def save_to_file(
        self,
        settings_file_path: str,
        file_format: str = "auto",
        include_installation_items: bool = True,
        dry_run: bool = False,
    ) -> None:
        """Save current configuration to JSON/YAML settings file.

        Args:
            settings_file_path: Path where to save the settings file
            file_format: Format to use ('json', 'yaml', or 'auto' to detect from extension)
            include_installation_items: Whether to include installation section

        Raises:
            FileOperationError: If file cannot be written
        """
        settings_path = Path(settings_file_path)

        # determine output format
        if file_format == "auto":
            if settings_path.suffix.lower() in [".yml", ".yaml"]:
                file_format = "yaml"
            else:
                file_format = "json"

        # build settings structure
        settings_data = self._build_settings_data(include_installation_items)

        # dry-run support: report intended action and return
        if dry_run:
            InstallerLogger.info(
                f"Dry run: would save settings to {settings_file_path} as {file_format}"
            )
            return

        # write to file
        try:
            settings_path.parent.mkdir(parents=True, exist_ok=True)

            if file_format == "yaml":
                yaml = YAML()
                yaml.default_flow_style = False
                yaml.width = 4096  # prevent line wrapping
                with open(settings_path, "w") as f:
                    yaml.dump(settings_data, f)
            else:  # json
                with open(settings_path, "w") as f:
                    json.dump(settings_data, f, indent=2, sort_keys=True)

            InstallerLogger.debug(f"Settings saved to {settings_file_path}")
        except Exception as e:
            raise FileOperationError(
                f"Failed to write settings file {settings_file_path}: {e}"
            )

    def generate_default_export_filename(self, file_format: str = "json") -> str:
        """Generate a default export filename with timestamp.

        Args:
            file_format: File format to use ('json' or 'yaml')

        Returns:
            Generated filename with timestamp
        """
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        extension = "yaml" if file_format == "yaml" else "json"
        return f"malcolm-config_{timestamp}.{extension}"

    def get_template(self) -> Dict[str, Any]:
        """Generate a template settings file structure with all available options.

        Returns:
            Dictionary representing the complete settings file structure with defaults and descriptions
        """
        template = {
            "metadata": {
                "description": "Malcolm installer configuration file",
                "version": CONFIG_FILE_VERSION,
                "documentation": "https://malcolm.readthedocs.io/en/latest/installation.html",
                "usage": "Run installer with: ./install.py --import-config <path_to_this_file>",
            },
            "configuration": {},
            "installation": {},
        }

        # add all configuration items with their defaults and descriptions
        for key, item in self.malcolm_config.get_all_config_items().items():
            template["configuration"][key] = {
                "value": item.default_value,
                "description": item.metadata.get("help", "No description available"),
                "type": (
                    type(item.default_value).__name__
                    if item.default_value is not None
                    else "any"
                ),
            }

        # add installation items with defaults
        installation_keys = get_set_of_installation_item_keys()
        installation_defaults = self._get_installation_defaults()

        for key in installation_keys:
            if key in installation_defaults:
                value, description = installation_defaults[key]
                template["installation"][key] = {
                    "value": value,
                    "description": description,
                    "type": type(value).__name__ if value is not None else "any",
                }
            else:
                template["installation"][key] = {
                    "value": None,
                    "description": "Installation option (see documentation)",
                    "type": "any",
                }

        return template

    def _parse_settings_file(self, settings_path: Path) -> Dict[str, Any]:
        """Parse settings file content based on format detection.

        Args:
            settings_path: Path to the settings file

        Returns:
            Parsed settings data as dictionary

        Raises:
            FileOperationError: If file cannot be parsed
        """
        try:
            # determine file format and parse accordingly
            if settings_path.suffix.lower() in [".yml", ".yaml"]:
                yaml = YAML(typ="safe", pure=True)
                with open(settings_path, "r") as f:
                    return yaml.load(f) or {}
            elif settings_path.suffix.lower() == ".json":
                with open(settings_path, "r") as f:
                    return json.load(f)
            else:
                # try to auto-detect by parsing content
                with open(settings_path, "r") as f:
                    content = f.read().strip()
                    if content.startswith("{"):
                        return json.loads(content)
                    else:
                        yaml = YAML(typ="safe", pure=True)
                        return yaml.load(content) or {}
        except Exception as e:
            raise FileOperationError(
                f"Failed to parse settings file {settings_path}: {e}"
            )

    def _load_configuration_section(
        self, configuration_section: Dict[str, Any]
    ) -> List[str]:
        """Load configuration section and apply to MalcolmConfig.

        Args:
            configuration_section: Configuration settings from file

        Returns:
            List of configuration keys that were missing and used defaults
        """
        missing_configuration = []

        # apply settings to MalcolmConfig
        for key, value in configuration_section.items():
            if self.malcolm_config.get_item(key) is not None:
                try:
                    # Skip sentinel values (leave as default None/empty)
                    if value == CONFIG_ITEM_NONE_SENTINEL:
                        InstallerLogger.debug(
                            f"Skipping configuration item {key} (sentinel value)"
                        )
                        continue
                    # delegate normalization and validation to MalcolmConfig
                    self.malcolm_config.set_value(key, value)
                    InstallerLogger.debug(f"Set configuration item {key} = {value}")
                except Exception as e:
                    InstallerLogger.warning(
                        f"Failed to set configuration item {key}: {e}"
                    )
            else:
                InstallerLogger.warning(
                    f"Unknown configuration item in settings file: {key}"
                )

        # identify configuration items that weren't set and use defaults
        for item_key, item in self.malcolm_config.get_all_config_items().items():
            if not item.is_modified:
                missing_configuration.append(item_key)
                InstallerLogger.debug(
                    f"Configuration item {item_key} not found in settings file, using default: {item.get_value()}"
                )

        return missing_configuration

    def _load_installation_section(
        self, installation_section: Dict[str, Any]
    ) -> List[str]:
        """Load installation section and apply to InstallContext.

        Args:
            installation_section: Installation settings from file

        Returns:
            List of installation keys that were missing and used defaults
        """
        missing_installation = []

        # apply installation settings directly to InstallContext.items
        for key, value in installation_section.items():
            if key in self.install_context.items:
                try:
                    # Skip sentinel values (leave as default None/empty)
                    if value == CONFIG_ITEM_NONE_SENTINEL:
                        InstallerLogger.debug(
                            f"Skipping installation item {key} (sentinel value)"
                        )
                        continue
                    # delegate normalization/validation to InstallContext
                    self.install_context.set_item_value(key, value)
                    InstallerLogger.debug(f"Set installation item {key} = {value}")
                except Exception as e:
                    InstallerLogger.warning(
                        f"Failed to set installation item {key}: {e}"
                    )
            else:
                InstallerLogger.warning(
                    f"Unknown installation item in settings file: {key}"
                )

        # identify installation items that weren't set
        for key in self.install_context.items.keys():
            if key not in installation_section:
                missing_installation.append(key)
                InstallerLogger.debug(
                    f"Installation item {key} not found in settings file, using default"
                )

        return missing_installation

    def _build_settings_data(self, include_installation_items: bool) -> Dict[str, Any]:
        """Build the settings data structure for saving.

        Args:
            include_installation_items: Whether to include installation section

        Returns:
            Settings data structure ready for serialization
        """
        settings_data = {
            "configuration": {},
            "metadata": {
                "generated_by": "Malcolm Installer",
                "timestamp": datetime.datetime.now().isoformat(),
                "version": CONFIG_FILE_VERSION,
            },
        }

        # add ALL configuration items from MalcolmConfig.items dictionary
        for key, item in self.malcolm_config.get_all_config_items().items():
            value = item.get_value()

            # if current value is None/empty but default_value is valid, use the default
            if (value is None or (isinstance(value, str) and value == "")) and (
                item.default_value is not None
                and not (
                    isinstance(item.default_value, str) and item.default_value == ""
                )
            ):
                value = item.default_value

            # if value is still None/empty, use sentinel value for format consistency
            if value is None or (isinstance(value, str) and value == ""):
                value = CONFIG_ITEM_NONE_SENTINEL

            # convert enum values to serializable strings
            value = self._serialize_value(value)
            settings_data["configuration"][key] = value

        # optionally add installation items
        if include_installation_items:
            settings_data["installation"] = self._get_installation_section()

        return settings_data

    def _get_installation_section(self) -> Dict[str, Any]:
        """Get the installation section from current InstallContext.

        Returns:
            Installation settings dictionary
        """
        installation_section = {}

        # Export ALL installation items from InstallContext.items
        for key, item in self.install_context.items.items():
            value = item.get_value()

            # if current value is None/empty but default_value is valid, use the default
            if (value is None or (isinstance(value, str) and value == "")) and (
                item.default_value is not None
                and not (
                    isinstance(item.default_value, str) and item.default_value == ""
                )
            ):
                value = item.default_value

            # if value is still None/empty, use sentinel value for format consistency
            if value is None or (isinstance(value, str) and value == ""):
                value = CONFIG_ITEM_NONE_SENTINEL

            # convert enum values to serializable strings
            value = self._serialize_value(value)
            installation_section[key] = value

        return installation_section

    def _serialize_value(self, value: Any) -> Any:
        """Serialize values for settings export.

        - For Enum members, return `.value` (or `.name` for Flag for readability).
        - All other values pass through unchanged.
        """
        if isinstance(value, Enum):
            if isinstance(value, Flag):
                return value.name
            return value.value
        return value

    # Note: deserialization is delegated to MalcolmConfig and InstallContext

    def _get_installation_field_mapping(self) -> Dict[str, str]:
        """Get mapping between installation item keys and InstallContext field names.

        Returns:
            Dictionary mapping installation keys to InstallContext field names
        """
        return {
            KEY_INSTALLATION_ITEM_AUTO_TWEAKS: "auto_tweaks",
            KEY_INSTALLATION_ITEM_APPLY_MEMORY_SETTINGS: "apply_memory_settings",
            KEY_INSTALLATION_ITEM_INSTALL_DOCKER_IF_MISSING: "install_docker_if_missing",
            KEY_INSTALLATION_ITEM_USE_HOMEBREW: "use_homebrew",
            KEY_INSTALLATION_ITEM_CONTINUE_WITHOUT_HOMEBREW: "continue_without_homebrew",
            KEY_INSTALLATION_ITEM_CONFIGURE_DOCKER_RESOURCES: "configure_docker_resources",
            KEY_INSTALLATION_ITEM_TRY_DOCKER_REPOSITORY: "try_docker_repository_install",
            KEY_INSTALLATION_ITEM_TRY_DOCKER_CONVENIENCE_SCRIPT: "try_docker_convenience_script",
        }

    def _get_installation_defaults(self) -> Dict[str, tuple]:
        """Get installation defaults with descriptions.

        Returns:
            Dictionary mapping installation keys to (default_value, description) tuples
        """
        default_context = InstallContext()

        return {
            KEY_INSTALLATION_ITEM_AUTO_TWEAKS: (
                default_context.auto_tweaks,
                "Apply system tweaks automatically",
            ),
            KEY_INSTALLATION_ITEM_APPLY_MEMORY_SETTINGS: (
                default_context.apply_memory_settings,
                "Apply memory optimization settings",
            ),
            KEY_INSTALLATION_ITEM_INSTALL_DOCKER_IF_MISSING: (
                default_context.install_docker_if_missing,
                "Install Docker if not present",
            ),
            KEY_INSTALLATION_ITEM_USE_HOMEBREW: (
                default_context.use_homebrew,
                "Use Homebrew package manager (macOS)",
            ),
            KEY_INSTALLATION_ITEM_CONTINUE_WITHOUT_HOMEBREW: (
                default_context.continue_without_homebrew,
                "Continue without Homebrew if unavailable",
            ),
            KEY_INSTALLATION_ITEM_CONFIGURE_DOCKER_RESOURCES: (
                default_context.configure_docker_resources,
                "Configure Docker CPU/RAM settings",
            ),
            KEY_INSTALLATION_ITEM_TRY_DOCKER_REPOSITORY: (
                default_context.try_docker_repository_install,
                "Try Docker repository installation first",
            ),
            KEY_INSTALLATION_ITEM_TRY_DOCKER_CONVENIENCE_SCRIPT: (
                default_context.try_docker_convenience_script,
                "Try Docker convenience script if repository fails",
            ),
        }
