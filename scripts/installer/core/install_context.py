#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2025 Battelle Energy Alliance, LLC.  All rights reserved.

from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any
from enum import Enum

from scripts.installer.configs.constants.configuration_item_keys import (
    KEY_CONFIG_ITEM_DOCKER_ORCHESTRATION_MODE,
    KEY_CONFIG_ITEM_RUNTIME_BIN,
)

from scripts.malcolm_constants import PLATFORM_LINUX, PLATFORM_MAC, PLATFORM_WINDOWS

from scripts.installer.configs.installation_items.shared import (
    get_shared_installation_config_item_dict,
)
from scripts.installer.configs.installation_items.linux import (
    get_linux_installation_config_item_dict,
)
from scripts.installer.configs.installation_items.macos import (
    get_macos_installation_config_item_dict,
)
from scripts.installer.configs.installation_items.windows import (
    get_windows_installation_config_item_dict,
)

from scripts.installer.configs.constants.installation_item_keys import (
    KEY_INSTALLATION_ITEM_AUTO_TWEAKS,
    KEY_INSTALLATION_ITEM_CONFIGURE_DOCKER_RESOURCES,
    KEY_INSTALLATION_ITEM_INSTALL_DOCKER_IF_MISSING,
    KEY_INSTALLATION_ITEM_PULL_MALCOLM_IMAGES,
    KEY_INSTALLATION_ITEM_TRY_DOCKER_CONVENIENCE_SCRIPT,
    KEY_INSTALLATION_ITEM_TRY_DOCKER_REPOSITORY,
    KEY_INSTALLATION_ITEM_USE_HOMEBREW,
)
from scripts.malcolm_constants import OrchestrationFramework
from scripts.installer.core.visibility import install_item_is_visible
from scripts.installer.core.transform_registry import apply_inbound
from scripts.installer.utils.logger_utils import InstallerLogger
from scripts.installer.actions.shared import discover_compose_command  # type: ignore
from scripts.malcolm_common import GetNonRootMalcolmUserNames


@dataclass
class InstallContext:
    """Installation store for user choices and platform options."""

    # Installation behavior
    config_only: bool = False

    # Basic fields for compatibility
    has_system_tweaks: Optional[bool] = field(default=False, init=False)
    docker_extra_users: List[str] = field(default_factory=list)

    # User confirmation
    user_confirmed_install: bool = False

    # Installation ConfigItems - populated based on platform
    items: Dict[str, Any] = field(default_factory=dict)
    # Cached cross-store runtime inputs
    _runtime_bin: Optional[str] = field(default=None, init=False)
    _orchestration_mode: Optional[OrchestrationFramework] = field(default=None, init=False)
    _docker_installed: Optional[bool] = field(default=None, init=False)
    _compose_available: Optional[bool] = field(default=None, init=False)
    _sysctl_children_ids: List[str] = field(default_factory=list, init=False)

    def initialize_for_platform(self, platform_name: str) -> None:
        """Initialize installation items for the specified platform.

        Args:
            platform_name: Platform name ('linux', 'macos', 'windows', 'shared')
        """
        if platform_name.lower() == PLATFORM_LINUX.lower() or platform_name.lower() == "linux":
            self.items = {**get_linux_installation_config_item_dict(), **get_shared_installation_config_item_dict()}
        elif platform_name.lower() == PLATFORM_MAC.lower() or platform_name.lower() == "macos":
            self.items = {**get_macos_installation_config_item_dict(), **get_shared_installation_config_item_dict()}
        elif platform_name.lower() == PLATFORM_WINDOWS.lower() or platform_name.lower() == "windows":
            self.items = {**get_windows_installation_config_item_dict(), **get_shared_installation_config_item_dict()}
        # Register platform-specific tweak items
        if platform_name.lower() == PLATFORM_LINUX.lower() or platform_name.lower() == "linux":
            self._register_linux_tweak_items()
            self.has_system_tweaks = True
            self.set_docker_extra_users(GetNonRootMalcolmUserNames())

    def _register_linux_tweak_items(self) -> None:
        """Register Linux tweak items from the Tweak Registry as first-class items."""
        from scripts.installer.core.tweak_registry import get_linux_tweak_definitions
        from scripts.installer.core.config_item import ConfigItem

        tweak_defs = get_linux_tweak_definitions()
        sysctl_children_ids: list[str] = []
        for tweak_def in tweak_defs:
            tid = tweak_def.get("id")
            if not tid:
                continue
            label = tweak_def.get("label", tid)
            item = ConfigItem(
                key=tid,
                label=label,
                default_value=False,
                choices=[True, False],
            )
            # parent relationships
            ui_parent = tweak_def.get("ui_parent")
            if ui_parent:
                item.ui_parent = ui_parent
            if ui_parent == "sysctl":
                sysctl_children_ids.append(tid)
            # metadata flags
            meta = tweak_def.get("metadata") or {}
            if meta:
                item.metadata.update(meta)
            self.items[tid] = item

        self._sysctl_children_ids = sysctl_children_ids

    def attach_runtime_source(self, malcolm_config: Any) -> None:
        """Cache runtime values from MalcolmConfig for visibility checks."""
        self._runtime_bin = malcolm_config.get_value(KEY_CONFIG_ITEM_RUNTIME_BIN)
        self._orchestration_mode = malcolm_config.get_value(KEY_CONFIG_ITEM_DOCKER_ORCHESTRATION_MODE)

    def attach_platform_probe(self, platform: Any) -> None:
        """Probe platform for container tooling availability for visibility rules."""
        rb = (self._runtime_bin or "").lower()
        self._docker_installed = bool(platform.is_docker_installed(runtime_bin=rb))
        cmd = discover_compose_command(rb, platform)
        self._compose_available = bool(cmd)

    def get_item_value(self, key: str, default=None) -> Any:
        """Get the value of an installation item.

        Args:
            key: The item key

        Returns:
            The item's current value, or None if not found
        """
        if key in self.items:
            return self.items[key].get_value()
        return default

    def set_item_value(self, key: str, value: Any) -> bool:
        """Set the value of an installation item.

        Args:
            key: The item key
            value: The new value

        Returns:
            True if value was set, False if key not found
        """
        if key in self.items:
            try:
                value = apply_inbound(key, value)
            except Exception:
                InstallerLogger.warning(f"Failed to normalize value for {key}: {value}")
                return False
            try:
                self.items[key].set_value(value)
            except Exception:
                InstallerLogger.warning(f"Failed to set value for {key}: {value}")
                return False

            if key == "sysctl" and bool(value):
                for cid in self._sysctl_children_ids:
                    it = self.items.get(cid)
                    if it and not it.is_modified:
                        it.set_value(True)

            return True
        return False

    def set_docker_extra_users(self, users: List[str]) -> None:
        self.docker_extra_users = users or []

    def get_item(self, key: str):
        return self.items.get(key)

    def get_value(self, key: str):
        return self.get_item_value(key)

    def set_value(self, key: str, value: Any) -> None:
        self.set_item_value(key, value)

    def is_item_visible(self, key: str) -> bool:
        item = self.items.get(key)
        if item is None:
            return False
        return install_item_is_visible(self, key, item)

    @property
    def auto_tweaks(self) -> bool:
        """Get auto_tweaks value from items or default."""
        return self.get_item_value(KEY_INSTALLATION_ITEM_AUTO_TWEAKS, default=True)

    @property
    def install_docker_if_missing(self) -> bool:
        """Get install_docker_if_missing value from items or default."""
        return self.get_item_value(KEY_INSTALLATION_ITEM_INSTALL_DOCKER_IF_MISSING, default=True)

    @property
    def use_homebrew(self) -> bool:
        """Get use_homebrew value from items or default."""
        return self.get_item_value(KEY_INSTALLATION_ITEM_USE_HOMEBREW, default=True)

    @property
    def configure_docker_resources(self) -> bool:
        """Get configure_docker_resources value from items or default."""
        return self.get_item_value(KEY_INSTALLATION_ITEM_CONFIGURE_DOCKER_RESOURCES, default=True)

    @property
    def try_docker_repository_install(self) -> bool:
        """Get try_docker_repository_install value from items or default."""
        return self.get_item_value(KEY_INSTALLATION_ITEM_TRY_DOCKER_REPOSITORY, default=True)

    @property
    def try_docker_convenience_script(self) -> bool:
        """Get try_docker_convenience_script value from items or default."""
        return self.get_item_value(KEY_INSTALLATION_ITEM_TRY_DOCKER_CONVENIENCE_SCRIPT, default=False)

    @property
    def pull_malcolm_images(self) -> bool:
        """Get pull_malcolm_images value from items or default."""
        return bool(self.get_item_value(KEY_INSTALLATION_ITEM_PULL_MALCOLM_IMAGES, default=False))

    # ------------------------------------------------------------------
    # Serialization helpers for testing
    # ------------------------------------------------------------------
    def to_dict_values_only(self) -> Dict[str, Any]:
        """Return a simple dict of installation item values.

        Skips None/empty values, converts Enum to serializable representation.
        """
        result: Dict[str, Any] = {}
        for key, item in self.items.items():
            val = item.get_value()
            if val is None or (isinstance(val, str) and val == ""):
                continue
            if isinstance(val, Enum):
                # Prefer value if it is a string; otherwise use name
                result[key] = val.value if isinstance(val.value, str) else val.name
            else:
                result[key] = val
        return result

    def load_from_dict(self, installation_section: Dict[str, Any]) -> List[str]:
        """Apply values from dict to installation items.

        Returns a list of keys that were absent (left at defaults).
        """
        missing: List[str] = []
        for key, item in self.items.items():
            if key not in installation_section:
                missing.append(key)
                continue
            value = installation_section.get(key)
            if value is None:
                continue
            try:
                self.set_item_value(key, value)
            except Exception:
                # Ignore invalid values here; validators will surface issues during normal flow
                pass
        return missing
