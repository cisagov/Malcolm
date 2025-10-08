#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2025 Battelle Energy Alliance, LLC.  All rights reserved.

from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any, Callable
from enum import Enum

from scripts.installer.configs.constants.installation_item_keys import (
    KEY_INSTALLATION_ITEM_LOAD_MALCOLM_IMAGES,
    KEY_INSTALLATION_ITEM_PULL_MALCOLM_IMAGES,
    KEY_INSTALLATION_ITEM_AUTO_TWEAKS,
    KEY_INSTALLATION_ITEM_INSTALL_DOCKER_IF_MISSING,
    KEY_INSTALLATION_ITEM_USE_HOMEBREW,
    KEY_INSTALLATION_ITEM_CONTINUE_WITHOUT_HOMEBREW,
    KEY_INSTALLATION_ITEM_CONFIGURE_DOCKER_RESOURCES,
    KEY_INSTALLATION_ITEM_TRY_DOCKER_REPOSITORY,
    KEY_INSTALLATION_ITEM_TRY_DOCKER_CONVENIENCE_SCRIPT,
    KEY_INSTALLATION_ITEM_APPLY_MEMORY_SETTINGS,
    KEY_INSTALLATION_ITEM_DOCKER_INSTALL_METHOD,
    KEY_INSTALLATION_ITEM_DOCKER_COMPOSE_INSTALL_METHOD,
)
from scripts.installer.configs.constants.enums import (
    DockerInstallMethod,
    DockerComposeInstallMethod,
)
from scripts.malcolm_constants import OrchestrationFramework
from scripts.installer.core.observable import ObservableStoreMixin


@dataclass
class InstallContext(ObservableStoreMixin):
    """Installation store for user choices and platform options."""

    # Source control
    image_source: str = "registry"  # "archive" | "registry" | "skip"
    image_archive_path: Optional[str] = None
    load_images_from_archive: bool = False
    tarball_path: Optional[str] = None

    # Installation behavior
    run_network_reachability_check: bool = True
    offline_mode: bool = False
    config_only: bool = False

    # System tweaks decisions (collected during installation setup when auto_tweaks=False)
    # Key: tweak identifier, Value: whether to apply this tweak
    system_tweaks_decisions: dict = field(default_factory=dict)

    # Basic fields for compatibility
    docker_extra_users: List[str] = field(default_factory=list)
    package_manager_choice: Optional[str] = None  # For Windows/macOS

    # User confirmation
    user_confirmed_install: bool = False

    # Installation ConfigItems - populated based on platform
    items: Dict[str, Any] = field(default_factory=dict)
    _observers: Dict[str, List[Callable[[Any], None]]] = field(default_factory=dict, init=False)
    # Cached cross-store runtime inputs (kept in sync via observers)
    _runtime_bin: Optional[str] = field(default=None, init=False)
    _orchestration_mode: Optional[OrchestrationFramework] = field(default=None, init=False)
    _docker_installed: Optional[bool] = field(default=None, init=False)
    _compose_available: Optional[bool] = field(default=None, init=False)

    def initialize_for_platform(self, platform_name: str) -> None:
        """Initialize installation items for the specified platform.

        Args:
            platform_name: Platform name ('linux', 'macos', 'windows', 'shared')
        """
        if platform_name.lower() == "linux":
            from scripts.installer.configs.installation_items.linux import (
                get_linux_installation_config_item_dict,
            )

            self.items = get_linux_installation_config_item_dict()
        elif platform_name.lower() == "macos":
            from scripts.installer.configs.installation_items.macos import (
                get_macos_installation_config_item_dict,
            )

            self.items = get_macos_installation_config_item_dict()
        elif platform_name.lower() == "windows":
            from scripts.installer.configs.installation_items.windows import (
                ALL_WINDOWS_INSTALLATION_CONFIG_ITEMS_DICT,
            )

            self.items = ALL_WINDOWS_INSTALLATION_CONFIG_ITEMS_DICT
        else:
            # Default to shared items
            from scripts.installer.configs.installation_items.shared import (
                ALL_SHARED_INSTALLATION_CONFIG_ITEMS_DICT,
            )

            self.items = ALL_SHARED_INSTALLATION_CONFIG_ITEMS_DICT
        # Register platform-specific tweak items
        try:
            if platform_name.lower() == "linux":
                self._register_linux_tweak_items()
        except Exception:
            # Non-fatal; tweaks remain optional
            pass

    def _register_linux_tweak_items(self) -> None:
        """Register Linux tweak items from the Tweak Registry as first-class items."""
        from scripts.installer.core.tweak_registry import get_linux_tweak_definitions
        from scripts.installer.core.config_item import ConfigItem
        from scripts.installer.configs.constants.installation_item_keys import (
            KEY_INSTALLATION_ITEM_AUTO_TWEAKS,
        )

        tweak_defs = get_linux_tweak_definitions()
        sysctl_children_ids: list[str] = []
        for tdef in tweak_defs:
            tid = tdef.get("id")
            if not tid:
                continue
            label = tdef.get("label", tid)
            item = ConfigItem(
                key=tid,
                label=label,
                default_value=False,
                choices=[True, False],
            )
            # parent relationships
            ui_parent = tdef.get("ui_parent")
            if ui_parent:
                item.ui_parent = ui_parent
            if ui_parent == "sysctl":
                sysctl_children_ids.append(tid)
            # metadata flags
            meta = tdef.get("metadata") or {}
            if meta:
                item.metadata.update(meta)
            self.items[tid] = item

        # when "Enable All Sysctl Settings" is enabled, set all sysctl children to True (unless user-modified)
        def _on_sysctl_toggle(enabled: Any) -> None:
            try:
                if bool(enabled):
                    for cid in sysctl_children_ids:
                        it = self.items.get(cid)
                        if it and not it.is_modified:
                            it.set_value(True)
            except Exception:
                pass

        # attach observer to sysctl parent if present
        if "sysctl" in self.items:
            self.observe("sysctl", _on_sysctl_toggle)

    def attach_runtime_source(self, malcolm_config: Any) -> None:
        """Attach MalcolmConfig to observe runtime values for visibility rules.

        This avoids UI code having to pass runtime values for visibility checks.
        """
        try:
            from scripts.installer.configs.constants.configuration_item_keys import (
                KEY_CONFIG_ITEM_RUNTIME_BIN,
                KEY_CONFIG_ITEM_DOCKER_ORCHESTRATION_MODE,
            )

            # seed cached values
            self._runtime_bin = malcolm_config.get_value(KEY_CONFIG_ITEM_RUNTIME_BIN)
            self._orchestration_mode = malcolm_config.get_value(
                KEY_CONFIG_ITEM_DOCKER_ORCHESTRATION_MODE
            )

            def _on_runtime_bin(val: Any) -> None:
                try:
                    self._runtime_bin = val
                except Exception:
                    pass

            def _on_orch_mode(val: Any) -> None:
                try:
                    self._orchestration_mode = val
                except Exception:
                    pass

            malcolm_config.observe(KEY_CONFIG_ITEM_RUNTIME_BIN, _on_runtime_bin)
            malcolm_config.observe(
                KEY_CONFIG_ITEM_DOCKER_ORCHESTRATION_MODE, _on_orch_mode
            )
        except Exception:
            # Best-effort attachment; safe to continue without observers
            pass

    def attach_platform_probe(self, platform: Any) -> None:
        """Probe platform for container tooling availability for visibility rules."""
        try:
            self._docker_installed = bool(platform.is_docker_installed())
        except Exception:
            self._docker_installed = None
        # Discover compose availability using shared helper if possible
        try:
            from scripts.installer.actions.shared import discover_compose_command  # type: ignore

            rb = (self._runtime_bin or "").lower()
            cmd = discover_compose_command(rb, platform)
            self._compose_available = bool(cmd)
        except Exception:
            self._compose_available = None

    def get_item_value(self, key: str) -> Any:
        """Get the value of an installation item.

        Args:
            key: The item key

        Returns:
            The item's current value, or None if not found
        """
        if key in self.items:
            return self.items[key].get_value()
        return None

    def set_item_value(self, key: str, value: Any) -> bool:
        """Set the value of an installation item.

        Args:
            key: The item key
            value: The new value

        Returns:
            True if value was set, False if key not found
        """
        if key in self.items:
            # Delegate to Transform Registry for normalization
            try:
                from scripts.installer.core.transform_registry import apply_inbound

                value = apply_inbound(key, value)
            except Exception:
                pass
            self.items[key].set_value(value)
            # enforce simple mutual exclusivity between image source toggles
            try:
                if key == KEY_INSTALLATION_ITEM_LOAD_MALCOLM_IMAGES and bool(value):
                    if KEY_INSTALLATION_ITEM_PULL_MALCOLM_IMAGES in self.items:
                        self.items[KEY_INSTALLATION_ITEM_PULL_MALCOLM_IMAGES].set_value(
                            False
                        )
                    # reflect source hint fields
                    self.image_source = "archive"
                    self.load_images_from_archive = True
                elif key == KEY_INSTALLATION_ITEM_PULL_MALCOLM_IMAGES and bool(value):
                    if KEY_INSTALLATION_ITEM_LOAD_MALCOLM_IMAGES in self.items:
                        self.items[KEY_INSTALLATION_ITEM_LOAD_MALCOLM_IMAGES].set_value(
                            False
                        )
                    self.image_source = "registry"
                    self.load_images_from_archive = False
            except Exception:
                pass
            # notify observers
            self._notify_observers(key, self.items[key].get_value())
            return True
        # Unknown key when items not initialized: signal failure
        return False

    # Explicit API for known config side effects (avoid reflection)
    def set_docker_extra_users(self, users: List[str]) -> None:
        self.docker_extra_users = users or []

    # per-item normalization is centralized in the Transform Registry

    # ItemStore Protocol conformance methods
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
        try:
            from scripts.installer.core.visibility import install_item_is_visible

            return install_item_is_visible(self, key, item)
        except Exception:
            return bool(item.is_visible)

    def all_keys(self) -> List[str]:
        return list(self.items.keys())

    

    def _notify_observers(self, key: str, value: Any) -> None:
        if key in self._observers:
            for cb in list(self._observers[key]):
                try:
                    cb(value)
                except Exception:
                    # Observers must not break installer flow
                    pass

    # Compatibility properties for step functions that expect direct fields
    @property
    def auto_tweaks(self) -> bool:
        """Get auto_tweaks value from items or default."""
        return self.get_item_value(KEY_INSTALLATION_ITEM_AUTO_TWEAKS) or True

    @property
    def install_docker_if_missing(self) -> bool:
        """Get install_docker_if_missing value from items or default."""
        return (
            self.get_item_value(KEY_INSTALLATION_ITEM_INSTALL_DOCKER_IF_MISSING) or True
        )

    @property
    def use_homebrew(self) -> bool:
        """Get use_homebrew value from items or default."""
        return self.get_item_value(KEY_INSTALLATION_ITEM_USE_HOMEBREW) or True

    @property
    def continue_without_homebrew(self) -> bool:
        """Get continue_without_homebrew value from items or default."""
        return (
            self.get_item_value(KEY_INSTALLATION_ITEM_CONTINUE_WITHOUT_HOMEBREW)
            or False
        )

    @property
    def configure_docker_resources(self) -> bool:
        """Get configure_docker_resources value from items or default."""
        return (
            self.get_item_value(KEY_INSTALLATION_ITEM_CONFIGURE_DOCKER_RESOURCES)
            or True
        )

    @property
    def try_docker_repository_install(self) -> bool:
        """Get try_docker_repository_install value from items or default."""
        return self.get_item_value(KEY_INSTALLATION_ITEM_TRY_DOCKER_REPOSITORY) or True

    @property
    def try_docker_convenience_script(self) -> bool:
        """Get try_docker_convenience_script value from items or default."""
        return (
            self.get_item_value(KEY_INSTALLATION_ITEM_TRY_DOCKER_CONVENIENCE_SCRIPT)
            or False
        )

    @property
    def apply_memory_settings(self) -> bool:
        """Get apply_memory_settings value from items or default."""
        return self.get_item_value(KEY_INSTALLATION_ITEM_APPLY_MEMORY_SETTINGS) or True

    @property
    def pull_malcolm_images(self) -> bool:
        """Get pull_malcolm_images value from items or default."""
        return bool(self.get_item_value(KEY_INSTALLATION_ITEM_PULL_MALCOLM_IMAGES))

    # ------------------------------------------------------------------
    # Serialization helpers for testing/session continuity
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
