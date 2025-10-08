#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2025 Battelle Energy Alliance, LLC.  All rights reserved.

"""Installation menu for TUI installer interface."""

import os
from typing import Optional, Dict, Any, TYPE_CHECKING
from scripts.installer.ui.tui.base_menu import BaseMenu, MenuItem
from scripts.installer.configs.constants.configuration_item_keys import (
    KEY_CONFIG_ITEM_RUNTIME_BIN,
    KEY_CONFIG_ITEM_DOCKER_ORCHESTRATION_MODE,
)
from scripts.malcolm_constants import OrchestrationFramework
from scripts.installer.configs.constants.installation_item_keys import (
    KEY_INSTALLATION_ITEM_DOCKER_COMPOSE_INSTALL_METHOD,
    KEY_INSTALLATION_ITEM_DOCKER_INSTALL_METHOD,
    KEY_INSTALLATION_ITEM_INSTALL_DOCKER_IF_MISSING,
    KEY_INSTALLATION_ITEM_TRY_DOCKER_REPOSITORY,
    KEY_INSTALLATION_ITEM_TRY_DOCKER_CONVENIENCE_SCRIPT,
)
from scripts.installer.ui.shared.labels import installation_item_display_label
 
from scripts.installer.ui.shared.store_view_model import build_rows_from_items

if TYPE_CHECKING:
    from scripts.installer.platforms.base import BaseInstaller
    from scripts.installer.core.malcolm_config import MalcolmConfig
    from scripts.installer.core.install_context import InstallContext


class InstallationMenu(BaseMenu):
    """Installation options menu for Malcolm installer."""

    def __init__(
        self,
        platform: "BaseInstaller",
        malcolm_config: "MalcolmConfig",
        install_context: "InstallContext",
        **kwargs
    ):
        """Initialize the installation menu.

        Args:
            platform: The platform-specific installer instance
            malcolm_config: MalcolmConfig instance for accessing configuration
            install_context: Pre-created InstallContext instance to populate
            **kwargs: Additional arguments passed to BaseMenu
        """
        super().__init__(**kwargs)
        self.platform = platform
        self.malcolm_config = malcolm_config
        self.install_context = install_context
        self.displayed_entries = []  # mixed list of config items and tweak toggles

        # Use InstallContext's own items - no separate initialization needed

    def build_menu(self) -> None:
        """Build the installation options menu."""
        self.menu_builder.add_header("Malcolm Installation Options")
        self.menu_builder.add_description(
            "Select an item number to configure, or an action:"
        )

        # Build menu items with grouping via the view model
        all_items = list(self.install_context.items.items())
        rows = build_rows_from_items(all_items, self.install_context)
        # capture runtime for label adjustments
        try:
            runtime_bin = (self.malcolm_config.get_value(KEY_CONFIG_ITEM_RUNTIME_BIN) or "").lower()
        except Exception:
            runtime_bin = ""

        self.displayed_entries = []
        index = 0
        for row in rows:
            if not row.visible:
                continue
            key = row.key
            config_item = self.install_context.items[key]
            current_value = config_item.get_value()
            base_label = config_item.label
            adj_label = installation_item_display_label(key, base_label, runtime_bin)
            index += 1
            # Use tree-style rendering consistent with configuration menu
            self.menu_builder.add_tree_item(row.prefix, index, adj_label, current_value)
            self.displayed_entries.append({"kind": "config", "key": key, "item": config_item})

        self.menu_builder.add_action_section()
        self.menu_builder.add_action("s", "Save and Continue")
        self.menu_builder.add_action("q", "Quit")

    def process_choice(self, choice: str) -> Optional["InstallContext"]:
        """Process the user's menu choice.

        Args:
            choice: The user's input choice

        Returns:
            InstallContext if user saves and continues, None if cancelled
        """
        choice_upper = choice.upper()

        if choice_upper == "Q":
            return None  # User cancelled
        elif choice_upper == "S":
            # Save choices and continue - InstallContext already populated
            return self.install_context
        else:
            # Try to parse as numeric choice
            item_index = self.parse_numeric_choice(choice, len(self.displayed_entries))
            if item_index is not None:
                self._handle_item_selection(item_index)
            else:
                self.handle_invalid_choice(choice)
            return None

    def _handle_item_selection(self, item_index: int) -> None:
        """Handle selection of an installation item.

        Args:
            item_index: The index of the selected item
        """
        entry = self.displayed_entries[item_index]
        key = entry.get("key")
        config_item = entry.get("item")
        new_value = self.prompt_config_item(config_item)
        if new_value is not None:
            self.install_context.set_item_value(key, new_value)

    def handle_cancel(self) -> Optional["InstallContext"]:
        """Handle menu cancellation.

        Returns:
            None to indicate cancellation
        """
        return None
