#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2025 Battelle Energy Alliance, LLC.  All rights reserved.

"""Configuration menu for TUI installer interface."""

from typing import Optional, Dict, List, TYPE_CHECKING

from scripts.installer.configs.constants.constants import MAIN_MENU_KEYS
from scripts.installer.utils.debug_utils import debug_menu_structure
from scripts.installer.ui.tui.base_menu import BaseMenu
from scripts.installer.ui.shared.menu_builder import ValueFormatter
from scripts.installer.ui.shared.store_view_model import build_rows_from_items
from scripts.installer.ui.shared.search_utils import format_search_results_text

if TYPE_CHECKING:
    from scripts.installer.core.malcolm_config import MalcolmConfig
    from scripts.installer.core.install_context import InstallContext


class ConfigurationMenu(BaseMenu):
    """Hierarchical configuration menu for Malcolm installer."""

    def __init__(
        self,
        malcolm_config: "MalcolmConfig",
        install_context: "InstallContext",
        main_menu_keys: List[str],
        debug_mode: bool = False,
        **kwargs,
    ):
        """Initialize the configuration menu.

        Args:
            malcolm_config: MalcolmConfig instance containing all configuration
            install_context: InstallContext instance for installation decisions
            main_menu_keys: List of main menu configuration keys to display
            debug_mode: Whether to enable debug menu options
            **kwargs: Additional arguments passed to BaseMenu
        """
        super().__init__(**kwargs)
        self.malcolm_config = malcolm_config
        self.install_context = install_context
        self.main_menu_keys = main_menu_keys
        self.debug_mode = debug_mode
        self.displayed_keys: List[str] = []
        self.child_map: Dict[str, List[str]] = {}

        # Build child map from ui_parent relationships
        self._build_child_map()

    def _build_child_map(self) -> None:
        """Build the child map from the items' ui_parent attribute."""
        self.child_map = {}
        all_items = self.malcolm_config.get_all_config_items()

        for key, item in all_items.items():
            if item.ui_parent and item.ui_parent in all_items:
                parent_key = item.ui_parent
                if parent_key not in self.child_map:
                    self.child_map[parent_key] = []
                self.child_map[parent_key].append(key)

    def build_menu(self) -> None:
        """Build the hierarchical configuration menu."""
        self.menu_builder.add_header("Malcolm Configuration Menu")
        self.menu_builder.add_description(
            "Select an item number to configure, or an action:"
        )

        # Render via store view model for consistent ordering and connectors
        self.displayed_keys = []
        all_items = self.malcolm_config.get_all_config_items().items()
        rows = build_rows_from_items(all_items, self.malcolm_config, roots=self.main_menu_keys)
        for row in rows:
            if not row.visible:
                continue
            item = self.malcolm_config.get_item(row.key)
            if not item:
                continue
            value_display = ValueFormatter.format_config_value(item.label, item.get_value())
            item_number = len(self.displayed_keys) + 1
            self.displayed_keys.append(row.key)
            self.menu_builder.add_tree_item(row.prefix, item_number, item.label, value_display)

        self.menu_builder.add_action_section()
        self.menu_builder.add_action("s", "Save and Continue Installation")
        self.menu_builder.add_action("w", "Where Is...? (search for settings)")

        if self.debug_mode:
            self.menu_builder.add_action("d", "Debug menu structure")

        self.menu_builder.add_action("x", "Exit Installer")
        self.menu_builder.add_separator()

    # Legacy recursion retained for reference; view model handles rendering now.

    def process_choice(self, choice: str) -> Optional[bool]:
        """Process the user's menu choice.

        Args:
            choice: The user's input choice

        Returns:
            True if user selected to save and continue, False to exit, None to continue menu
        """
        choice_lower = choice.lower()

        if choice_lower == "x":
            return False  # Exit installer
        elif choice_lower == "s":
            return True  # Save and continue
        elif choice_lower == "w":
            self._handle_search_prompt()
            return None
        elif choice_lower.startswith("where "):
            search_term = choice[6:].strip()
            if search_term:
                self._handle_search(search_term)
            else:
                print("Please provide a search term after 'where'")
            return None
        elif choice_lower.startswith("w "):
            search_term = choice[2:].strip()
            if search_term:
                self._handle_search(search_term)
            else:
                print("Please provide a search term after 'w'")
            return None
        elif choice_lower == "d" and self.debug_mode:
            debug_menu_structure(self.malcolm_config, self.main_menu_keys)
            return None
        else:
            # Try to parse as numeric choice
            item_index = self.parse_numeric_choice(choice, len(self.displayed_keys))
            if item_index is not None:
                self._handle_item_selection(item_index)
            else:
                self.handle_invalid_choice(choice)
            return None

    def _handle_search_prompt(self) -> None:
        """Handle the search prompt action."""
        print("Search for configuration items by name or description")
        search_term = self.ask_string("Enter search term: ", default="")
        if search_term and search_term.strip():
            self._handle_search(search_term.strip())
        else:
            print("No search term provided.")
            self.ask_string("Press Enter to continue...", default="")

    def _handle_search(self, search_term: str) -> None:
        """Handle search functionality.

        Args:
            search_term: The term to search for
        """
        # Use shared formatter so DUI/TUI remain in sync; keep numbers for TUI
        text = format_search_results_text(
            self.malcolm_config,
            search_term,
            self.displayed_keys,
            debug_mode=self.debug_mode,
            include_numbers=True,
        )
        print("\n" + text + "\n")
        self.ask_string("Press Enter to continue...", default="")

    def _handle_item_selection(self, item_index: int) -> None:
        """Handle selection of a configuration item.

        Args:
            item_index: The index of the selected item
        """
        selected_key = self.displayed_keys[item_index]
        item_to_edit = self.malcolm_config.get_item(selected_key)

        while True:
            new_value = self.prompt_config_item(item_to_edit)

            # If user cancelled or entered same value, stop prompting
            if new_value is None or new_value == item_to_edit.get_value():
                break

            try:
                # Attempt to set the new value
                self.malcolm_config.set_value(selected_key, new_value)

                # Check if this item also affects InstallContext (explicit API)
                if item_to_edit.metadata.get("affects_install_context", False):
                    install_context_field = item_to_edit.metadata.get(
                        "install_context_field"
                    )
                    if install_context_field == "docker_extra_users":
                        try:
                            self.install_context.set_docker_extra_users(new_value)
                        except Exception:
                            pass

                break  # Success - exit the edit loop
            except Exception as e:
                # Show validation error and re-prompt
                print(f"Error: {e}")
                self.ask_string("Press Enter to continue...", default="")

    def handle_cancel(self) -> Optional[bool]:
        """Handle menu cancellation.

        Returns:
            False to indicate exit
        """
        return False
