#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2025 Battelle Energy Alliance, LLC.  All rights reserved.

"""Base menu class for TUI installer interface."""

from abc import ABC, abstractmethod
from typing import Optional, Any, Dict, List
from scripts.malcolm_common import (
    InstallerYesOrNo,
    InstallerAskForString,
    UserInterfaceMode,
    DialogBackException,
    DialogCanceledException,
)
from scripts.malcolm_utils import clear_screen
from ..shared.menu_builder import MenuBuilder
from ..shared.prompt_utils import prompt_config_item_value


class BaseMenu(ABC):
    """Base class for TUI menus that use InstallerAsk* functions for input."""

    def __init__(self, ui_mode: UserInterfaceMode = UserInterfaceMode.InteractionInput):
        """Initialize the base menu.

        Args:
            ui_mode: The user interface mode for InstallerAsk* functions
        """
        self.ui_mode = ui_mode
        self.menu_builder = MenuBuilder()

    def ask_string(
        self, prompt: str, default: str = "", force_interaction: bool = False
    ) -> Optional[str]:
        """Ask the user for a string input using InstallerAskForString.

        Args:
            prompt: The prompt to show the user
            default: Default value if user just presses enter
            force_interaction: Force user interaction even if in non-interactive mode

        Returns:
            The user's input string, or None if cancelled
        """
        return InstallerAskForString(
            prompt,
            default=default,
            forceInteraction=force_interaction,
            uiMode=self.ui_mode,
        )

    def ask_yes_no(
        self, message: str, default: bool = True, force_interaction: bool = False
    ) -> bool:
        """Ask the user a yes/no question using InstallerYesOrNo.

        Args:
            message: The question to ask the user
            default: Default answer if user just presses enter
            force_interaction: Force user interaction even if in non-interactive mode

        Returns:
            True for yes, False for no
        """
        return InstallerYesOrNo(
            message,
            default=default,
            forceInteraction=force_interaction,
            uiMode=self.ui_mode,
        )

    def prompt_config_item(self, config_item, show_preamble: bool = True):
        """Prompt for ConfigItem value using proper UI abstraction methods.

        This centralizes ConfigItem prompting logic for all menu types,
        using the UI abstraction layer methods (ask_string, ask_yes_no, etc.)
        instead of bypassing to raw InstallerAsk* functions.

        Args:
            config_item: The ConfigItem instance to prompt for
            show_preamble: Whether to show current value and help text

        Returns:
            The new value from the user, or None if cancelled
        """

        # Delegate to shared helper for consistency across TUI/DUI
        return prompt_config_item_value(
            ui_mode=self.ui_mode,
            config_item=config_item,
            back_label=None,
            show_preamble=show_preamble,
        )

    def run_menu(self) -> Any:
        """Run the menu loop and return the result.

        Returns:
            The menu result (varies by implementation)
        """
        try:
            while True:
                clear_screen()
                self.menu_builder.clear()

                # Build the menu content
                self.build_menu()

                # Display the menu
                self.menu_builder.display()

                # Get user choice
                choice = self.get_user_choice()

                # Process the choice
                result = self.process_choice(choice)

                # Check if we should exit the menu
                if result is not None:
                    return result

        except KeyboardInterrupt:
            return self.handle_cancel()
        except (DialogBackException, DialogCanceledException):
            return self.handle_cancel()

    @abstractmethod
    def build_menu(self) -> None:
        """Build the menu content using the menu builder.

        This method should populate self.menu_builder with the appropriate
        menu items, actions, and formatting.
        """
        pass

    @abstractmethod
    def process_choice(self, choice: str) -> Any:
        """Process the user's menu choice.

        Args:
            choice: The user's input choice

        Returns:
            The result of processing the choice, or None to continue the menu loop
        """
        pass

    def get_user_choice(self) -> str:
        """Get the user's menu choice.

        Returns:
            The user's input choice as a string
        """
        choice = self.ask_string("Enter item number or action: ", default="")
        return choice.strip() if choice else ""

    def handle_cancel(self) -> Any:
        """Handle menu cancellation.

        Returns:
            The result to return when the menu is cancelled
        """
        return None

    def handle_invalid_choice(self, choice: str) -> None:
        """Handle invalid menu choices.

        Args:
            choice: The invalid choice
        """
        print(f"Invalid input: {choice}")
        self.ask_string("Press Enter to continue...", default="")

    def parse_numeric_choice(self, choice: str, max_items: int) -> Optional[int]:
        """Parse a numeric choice and validate it.

        Args:
            choice: The user's input choice
            max_items: Maximum number of valid items

        Returns:
            The parsed item index (0-based), or None if invalid
        """
        try:
            item_index = int(choice) - 1
            if 0 <= item_index < max_items:
                return item_index
            else:
                print(f"Invalid item number: {choice}")
                self.ask_string("Press Enter to continue...", default="")
                return None
        except ValueError:
            return None


class MenuAction:
    """Represents a menu action with key and description."""

    def __init__(self, key: str, description: str):
        """Initialize the menu action.

        Args:
            key: The action key/letter
            description: The action description
        """
        self.key = key
        self.description = description


class MenuItem:
    """Represents a menu item with label and current value."""

    def __init__(self, key: str, label: str, value: Any, help_text: str = None):
        """Initialize the menu item.

        Args:
            key: The item key/identifier
            label: The item label
            value: The current value
            help_text: Optional help text
        """
        self.key = key
        self.label = label
        self.value = value
        self.help_text = help_text
