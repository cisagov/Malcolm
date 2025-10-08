#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2025 Battelle Energy Alliance, LLC.  All rights reserved.

"""Terminal UI implementation for the installer."""

from typing import Optional, TYPE_CHECKING

from scripts.malcolm_common import (
    InstallerYesOrNo,
    InstallerAskForString,
    InstallerAskForPassword,
    InstallerDisplayMessage,
    UserInterfaceMode,
    DialogBackException,
    DialogCanceledException,
)
from scripts.malcolm_utils import clear_screen
from scripts.malcolm_utils import eprint
from scripts.installer.utils.logger_utils import InstallerLogger
from scripts.installer.utils.debug_utils import debug_menu_structure

from scripts.installer.ui.shared.installer_ui import InstallerUI
from scripts.installer.ui.tui.configuration_menu import ConfigurationMenu
from scripts.installer.ui.tui.installation_menu import InstallationMenu

if TYPE_CHECKING:
    from scripts.installer.core.malcolm_config import MalcolmConfig
    from scripts.installer.platforms.base import BaseInstaller
    from scripts.installer.core.install_context import InstallContext


class TUIInstallerUI(InstallerUI):
    """Terminal UI implementation using malcolm_common prompts."""

    def __init__(self, ui_mode: UserInterfaceMode = UserInterfaceMode.InteractionInput):
        """Initialize the TUI interface.

        Args:
            ui_mode: The user interface mode (InteractionInput for TUI, InteractionDialog for DUI)
        """
        super().__init__(ui_mode)

    def ask_yes_no(
        self, message: str, default: bool = True, force_interaction: bool = False
    ) -> bool:
        """Ask the user a yes/no question using the TUI interface.

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

    def ask_string(
        self, prompt: str, default: str = "", force_interaction: bool = False
    ) -> Optional[str]:
        """Ask the user for a string input using the TUI interface.

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

    def ask_password(self, prompt: str, default: str = "") -> Optional[str]:
        """Ask the user for a password using the TUI interface.

        Args:
            prompt: The prompt to show the user
            default: Default value if user just presses enter

        Returns:
            The user's password input, or None if cancelled
        """
        return InstallerAskForPassword(prompt, default=default, uiMode=self.ui_mode)

    def display_message(self, message: str) -> None:
        """Display a message to the user using the TUI interface.

        Args:
            message: The message to display
        """
        InstallerDisplayMessage(message, uiMode=self.ui_mode)

    def display_error(self, message: str) -> None:
        """Display an error message to the user using the shared logger."""
        InstallerLogger.error(message)

    def gather_install_options(
        self,
        platform: "BaseInstaller",
        malcolm_config: "MalcolmConfig",
        install_context: "InstallContext",
    ) -> Optional["InstallContext"]:
        """Gather installation options from the user using TUI hierarchical menu.

        This method presents installation-specific options to the user in the
        same hierarchical menu format as the configuration menu.

        Args:
            platform: The platform-specific installer instance
            malcolm_config: MalcolmConfig instance for accessing configuration
            install_context: Pre-created InstallContext instance to populate

        Returns:
            Updated InstallContext with user's installation choices, or None if cancelled
        """
        installation_menu = InstallationMenu(
            platform, malcolm_config, install_context, ui_mode=self.ui_mode
        )
        return installation_menu.run_menu()

    # Tweaks are first-class install items; no special collection required

    def show_final_configuration_summary(
        self,
        malcolm_config: "MalcolmConfig",
        config_dir: str,
        install_context: "InstallContext",
        is_dry_run: bool = False,
    ) -> bool:
        """Show final configuration summary and get user confirmation to proceed.

        This method presents a TUI-based final configuration summary with all
        the key settings and asks for user confirmation before installation.

        Args:
            malcolm_config: MalcolmConfig instance containing all configuration
            config_dir: Configuration directory path where files will be saved
            install_context: The populated InstallContext with installation choices.

        Returns:
            True if user confirms to proceed with installation, False otherwise
        """
        from scripts.installer.utils.summary_utils import (
            build_configuration_summary_items,
            format_summary_value,
        )

        # Build configuration summary items
        summary_items = build_configuration_summary_items(malcolm_config, config_dir)

        # Remove the MalcolmConfig "Auto System Tweaks" entry since we'll use InstallContext value
        summary_items = [
            item for item in summary_items if item[0] != "Auto System Tweaks"
        ]

        # Artifact handling (tarball/images) is outside the UI path; omit from summary

        # add installation options from the context (keep to simple, high-signal flags)
        summary_items.append(
            ("Auto Apply System Tweaks", "Yes" if install_context.auto_tweaks else "No")
        )
        summary_items.append(
            ("Offline Mode", "Yes" if install_context.offline_mode else "No")
        )
        summary_items.append(
            ("Config Only", "Yes" if install_context.config_only else "No")
        )
        summary_items.append(("Dry Run", "Yes" if is_dry_run else "No"))

        # Clear screen and display the summary using TUI formatting
        clear_screen()

        # Build the entire summary as one cohesive display
        summary_lines = []
        summary_lines.append("=" * 60)
        summary_lines.append(
            "FINAL CONFIGURATION SUMMARY" + (" (DRY RUN)" if is_dry_run else "")
        )
        summary_lines.append("=" * 60)

        for label, value in summary_items:
            display_value = format_summary_value(label, value)
            summary_lines.append(f"{label:<30}: {display_value}")

        summary_lines.append("=" * 60)

        # Display the entire summary as one block
        print("\n".join(summary_lines))

        # Get user confirmation
        prompt = (
            "Proceed with dry-run using the above configuration?"
            if is_dry_run
            else "Proceed with Malcolm installation using the above configuration?"
        )
        return self.ask_yes_no(
            prompt,
            default=False,
            force_interaction=True,
        )

    def run_configuration_menu(
        self,
        malcolm_config,
        install_context,
        main_menu_keys: list[str],
        debug_mode: bool = False,
    ) -> bool:
        """Run the hierarchical configuration menu for Malcolm installer.

        Args:
            malcolm_config: MalcolmConfig instance containing all configuration
            install_context: InstallContext instance for installation decisions
            main_menu_keys: List of main menu configuration keys to display
            debug_mode: Whether to enable debug menu options

        Returns:
            True if user selected to save and continue, False if user cancelled
        """
        config_menu = ConfigurationMenu(
            malcolm_config,
            install_context,
            main_menu_keys,
            debug_mode,
            ui_mode=self.ui_mode,
        )
        result = config_menu.run_menu()
        return result if result is not None else False
