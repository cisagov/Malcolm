#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2025 Battelle Energy Alliance, LLC.  All rights reserved.

"""
DUI (python3-dialog) implementation for installer UI.
"""

from typing import Optional, TYPE_CHECKING

from scripts.malcolm_common import (
    InstallerYesOrNo,
    InstallerAskForString,
    InstallerAskForPassword,
    InstallerDisplayMessage,
    UserInterfaceMode,
)
from scripts.installer.utils.logger_utils import InstallerLogger

from scripts.installer.ui.shared.installer_ui import InstallerUI
from scripts.installer.ui.dui.dialog_configuration_menu import DialogConfigurationMenu
from scripts.installer.ui.dui.dialog_installation_menu import DialogInstallationMenu

if TYPE_CHECKING:
    from scripts.installer.core.malcolm_config import MalcolmConfig
    from scripts.installer.platforms.base import BaseInstaller
    from scripts.installer.core.install_context import InstallContext


class DialogInstallerUI(InstallerUI):
    """Dialog-based User Interface aligned with the TUI hierarchy."""

    def __init__(
        self, ui_mode: UserInterfaceMode = UserInterfaceMode.InteractionDialog
    ):
        super().__init__(ui_mode)

    # primitive prompts are thin wrappers around the shared helpers
    def ask_yes_no(
        self, message: str, default: bool = True, force_interaction: bool = False
    ) -> bool:
        return InstallerYesOrNo(
            message,
            default=default,
            forceInteraction=force_interaction,
            uiMode=self.ui_mode,
        )

    def ask_string(
        self, prompt: str, default: str = "", force_interaction: bool = False
    ) -> Optional[str]:
        return InstallerAskForString(
            prompt,
            default=default,
            forceInteraction=force_interaction,
            uiMode=self.ui_mode,
        )

    def ask_password(self, prompt: str, default: str = "") -> Optional[str]:
        return InstallerAskForPassword(prompt, default=default, uiMode=self.ui_mode)

    def display_message(self, message: str) -> None:
        InstallerDisplayMessage(message, uiMode=self.ui_mode)

    def display_error(self, message: str) -> None:
        InstallerLogger.error(message)

    # configuration phase
    def run_configuration_menu(
        self,
        malcolm_config: "MalcolmConfig",
        install_context: "InstallContext",
        main_menu_keys: list[str],
        debug_mode: bool = False,
    ) -> bool:
        menu = DialogConfigurationMenu(
            malcolm_config,
            install_context,
            main_menu_keys,
            debug_mode,
            ui_mode=self.ui_mode,
        )
        result = menu.run()
        return bool(result)

    # installation phase
    def gather_install_options(
        self,
        platform: "BaseInstaller",
        malcolm_config: "MalcolmConfig",
        install_context: "InstallContext",
    ) -> Optional["InstallContext"]:
        menu = DialogInstallationMenu(
            platform, malcolm_config, install_context, ui_mode=self.ui_mode
        )
        return menu.run()

    def show_final_configuration_summary(
        self,
        malcolm_config: "MalcolmConfig",
        config_dir: str,
        install_context: "InstallContext",
        is_dry_run: bool = False,
    ) -> bool:
        from scripts.installer.utils.summary_utils import (
            build_configuration_summary_items,
            format_summary_value,
        )

        items = build_configuration_summary_items(malcolm_config, config_dir)

        # include config-only and dry-run indicators
        items.append(("Config Only", "Yes" if install_context.config_only else "No"))
        items.append(("Dry Run", "Yes" if is_dry_run else "No"))

        # present a single yes/no dialog that includes the full summary
        lines = [
            "FINAL CONFIGURATION SUMMARY" + (" (DRY RUN)" if is_dry_run else ""),
            "",
        ]
        for label, value in items:
            lines.append(f"{label}: {format_summary_value(label, value)}")
        lines.append("")
        prompt = (
            "Proceed with dry-run using the above configuration?"
            if is_dry_run
            else "Proceed with Malcolm installation using the above configuration?"
        )
        lines.append(prompt)
        return self.ask_yes_no("\n".join(lines), default=False, force_interaction=True)
