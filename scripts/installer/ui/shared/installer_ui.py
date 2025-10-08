#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2025 Battelle Energy Alliance, LLC.  All rights reserved.

"""Abstract base class for installer UI implementations."""

import os
from abc import ABC, abstractmethod
from typing import Optional, TYPE_CHECKING

from scripts.malcolm_common import UserInterfaceMode

if TYPE_CHECKING:
    from scripts.installer.core.malcolm_config import MalcolmConfig
    from scripts.installer.platforms.base import BaseInstaller
    from scripts.installer.core.install_context import InstallContext


class InstallerUI(ABC):
    """Abstract base class for installer UI implementations.

    This interface decouples the installer logic from the presentation layer,
    allowing the same installer logic to work with TUI, GUI, or silent interfaces.
    """

    def __init__(self, ui_mode: UserInterfaceMode = UserInterfaceMode.InteractionInput):
        """Initialize the UI interface.

        Args:
            ui_mode: The user interface mode for this implementation
        """
        self.ui_mode = ui_mode

    @abstractmethod
    def ask_yes_no(
        self, message: str, default: bool = True, force_interaction: bool = False
    ) -> bool:
        """Ask the user a yes/no question.

        Args:
            message: The question to ask the user
            default: Default answer if user just presses enter
            force_interaction: Force user interaction even if in non-interactive mode

        Returns:
            True for yes, False for no
        """
        pass

    @abstractmethod
    def ask_string(
        self, prompt: str, default: str = "", force_interaction: bool = False
    ) -> Optional[str]:
        """Ask the user for a string input.

        Args:
            prompt: The prompt to show the user
            default: Default value if user just presses enter
            force_interaction: Force user interaction even if in non-interactive mode

        Returns:
            The user's input string, or None if cancelled
        """
        pass

    @abstractmethod
    def ask_password(self, prompt: str, default: str = "") -> Optional[str]:
        """Ask the user for a password (hidden input).

        Args:
            prompt: The prompt to show the user
            default: Default value if user just presses enter

        Returns:
            The user's password input, or None if cancelled
        """
        pass

    @abstractmethod
    def display_message(self, message: str) -> None:
        """Display a message to the user.

        Args:
            message: The message to display
        """
        pass

    @abstractmethod
    def display_error(self, message: str) -> None:
        """Display an error message to the user.

        Args:
            message: The error message to display
        """
        pass

    @abstractmethod
    def gather_install_options(
        self, platform: "BaseInstaller"
    ) -> Optional["InstallContext"]:
        """Gather platform-specific installation options from the user.

        This method should interact with the user to fill out the installation-
        specific options and return them in an InstallContext object.

        Args:
            platform: The platform-specific installer instance, which provides
                      the questions to be asked.

        Returns:
            An InstallContext object populated with the user's choices, or None
            if the user cancels.
        """
        pass

    @abstractmethod
    def show_final_configuration_summary(
        self,
        malcolm_config: "MalcolmConfig",
        config_dir: str,
        install_context: "InstallContext",
        is_dry_run: bool = False,
    ) -> bool:
        """Show final configuration summary and get user confirmation to proceed.

        This method presents the user with a comprehensive summary of their
        configuration choices and installation parameters, then asks for
        confirmation to proceed with the installation.

        Args:
            malcolm_config: MalcolmConfig instance containing all configuration
            config_dir: Configuration directory path where files will be saved
            install_context: The populated InstallContext with installation choices.
            is_dry_run: When True, display summary as a dry-run and adjust prompt wording.

        Returns:
            True if user confirms to proceed with installation, False otherwise
        """
        pass

    def validate_configuration_directory(self, config_dir: str) -> Optional[str]:
        """Validate configuration directory and get user confirmation for overwrites.

        This method handles UI concerns for config directory setup:
        1. Config directory validation and creation prompts
        2. Overwrite confirmation for existing .env files

        Note: Actual .env file generation is handled by the filesystem installation step.

        Args:
            config_dir: Configuration directory path where files will be saved

        Returns:
            The validated config directory path, or None if user cancels
        """
        # Validate and create config directory if needed
        validated_dir = self._validate_config_directory(config_dir)
        if not validated_dir:
            return None

        # Check for existing .env files and get user confirmation
        if not self._confirm_overwrite_existing_config(validated_dir):
            return None

        return validated_dir

    def _validate_config_directory(self, config_dir: str) -> Optional[str]:
        """Validate and potentially create the config directory.

        Args:
            config_dir: The initial config directory path

        Returns:
            The validated config directory path, or None if cancelled
        """
        current_dir = config_dir

        while True:
            # Check if directory exists and is writable
            if not os.path.exists(current_dir) or not os.access(current_dir, os.W_OK):
                self.display_message(
                    f"Provided configuration directory {current_dir} does not exist."
                )

                # Ask if user wants to create it
                if self.ask_yes_no("Would you like to create it?", default=True):
                    try:
                        os.makedirs(current_dir)
                        return current_dir
                    except Exception as e:
                        self.display_error(
                            f"Failed to create configuration directory {current_dir}: {e}"
                        )
                        return None
                else:
                    # Ask for new directory
                    new_dir = self.ask_string(
                        "Enter new config directory: ", default=current_dir
                    )
                    if new_dir:
                        current_dir = new_dir
                    else:
                        self.display_message(
                            "No config directory provided. Cancelling."
                        )
                        return None
            else:
                return current_dir

    def _confirm_overwrite_existing_config(self, config_dir: str) -> bool:
        """Check for existing .env files and get user confirmation to overwrite.

        Args:
            config_dir: The config directory to check

        Returns:
            True if user confirms overwrite or no existing files, False if cancelled
        """
        try:
            # Check if there are any .env files that are not .example files
            existing_env_files = [
                f
                for f in os.listdir(config_dir)
                if f.endswith(".env") and not f.endswith(".example")
            ]

            if existing_env_files:
                if not self.ask_yes_no(
                    f"This will overwrite the existing configuration in {config_dir}. Are you sure you want to proceed?"
                ):
                    # Ask for new directory
                    new_dir = self.ask_string(
                        "Enter new config directory: ", default=config_dir
                    )
                    if new_dir:
                        return self._confirm_overwrite_existing_config(new_dir)
                    else:
                        self.display_message(
                            "No new config directory provided. Cancelling."
                        )
                        return False

            return True
        except OSError:
            # Directory doesn't exist or can't be read, that's fine
            return True
