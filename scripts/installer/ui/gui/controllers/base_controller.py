#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2025 Battelle Energy Alliance, LLC.  All rights reserved.

"""
Base Controller for Malcolm GUI Installer
=======================================

This module provides the base class for all controllers in the Malcolm GUI installer.
"""

import sys
import importlib.util
import os
from scripts.malcolm_common import GetMalcolmDir, GetScriptsDir

from scripts.install import (
    InstallerYesOrNo,
    InstallerAskForString,
    InstallerChooseOne,
    InstallerChooseMultiple,
    InstallerDisplayMessage,
    UserInterfaceMode,
    UserInputDefaultsBehavior,
)


class BaseController:
    """
    Base class for all Controllers in MVC architecture.

    This class serves as the base for all Controller classes, providing
    common functionality for managing the Model and View, handling user
    interactions, and processing business logic.
    """

    def __init__(self, model):
        """
        Initialize with a reference to the model.

        Args:
            model: The MalcolmConfig model instance
        """
        self.model = model
        self.view = None

    def set_view(self, view):
        """
        Set the view this controller will manage.

        Args:
            view: The view instance to manage
        """
        self.view = view
        self.refresh_view()

    def refresh_view(self):
        """
        Refresh the view with current model data.

        This method should be overridden by subclasses to update
        specific view elements with data from the model.
        """
        pass

    def validate(self):
        """
        Validate all settings managed by this controller.

        Returns:
            tuple: (success, error_message)
        """
        # Base implementation just returns success
        # Subclasses should override this
        return True, ""

    def save_settings(self):
        """
        Validate and save all settings to the model.

        This method should be overridden by subclasses to implement
        validation and saving of specific settings.

        Returns:
            tuple: (success, error_message)
        """
        # Base implementation just returns success
        # Subclasses should override this
        return True, ""

    def load_from_model(self):
        """
        Load data from the model and update the view.

        This method should be called when new data is loaded into the model
        from an external source (like a config file).
        """
        self.refresh_view()

    def handle_yes_no(self, question, default=None, model_key=None):
        """
        Handle a Yes/No question consistently across UI modes.

        This method uses the installer's InstallerYesOrNo function when available
        or falls back to direct model access.

        Args:
            question: The question to ask
            default: Default value (True/False)
            model_key: Key to store in model (if None, doesn't store)

        Returns:
            bool: The user's response
        """
        if INSTALL_FUNCTIONS_AVAILABLE:
            # Use the installer's function
            result = InstallerYesOrNo(
                question,
                default=default,
                uiMode=UserInterfaceMode.InteractionDialog,
            )
        else:
            # Fall back to view-specific implementation
            if self.view and hasattr(self.view, "ask_yes_no"):
                result = self.view.ask_yes_no(question, default)
            else:
                # Default behavior if no UI is available
                result = default

        # Store in model if requested
        if model_key is not None:
            self.model.set(model_key, result)

        return result

    def handle_string_input(self, question, default=None, model_key=None):
        """
        Handle string input consistently across UI modes.

        This method uses the installer's InstallerAskForString function when available
        or falls back to direct model access.

        Args:
            question: The question to ask
            default: Default value
            model_key: Key to store in model (if None, doesn't store)

        Returns:
            str: The user's response
        """
        if INSTALL_FUNCTIONS_AVAILABLE:
            # Use the installer's function
            result = InstallerAskForString(
                question,
                default=default,
                uiMode=UserInterfaceMode.InteractionDialog,
            )
        else:
            # Fall back to view-specific implementation
            if self.view and hasattr(self.view, "ask_string"):
                result = self.view.ask_string(question, default)
            else:
                # Default behavior if no UI is available
                result = default

        # Store in model if requested
        if model_key is not None:
            self.model.set(model_key, result)

        return result

    def handle_choice(self, prompt, choices, default=None, model_key=None):
        """
        Handle a multiple-choice question consistently across UI modes.

        This method uses the installer's InstallerChooseOne function when available
        or falls back to direct model access.

        Args:
            prompt: The prompt to display
            choices: List of choices
            default: Default choice index
            model_key: Key to store in model (if None, doesn't store)

        Returns:
            The selected choice value
        """
        if INSTALL_FUNCTIONS_AVAILABLE:
            # Use the installer's function
            result = InstallerChooseOne(
                prompt,
                choices=choices,
                uiMode=UserInterfaceMode.InteractionDialog,
            )
        else:
            # Fall back to view-specific implementation
            if self.view and hasattr(self.view, "ask_choice"):
                result = self.view.ask_choice(prompt, choices, default)
            else:
                # Default behavior if no UI is available
                result = (
                    choices[default]
                    if default is not None and default < len(choices)
                    else None
                )

        # Store in model if requested
        if model_key is not None:
            self.model.set(model_key, result)

        return result
