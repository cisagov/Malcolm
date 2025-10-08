#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2025 Battelle Energy Alliance, LLC.  All rights reserved.

"""
Authentication Controller for Malcolm GUI Installer
================================================

This module provides the controller for authentication settings in the Malcolm GUI installer.
"""

import os
import sys
from typing import Optional, Tuple, Any

from .base_controller import BaseController
from scripts.malcolm_common import GetMalcolmDir

from configs import MalcolmConfig


class AuthController(BaseController):
    """
    Controller for managing Malcolm authentication settings.

    This controller handles all operations related to authentication configuration,
    including authentication method, HTTPS settings, and reverse proxy settings.
    """

    def __init__(self, config: MalcolmConfig):
        """
        Initialize with a reference to the central config model

        Args:
            config: The central MalcolmConfig instance
        """
        super().__init__(config)
        self.model = AuthModel(config)
        self.view = None

    def set_view(self, view):
        """
        Set the view this controller will manage

        Args:
            view: The view instance
        """
        self.view = view
        self.refresh_view()

    def refresh_view(self):
        """
        Update the view with current model data.
        """
        if not self.view:
            return

        # Update view with current model values
        self.view.update_auth_method(self.model.auth_method)
        self.view.update_use_https(self.model.use_https)
        self.view.update_behind_reverse_proxy(self.model.behind_reverse_proxy)

    def set_auth_method(self, method: str) -> Tuple[bool, str]:
        """
        Set the authentication method

        Args:
            method: The authentication method ('basic', 'ldap', or 'none')

        Returns:
            tuple: (success, error_message)
        """
        if not method:
            return False, "Authentication method cannot be empty"

        if method not in self.model.AUTH_METHODS.keys():
            return (
                False,
                f"Invalid authentication method. Must be one of: {', '.join(self.model.AUTH_METHODS.keys())}",
            )

        # Try to set the method in the model
        if not self.model.auth_method == method:
            # Set the auth method
            self.model.auth_method = method
            if self.model.auth_method != method:
                return False, "Failed to set authentication method"

        return True, ""

    def set_use_https(self, value: bool) -> Tuple[bool, str]:
        """
        Set whether HTTPS connections are required

        Args:
            value: True to require HTTPS, False otherwise

        Returns:
            tuple: (success, error_message)
        """
        # Try to set the value in the model
        self.model.use_https = value
        if self.model.use_https != value:
            return False, "Failed to set HTTPS requirement"

        return True, ""

    def set_behind_reverse_proxy(self, value: bool) -> Tuple[bool, str]:
        """
        Set whether Malcolm is running behind a reverse proxy

        Args:
            value: True if behind a reverse proxy, False otherwise

        Returns:
            tuple: (success, error_message)
        """
        # Try to set the value in the model
        self.model.behind_reverse_proxy = value
        if self.model.behind_reverse_proxy != value:
            return False, "Failed to set reverse proxy setting"

        return True, ""

    def validate(self) -> Tuple[bool, str]:
        """
        Validate authentication settings

        Returns:
            tuple: (success, error_message)
        """
        return self.model.validate()

    def save_settings(self) -> Tuple[bool, str]:
        """
        Validate and save all settings to the model.

        Returns:
            tuple: (success, error_message)
        """
        # Validate settings first
        valid, error_message = self.validate()
        if not valid:
            return False, error_message

        # All settings are already in the model through properties
        return True, "Authentication settings saved successfully"
