#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Controlled Checkbox Component
=========================

A checkbox component that is directly tied to a controller for MVC pattern integration.
"""

import customtkinter
from typing import Callable, Optional, Tuple


class ControlledCheckbox(customtkinter.CTkCheckBox):
    """
    A checkbox that is tied to a controller for MVC integration.

    This component provides automatic data binding between the UI and the controller.
    It handles validation and change notification automatically.
    """

    def __init__(
        self,
        master,
        text: str,
        controller_set_method: Callable[[bool], Tuple[bool, str]],
        controller_get_method: Callable[[], bool] = None,
        command: Callable = None,
        **kwargs
    ):
        """
        Initialize a new controlled checkbox.

        Args:
            master: The parent widget
            text: The label text for the checkbox
            controller_set_method: Controller method to call when the value changes
                                  Should return (success, message) tuple
            controller_get_method: Controller method to call to get the current value
            command: External command to call when checkbox is toggled
            **kwargs: Additional arguments to pass to CTkCheckBox
        """
        # Create a variable to track the checkbox state
        self._var = customtkinter.BooleanVar(value=False)

        # Store the external command if provided
        self._external_command = command

        # Store additional command handlers
        self._command_handlers = []

        # Create our internal command function
        def internal_command():
            self._on_toggle()
            # Call external command if provided
            if self._external_command:
                self._external_command()
            # Call any additional command handlers
            for handler in self._command_handlers:
                handler()

        super().__init__(
            master, text=text, variable=self._var, command=internal_command, **kwargs
        )

        self._controller_set = controller_set_method
        self._controller_get = controller_get_method
        self._error_callback = None

        # Initialize the checkbox with the controller's value if provided
        if controller_get_method:
            self.refresh_from_controller()

    def refresh_from_controller(self):
        """Update the checkbox with the current value from the controller."""
        if self._controller_get:
            current_value = self._controller_get()
            if current_value != self._var.get():
                self._var.set(current_value)

    def set_error_callback(self, callback: Callable[[str], None]):
        """
        Set a callback function to be called when validation fails.

        Args:
            callback: A function that takes an error message string
        """
        self._error_callback = callback

    def _on_toggle(self):
        """Handle checkbox toggle events with validation."""
        current_value = self._var.get()
        success, message = self._controller_set(current_value)

        if not success:
            # Revert the change if validation fails
            self._var.set(not current_value)
            if self._error_callback:
                self._error_callback(message)

    def add_command_handler(self, handler: Callable[[], None]):
        """
        Add an additional command handler to be called when the checkbox is toggled.

        Args:
            handler: A function to call when the checkbox state changes
        """
        if handler not in self._command_handlers:
            self._command_handlers.append(handler)
