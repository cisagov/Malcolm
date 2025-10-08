#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Controlled Entry Component
=======================

An entry field that is directly tied to a controller for MVC pattern integration.
"""

import customtkinter
from typing import Callable, Optional, Tuple


class ControlledEntry(customtkinter.CTkEntry):
    """
    An entry field that is tied to a controller for MVC integration.

    This component provides automatic data binding between the UI and the controller.
    It handles validation and change notification automatically.
    """

    def __init__(
        self,
        master,
        controller_set_method: Callable[[str], Tuple[bool, str]],
        controller_get_method: Callable[[], str] = None,
        validate_on_focus_out: bool = True,
        placeholder_text: str = "",
        width: int = 200,
        **kwargs
    ):
        """
        Initialize a new controlled entry field.

        Args:
            master: The parent widget
            controller_set_method: Controller method to call when the value changes
                                  Should return (success, message) tuple
            controller_get_method: Controller method to call to get the current value
            validate_on_focus_out: Whether to validate when focus leaves the field
            placeholder_text: Placeholder text for the entry field
            width: Width of the entry field
            **kwargs: Additional arguments to pass to CTkEntry
        """
        super().__init__(
            master, placeholder_text=placeholder_text, width=width, **kwargs
        )

        self._controller_set = controller_set_method
        self._controller_get = controller_get_method
        self._last_valid_value = ""
        self._error_callback = None

        # Register validation events
        if validate_on_focus_out:
            self.bind("<FocusOut>", self._on_focus_out)

        # Initialize the field with the controller's value if provided
        if controller_get_method:
            self.refresh_from_controller()

    def refresh_from_controller(self):
        """Update the entry field with the current value from the controller."""
        if self._controller_get:
            current_value = self._controller_get()
            if current_value != self.get():
                self.delete(0, "end")
                self.insert(0, current_value)
                self._last_valid_value = current_value

    def set_error_callback(self, callback: Callable[[str], None]):
        """
        Set a callback function to be called when validation fails.

        Args:
            callback: A function that takes an error message string
        """
        self._error_callback = callback

    def _on_focus_out(self, event=None):
        """Handle focus out events by validating the entry value."""
        current_value = self.get().strip()
        if current_value != self._last_valid_value:
            success, message = self._controller_set(current_value)
            if not success:
                if self._error_callback:
                    self._error_callback(message)
                # Optionally revert to last valid value
                # self.delete(0, "end")
                # self.insert(0, self._last_valid_value)
            else:
                self._last_valid_value = current_value
