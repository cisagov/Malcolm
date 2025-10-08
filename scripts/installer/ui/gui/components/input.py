#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Input Components
=============

Provides standard input field components with consistent styling.
"""

import customtkinter
from components.styles import PADDING_SMALL
from .font_manager import FontManager


class Input:
    """Input components with standard styling."""

    @staticmethod
    def field(parent, label_text, placeholder_text="", row=0):
        """
        Create a labeled input field.

        Args:
            parent: The parent widget
            label_text: The label text
            placeholder_text: Placeholder text for the input field
            row: The row number for grid layout

        Returns:
            customtkinter.CTkEntry: The entry field
        """
        label = customtkinter.CTkLabel(
            parent, text=label_text, font=FontManager.bold_font()
        )
        label.grid(
            row=row, column=0, padx=PADDING_SMALL, pady=PADDING_SMALL, sticky="w"
        )

        entry = customtkinter.CTkEntry(parent, placeholder_text=placeholder_text)
        entry.grid(
            row=row, column=1, padx=PADDING_SMALL, pady=PADDING_SMALL, sticky="ew"
        )

        return entry

    @staticmethod
    def password_field(parent, label_text, placeholder_text="", row=0):
        """
        Create a labeled password input field.

        Args:
            parent: The parent widget
            label_text: The label text
            placeholder_text: Placeholder text for the password field
            row: The row number for grid layout

        Returns:
            customtkinter.CTkEntry: The password entry field
        """
        label = customtkinter.CTkLabel(
            parent, text=label_text, font=FontManager.bold_font()
        )
        label.grid(
            row=row, column=0, padx=PADDING_SMALL, pady=PADDING_SMALL, sticky="w"
        )

        entry = customtkinter.CTkEntry(
            parent, placeholder_text=placeholder_text, show="*"
        )  # Hide password characters
        entry.grid(
            row=row, column=1, padx=PADDING_SMALL, pady=PADDING_SMALL, sticky="ew"
        )

        return entry

    @staticmethod
    def checkbox(parent, text, variable, command=None):
        """
        Create a checkbox.

        Args:
            parent: The parent widget
            text: The checkbox label text
            variable: The variable to bind to the checkbox state
            command: Optional callback function

        Returns:
            customtkinter.CTkCheckBox: The checkbox
        """
        return customtkinter.CTkCheckBox(
            parent, text=text, variable=variable, command=command
        )

    @staticmethod
    def radio_group(parent, options, variable, command=None, row=0, column=0):
        """
        Create a group of radio buttons.

        Args:
            parent: Parent widget
            options: List of (value, text) tuples for radio options
            variable: Variable to store the selection
            command: Optional callback function
            row: Starting row number
            column: Column number for the radio group

        Returns:
            list: List of created radio buttons
        """
        radio_buttons = []
        for i, (value, text) in enumerate(options):
            radio = customtkinter.CTkRadioButton(
                parent, text=text, value=value, variable=variable, command=command
            )
            radio.grid(
                row=row + i,
                column=column,
                padx=PADDING_SMALL,
                pady=PADDING_SMALL,
                sticky="w",
            )
            radio_buttons.append(radio)
        return radio_buttons
