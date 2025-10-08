#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2025 Battelle Energy Alliance, LLC.  All rights reserved.

"""
Button Components
==============

Provides standard button components with consistent styling.
"""

import customtkinter
from components.styles import PADDING_LARGE, PADDING_MEDIUM, COLOR_SUCCESS
from .frame import Frame


class Button:
    """Button components with standard styling."""

    @staticmethod
    def create(frame, text, command, width=200):
        """
        Create a standard button.

        Args:
            frame: The parent frame
            text: The button text
            command: The callback function
            width: The button width (default: 200)

        Returns:
            customtkinter.CTkButton: The button widget
        """
        return customtkinter.CTkButton(frame, text=text, command=command, width=width)

    @staticmethod
    def create_save_section(frame, text, command, row=None):
        """
        Create a save button section with status label.

        Args:
            frame: The parent frame
            text: The button text
            command: The callback function
            row: Optional row number for grid layout

        Returns:
            tuple: (button_frame, save_button, status_label)
        """
        button_frame = Frame.create_section(frame)
        if row is not None:
            button_frame.grid(
                row=row, column=0, padx=PADDING_LARGE, pady=PADDING_MEDIUM, sticky="ew"
            )

        save_button = Button.create(button_frame, text=text, command=command)
        save_button.grid(row=0, column=0, padx=PADDING_LARGE, pady=PADDING_MEDIUM)

        status_label = customtkinter.CTkLabel(
            button_frame, text="", text_color=COLOR_SUCCESS
        )

        return button_frame, save_button, status_label
