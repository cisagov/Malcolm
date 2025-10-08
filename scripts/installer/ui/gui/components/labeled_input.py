#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Labeled Input Components
=====================

Provides consistently styled label-input field pairs.
"""

import customtkinter
from components.styles import PADDING_LARGE, PADDING_SMALL
from .font_manager import FontManager
from .frame import Frame


class LabeledInput:
    """Component for creating consistently styled label-input field pairs."""

    @staticmethod
    def create(parent, label_text, placeholder="", width=80, row=None, column=0):
        """
        Create a label-input field pair with consistent styling.

        Args:
            parent: The parent frame/widget
            label_text: Text for the label
            placeholder: Placeholder text for the input field
            width: Width of the input field (default: 80)
            row: Row number for grid layout (optional)
            column: Column number for grid layout (default: 0)

        Returns:
            tuple: (frame, entry_widget) - The container frame and the entry widget
        """
        # Create container frame
        container = Frame.create_section(parent)
        container.grid_columnconfigure(0, weight=0)  # Don't expand label column
        container.grid_columnconfigure(1, weight=1)  # Let input column expand

        if row is not None:
            container.grid(
                row=row,
                column=column,
                sticky="ew",
                padx=PADDING_LARGE,
                pady=(0, PADDING_SMALL),
            )

        # Create label
        label = customtkinter.CTkLabel(
            container, text=label_text, font=FontManager.bold_font()
        )
        label.grid(row=0, column=0, padx=(0, 5), pady=0, sticky="w")

        # Create entry field
        entry = customtkinter.CTkEntry(
            container, placeholder_text=placeholder, width=width
        )
        entry.grid(row=0, column=1, padx=0, pady=0, sticky="w")

        return container, entry

    @staticmethod
    def create_with_units(
        parent, label_text, units_text, placeholder="", width=80, row=None, column=0
    ):
        """
        Create a label-input field pair with units label.

        Args:
            parent: The parent frame/widget
            label_text: Text for the label
            units_text: Text for the units label (e.g., "GB", "MB/s")
            placeholder: Placeholder text for the input field
            width: Width of the input field (default: 80)
            row: Row number for grid layout (optional)
            column: Column number for grid layout (default: 0)

        Returns:
            tuple: (frame, entry_widget) - The container frame and the entry widget
        """
        container, entry = LabeledInput.create(
            parent, label_text, placeholder, width, row, column
        )

        # Add units label
        units_label = customtkinter.CTkLabel(
            container, text=units_text, font=FontManager.regular_font()
        )
        units_label.grid(row=0, column=2, padx=(5, 0), pady=0, sticky="w")

        return container, entry
