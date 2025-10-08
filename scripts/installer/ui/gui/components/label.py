#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Label Components
==============

Provides standard label components with consistent styling.
"""

import customtkinter
from components.styles import *
from .font_manager import FontManager


class Label:
    """Label components with standard styling."""

    @staticmethod
    def title(frame, text, row):
        """
        Create a centered title label.

        Args:
            frame: The parent frame
            text: The title text
            row: The row number for grid layout

        Returns:
            customtkinter.CTkLabel: The title label
        """
        label = customtkinter.CTkLabel(frame, text=text, font=FontManager.title_font())
        label.grid(row=row, column=0, padx=PADDING_LARGE, pady=TITLE_PADDING)
        return label

    @staticmethod
    def description(frame, text, row):
        """
        Create a centered description label.

        Args:
            frame: The parent frame
            text: The description text
            row: The row number for grid layout

        Returns:
            customtkinter.CTkLabel: The description label
        """
        label = customtkinter.CTkLabel(
            frame,
            text=text,
            font=FontManager.normal_font(),
            wraplength=DEFAULT_WRAPLENGTH,
        )
        label.grid(row=row, column=0, padx=PADDING_LARGE, pady=DESCRIPTION_PADDING)
        return label

    @staticmethod
    def section_header(frame, text, row):
        """
        Create a left-aligned section header.

        Args:
            frame: The parent frame
            text: The section header text
            row: The row number for grid layout

        Returns:
            customtkinter.CTkLabel: The section header label
        """
        label = customtkinter.CTkLabel(
            frame, text=text, font=FontManager.section_font()
        )
        label.grid(
            row=row, column=0, padx=PADDING_LARGE, pady=SECTION_PADDING, sticky="w"
        )
        return label

    @staticmethod
    def section_description(frame, text, row):
        """
        Create a left-aligned section description.

        Args:
            frame: The parent frame
            text: The section description text
            row: The row number for grid layout

        Returns:
            customtkinter.CTkLabel: The section description label
        """
        label = customtkinter.CTkLabel(
            frame, text=text, font=FontManager.normal_font(), justify="left"
        )
        label.grid(
            row=row, column=0, padx=PADDING_LARGE, pady=SECTION_DESC_PADDING, sticky="w"
        )
        return label

    @staticmethod
    def error(parent, text, row=None, column=0):
        """
        Create an error label with red text.

        Args:
            parent: The parent frame/widget
            text: The error text
            row: Optional row number for grid layout
            column: Column number for grid layout (default: 0)

        Returns:
            customtkinter.CTkLabel: The error label
        """
        label = customtkinter.CTkLabel(
            parent,
            text=text,
            font=FontManager.normal_font(),
            text_color=("red", "red"),
            justify="left",
        )

        if row is not None:
            label.grid(
                row=row,
                column=column,
                padx=PADDING_LARGE,
                pady=SECTION_DESC_PADDING,
                sticky="w",
            )

        return label

    @staticmethod
    def success(parent, text, row=None, column=0):
        """
        Create a success label with green text.

        Args:
            parent: The parent frame/widget
            text: The success text
            row: Optional row number for grid layout
            column: Column number for grid layout (default: 0)

        Returns:
            customtkinter.CTkLabel: The success label
        """
        label = customtkinter.CTkLabel(
            parent,
            text=text,
            font=FontManager.normal_font(),
            text_color=("green", "green"),
            justify="left",
        )

        if row is not None:
            label.grid(
                row=row,
                column=column,
                padx=PADDING_LARGE,
                pady=SECTION_DESC_PADDING,
                sticky="w",
            )

        return label

    @staticmethod
    def bold(parent, text, row=None, column=0, sticky="w"):
        """
        Create a bold text label.

        Args:
            parent: The parent frame/widget
            text: The label text
            row: Optional row number for grid layout
            column: Column number for grid layout (default: 0)
            sticky: Grid sticky parameter (default: "w")

        Returns:
            customtkinter.CTkLabel: The bold label
        """
        label = customtkinter.CTkLabel(
            parent, text=text, font=FontManager.bold_font(), justify="left"
        )

        if row is not None:
            label.grid(row=row, column=column, padx=(0, 10), pady=5, sticky=sticky)

        return label

    @staticmethod
    def regular(parent, text, row=None, column=0, sticky="w"):
        """
        Create a regular text label.

        Args:
            parent: The parent frame/widget
            text: The label text
            row: Optional row number for grid layout
            column: Column number for grid layout (default: 0)
            sticky: Grid sticky parameter (default: "w")

        Returns:
            customtkinter.CTkLabel: The regular label
        """
        label = customtkinter.CTkLabel(
            parent, text=text, font=FontManager.regular_font(), justify="left"
        )

        if row is not None:
            label.grid(row=row, column=column, padx=(0, 5), pady=5, sticky=sticky)

        return label
