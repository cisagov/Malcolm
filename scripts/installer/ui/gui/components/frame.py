#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Frame Components
===============

Provides standard frame components with consistent styling.
"""

import customtkinter


class Frame:
    """Frame components with standard styling."""

    @staticmethod
    def create(parent):
        """
        Create a standard frame that can be used for general purpose containers.

        Args:
            parent: The parent widget

        Returns:
            customtkinter.CTkFrame: A frame for general content
        """
        frame = customtkinter.CTkFrame(parent)

        # Configure the frame's grid to expand horizontally
        frame.grid_columnconfigure(0, weight=1)

        return frame

    @staticmethod
    def create_tab(parent):
        """
        Create a standard scrollable frame for a tab that fills the available space.

        Args:
            parent: The parent widget

        Returns:
            customtkinter.CTkScrollableFrame: A scrollable frame for tab content
        """
        # Create the main scrollable frame
        frame = customtkinter.CTkScrollableFrame(parent)

        # Configure the frame to fill the entire parent space
        frame.pack(fill="both", expand=True, padx=10, pady=10)

        # Configure grid weights for the frame
        frame.grid_columnconfigure(0, weight=1)

        return frame

    @staticmethod
    def create_section(parent):
        """
        Create a standard frame for a section that expands horizontally.

        Args:
            parent: The parent widget

        Returns:
            customtkinter.CTkFrame: A frame for section content
        """
        frame = customtkinter.CTkFrame(parent)

        # Configure the frame's grid to expand horizontally
        frame.grid_columnconfigure(0, weight=1)

        return frame
