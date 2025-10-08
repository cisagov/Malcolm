#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Font Manager Component
=====================

Manages font creation and caching for consistent font usage across the application.
"""

import customtkinter
from components.styles import (
    FONT_FAMILY,
    FONT_TITLE,
    FONT_SECTION,
    FONT_NORMAL,
    FONT_BOLD,
)


class FontManager:
    """Manages font creation and caching for consistent font usage."""

    _fonts = {}  # Font cache

    @classmethod
    def get_font(cls, size, weight="normal"):
        """
        Get a font with specified size and weight, using caching.

        Args:
            size: Font size
            weight: Font weight (e.g., "normal", "bold")

        Returns:
            customtkinter.CTkFont: The requested font
        """
        key = f"{size}-{weight}"
        if key not in cls._fonts:
            cls._fonts[key] = customtkinter.CTkFont(
                family=FONT_FAMILY, size=size, weight=weight
            )
        return cls._fonts[key]

    @classmethod
    def title_font(cls):
        """Get the standard title font."""
        return cls.get_font(*FONT_TITLE)

    @classmethod
    def section_font(cls):
        """Get the standard section header font."""
        return cls.get_font(*FONT_SECTION)

    @classmethod
    def normal_font(cls):
        """Get the standard normal font."""
        return cls.get_font(*FONT_NORMAL)

    @classmethod
    def bold_font(cls):
        """Get the standard bold font."""
        return cls.get_font(*FONT_BOLD)

    @classmethod
    def regular_font(cls):
        """Get the standard regular font."""
        return cls.get_font(*FONT_NORMAL)
