#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Styles for Malcolm GUI Installer
===============================

Constants defining the visual styling for the Malcolm GUI installer.
This module should contain only styling constants - no functionality.
"""

# Font configurations
FONT_FAMILY = "Helvetica"

# Font sizes
FONT_SIZE_TITLE = 20
FONT_SIZE_SECTION = 14
FONT_SIZE_NORMAL = 12

# Padding and spacing
PADDING_LARGE = 20
PADDING_MEDIUM = 10
PADDING_SMALL = 5

# Standard paddings for different elements
TITLE_PADDING = (PADDING_LARGE, PADDING_MEDIUM)  # (20, 10)
DESCRIPTION_PADDING = (0, PADDING_LARGE)  # (0, 20)
SECTION_PADDING = (PADDING_LARGE, PADDING_SMALL)  # (20, 5)
SECTION_DESC_PADDING = (0, PADDING_MEDIUM)  # (0, 10)
FRAME_PADDING = (PADDING_LARGE, PADDING_MEDIUM)  # (20, 10)
ELEMENT_PADDING = (PADDING_MEDIUM, PADDING_MEDIUM)  # (10, 10)

# Text wrapping
DEFAULT_WRAPLENGTH = 400

# Colors
COLOR_SUCCESS = "#2fa572"  # Green for success messages
COLOR_ERROR = "#e74c3c"  # Red for error messages
COLOR_TRANSPARENT = "transparent"

# Font styles - tuples of (size, weight)
FONT_TITLE = (FONT_SIZE_TITLE, "bold")
FONT_SECTION = (FONT_SIZE_SECTION, "bold")
FONT_NORMAL = (FONT_SIZE_NORMAL, "normal")
FONT_BOLD = (FONT_SIZE_NORMAL, "bold")

# Hierarchical indentation for nested UI elements
INDENT_BASE = 0  # Base indentation for top-level elements
INDENT_LEVEL_1 = 50  # First level of indentation
INDENT_LEVEL_2 = 100  # Second level of indentation
INDENT_LEVEL_3 = 150  # Third level of indentation

# Padding for hierarchical UI elements (left, right)
PADDING_HIERARCHY_BASE = (PADDING_MEDIUM, 0)  # Base padding for top-level elements
PADDING_HIERARCHY_LEVEL_1 = (PADDING_LARGE, 0)  # First level padding
PADDING_HIERARCHY_LEVEL_2 = (PADDING_LARGE * 2, 0)  # Second level padding
PADDING_HIERARCHY_LEVEL_3 = (PADDING_LARGE * 3, 0)  # Third level padding
