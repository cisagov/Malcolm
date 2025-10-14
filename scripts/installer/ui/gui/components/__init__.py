#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2025 Battelle Energy Alliance, LLC.  All rights reserved.

"""
GUI Components Package for Malcolm Installer
============================================

This package provides reusable UI components for the Malcolm installer GUI.
"""

# Standard components
from .font_manager import FontManager
from .frame import Frame
from .label import Label
from .input import Input
from .button import Button
from .labeled_input import LabeledInput

# MVC-oriented components
from .controlled_entry import ControlledEntry
from .controlled_checkbox import ControlledCheckbox
from .disableable_panel import DisableablePanel

# Allow wildcard imports from this package to get all components
__all__ = [
    # Standard components
    "FontManager",
    "Frame",
    "Label",
    "Input",
    "Button",
    "LabeledInput",
    # MVC-oriented components
    "ControlledEntry",
    "ControlledCheckbox",
    "DisableablePanel",
]
