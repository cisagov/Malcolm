#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2025 Battelle Energy Alliance, LLC.  All rights reserved.

"""
Presentation arguments for the Malcolm installer.

Defines interface mode flags (TUI/DUI/GUI) and non-interactive mode.
"""


def add_presentation_args(parser):
    """
    Add GUI arguments to the parser

    Args:
        parser: ArgumentParser to add arguments to
    """

    # Keep UI mode arguments here as they are fundamental to installer operation
    mode_group = parser.add_argument_group(title="Interface Mode (mutually exclusive)")

    # Add debug UI flag
    # mode_group.add_argument(
    #     '--debug-ui',
    #     action='store_true',
    #     dest='debug_ui',
    #     help='Enable UI debug mode with additional menu options for analyzing menu structure'
    # )

    # Add UI mode arguments
    mode_exclusive_group = mode_group.add_mutually_exclusive_group()
    mode_exclusive_group.add_argument(
        "--tui",
        action="store_true",
        help="Run in command-line text-based interface mode (default)",
    )
    mode_exclusive_group.add_argument(
        "--dui",
        action="store_true",
        help="Run in python dialogs text-based user interface mode (if available - requires python dialogs)",
    )
    mode_exclusive_group.add_argument(
        "--gui",
        action="store_true",
        help="Run in graphical user interface mode (if available - requires customtkinter)",
    )
    mode_exclusive_group.add_argument(
        "--non-interactive",
        dest="non_interactive",
        action="store_true",
        default=False,
        help="Run in non-interactive mode for unattended installations (suppresses all user prompts)",
    )
