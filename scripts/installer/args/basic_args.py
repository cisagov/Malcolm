#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2025 Battelle Energy Alliance, LLC.  All rights reserved.

"""
Basic ungrouped arguments for Malcolm installer
"""

from scripts.malcolm_utils import str2bool


def add_basic_args(parser):
    """
    Add basic ungrouped arguments to the basicArgGroup

    Args:
        basicArgGroup: ArgumentbasicArgGroup to add arguments to
    """
    basicArgGroup = parser.add_argument_group("Installer Options")

    basicArgGroup.add_argument(
        "--debug",
        "--verbose",
        dest="debug",
        type=str2bool,
        nargs="?",
        metavar="true|false",
        const=True,
        default=False,
        help="Enable debug output including tracebacks and debug utilities",
    )
    basicArgGroup.add_argument(
        "--quiet",
        "--silent",
        action="store_true",
        dest="quiet",
        default=False,
        help="Suppress console logging output during installation",
    )
    # --configure and --dry-run are mutually exclusive
    mutex = basicArgGroup.add_mutually_exclusive_group()
    mutex.add_argument(
        "--configure",
        "-c",
        dest="configOnly",
        type=str2bool,
        metavar="true|false",
        nargs="?",
        const=True,
        default=False,
        help="Only write configuration and ancillary files; skip installation steps",
    )
    mutex.add_argument(
        "--dry-run",
        dest="dryRun",
        action="store_true",
        help="Log planned actions without writing files or making system changes",
    )
    basicArgGroup.add_argument(
        "--log-to-file",
        dest="logToFile",
        metavar="filename",
        nargs="?",
        const="",
        default=None,
        help="Log output to file. If no filename provided, creates timestamped log file.",
    )

    basicArgGroup.add_argument(
        "--skip-splash",
        dest="skipSplash",
        action="store_true",
        default=False,
        help="Skip the splash screen prompt on startup",
    )
