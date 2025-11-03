#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2025 Battelle Energy Alliance, LLC.  All rights reserved.

"""
Additional configuration options for Malcolm installer
"""


def add_extras_args(parser):
    """
    Add additional configuration options arguments to the parser

    Args:
        parser: ArgumentParser to add arguments to
    """
    extrasArgGroup = parser.add_argument_group("Additional Configuration Options")

    extrasArgGroup.add_argument(
        "--extra",
        dest="extraSettings",
        nargs="*",
        type=str,
        default=[],
        help="Extra environment variables to set (e.g., foobar.env:VARIABLE_NAME=value)",
    )
