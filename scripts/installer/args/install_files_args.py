#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2025 Battelle Energy Alliance, LLC.  All rights reserved.

"""
Installation files arguments for Malcolm installer
"""


def add_install_files_args(parser):
    """
    Add installation files arguments to the parser

    Args:
        parser: ArgumentParser to add arguments to
    """
    installFilesArgGroup = parser.add_argument_group("Installation Files")

    installFilesArgGroup.add_argument(
        "--malcolm-file",
        "-m",
        required=False,
        dest="mfile",
        metavar="<string>",
        type=str,
        default="",
        help="Malcolm .tar.gz file for installation",
    )
    installFilesArgGroup.add_argument(
        "--image-file",
        "-i",
        required=False,
        dest="ifile",
        metavar="<string>",
        type=str,
        default="",
        help="Malcolm container images .tar.xz file for installation",
    )
