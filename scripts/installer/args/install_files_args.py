#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2026 Battelle Energy Alliance, LLC.  All rights reserved.

"""
Installation files arguments for Malcolm installer
"""


def remove_malcolm_file_args(argv):
    """
    Take an array of arguments (e.g., sys.argv[1:]) and remove --malcolm-file/-m,
    --image-file/-i and their corresponding values, if present

    Args:
        parser: ArgumentParser to add arguments to
    """
    cleaned_args = []
    skip_next = False
    for i, arg in enumerate(argv):
        if skip_next:
            skip_next = False
            continue
        if arg in (
            "--malcolm-file",
            "-m",
            "--image-file",
            "-i",
        ):
            skip_next = True
            continue
        if arg.startswith("--malcolm-file=") or arg.startswith("--image-file="):
            continue
        cleaned_args.append(arg)
    return cleaned_args


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
