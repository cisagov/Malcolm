#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2025 Battelle Energy Alliance, LLC.  All rights reserved.

"""
Environment source selection arguments for the Malcolm installer
"""

import os


def add_environment_args(parser):
    """
    Add configuration files arguments to the parser

    Args:
        parser: ArgumentParser to add arguments to
    """
    environment_arg_group = parser.add_argument_group(
        title="Environment Config Options"
    )

    # environment directories
    environment_arg_group.add_argument(
        "--environment-dir-input",
        required=False,
        dest="configDirInput",
        metavar="<string>",
        type=str,
        default=os.getenv("MALCOLM_CONFIG_DIR", None),
        help="Input directory containing Malcolm's .env and .env.example files",
    )
    environment_arg_group.add_argument(
        "--environment-dir-output",
        "-e",
        required=False,
        dest="configDir",
        metavar="<string>",
        type=str,
        default=os.getenv("MALCOLM_CONFIG_DIR", None),
        help="Target directory for writing Malcolm's .env files",
    )
    environment_arg_group.add_argument(
        "--export-malcolm-config-file",
        "--export-mc-file",
        required=False,
        dest="exportMalcolmConfigFile",
        metavar="<path>",
        type=str,
        nargs="?",
        const="",
        help="Export configuration to JSON/YAML settings file (auto-generates filename if not specified)",
    )

    # exclusive configuration source selection (one of: import file, load existing env, or defaults)
    env_source_exclusive_group = environment_arg_group.add_mutually_exclusive_group()
    env_source_exclusive_group.add_argument(
        "--import-malcolm-config-file",
        "--import-mc-file",
        required=False,
        dest="importMalcolmConfigFile",
        metavar="<path>",
        type=str,
        help="Import configuration from JSON/YAML settings file",
    )
    env_source_exclusive_group.add_argument(
        "--load-existing-env",
        "-l",
        required=False,
        dest="loadExistingEnv",
        metavar="true|false",
        nargs="?",
        const=True,
        default=None,
        help=(
            "Automatically load provided config/ .env files from the input directory when present. "
            "Can be used in conjunction with --environment-dir-input"
        ),
    )
    env_source_exclusive_group.add_argument(
        "--defaults",
        "-d",
        dest="use_defaults",
        action="store_true",
        default=False,
        help="Use built-in default configuration values and skip loading from the config directory",
    )
