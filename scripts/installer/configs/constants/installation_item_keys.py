#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2025 Battelle Energy Alliance, LLC.  All rights reserved.

"""
Installation key constants for Malcolm
"""

# Installation-specific options (not part of runtime Malcolm config)
KEY_INSTALLATION_ITEM_DOCKER_INSTALL_METHOD = "dockerInstallMethod"
KEY_INSTALLATION_ITEM_DOCKER_COMPOSE_INSTALL_METHOD = "dockerComposeInstallMethod"
KEY_INSTALLATION_ITEM_DOCKER_EXTRA_USERS = "dockerExtraUsers"
KEY_INSTALLATION_ITEM_HOMEBREW_USAGE = "homebrewUsage"
KEY_INSTALLATION_ITEM_INSTALLATION_PATH = "installationPath"
KEY_INSTALLATION_ITEM_LOAD_MALCOLM_IMAGES = "loadMalcolmImages"
KEY_INSTALLATION_ITEM_PULL_MALCOLM_IMAGES = "pullMalcolmImages"
KEY_INSTALLATION_ITEM_AUTO_TWEAKS = "autoTweaks"
KEY_INSTALLATION_ITEM_APPLY_MEMORY_SETTINGS = "applyMemorySettings"

# Docker installation questions (Linux)
KEY_INSTALLATION_ITEM_INSTALL_DOCKER_IF_MISSING = "installDockerIfMissing"
KEY_INSTALLATION_ITEM_TRY_DOCKER_REPOSITORY = "tryDockerRepository"
KEY_INSTALLATION_ITEM_TRY_DOCKER_CONVENIENCE_SCRIPT = "tryDockerConvenienceScript"

# macOS installation questions
KEY_INSTALLATION_ITEM_USE_HOMEBREW = "useHomebrew"
KEY_INSTALLATION_ITEM_CONTINUE_WITHOUT_HOMEBREW = "continueWithoutHomebrew"
KEY_INSTALLATION_ITEM_CONFIGURE_DOCKER_RESOURCES = "configureDockerResources"


def get_installation_config_item_keys_dict():
    """Get all installation item constants from this module."""
    constants = {}
    # Iterate over globals to find all defined constants in this module
    for key_name, key_value in globals().items():
        # Ensure that we are only processing string values
        if isinstance(key_value, str):
            # Check if the variable name matches the pattern for config items
            if key_name.startswith("KEY_INSTALLATION_ITEM_"):
                constants[key_value] = key_name
    return constants


# A dictionary representation of all environment keys, created once at module load.
ALL_INSTALLATION_CONFIG_ITEM_KEYS_DICT = get_installation_config_item_keys_dict()


def get_set_of_installation_item_keys():
    return set(ALL_INSTALLATION_CONFIG_ITEM_KEYS_DICT.keys())
