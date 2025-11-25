#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2025 Battelle Energy Alliance, LLC.  All rights reserved.


"""
Linux-specific installation configuration items for Malcolm installer.

This module contains all configuration items related to the installation process
that are specific to Linux platforms, including Docker installation methods
and Linux-specific system configuration options.
"""
from scripts.installer.core.config_item import ConfigItem, ListOfStringsConfigItem
from scripts.installer.configs.constants.installation_item_keys import (
    KEY_INSTALLATION_ITEM_DOCKER_COMPOSE_INSTALL_METHOD,
    KEY_INSTALLATION_ITEM_DOCKER_EXTRA_USERS,
    KEY_INSTALLATION_ITEM_DOCKER_INSTALL_METHOD,
    KEY_INSTALLATION_ITEM_INSTALL_DOCKER_IF_MISSING,
    KEY_INSTALLATION_ITEM_TRY_DOCKER_CONVENIENCE_SCRIPT,
    KEY_INSTALLATION_ITEM_TRY_DOCKER_REPOSITORY,
)
from scripts.installer.configs.constants.enums import (
    DockerInstallMethod,
    DockerComposeInstallMethod,
)
from scripts.malcolm_constants import WidgetType
from scripts.malcolm_common import GetNonRootMalcolmUserNames

CONFIG_ITEM_DOCKER_INSTALL_METHOD = ConfigItem(
    key=KEY_INSTALLATION_ITEM_DOCKER_INSTALL_METHOD,
    label="Docker Installation Method",
    default_value=DockerInstallMethod.REPOSITORY,
    choices=[x.value for x in DockerInstallMethod],
    validator=lambda x: x in DockerInstallMethod,
    question="Select method for Docker installation (if not already installed)",
    widget_type=WidgetType.SELECT,
    metadata={
        "visible_when_runtime": "docker",
    },
)

CONFIG_ITEM_DOCKER_COMPOSE_INSTALL_METHOD = ConfigItem(
    key=KEY_INSTALLATION_ITEM_DOCKER_COMPOSE_INSTALL_METHOD,
    label="Docker Compose Installation Method",
    default_value=DockerComposeInstallMethod.GITHUB,
    choices=[x.value for x in DockerComposeInstallMethod],
    validator=lambda x: x in DockerComposeInstallMethod,
    question="Select method for Docker Compose installation (if not already installed)",
    widget_type=WidgetType.SELECT,
    metadata={
        "visible_when_runtime": "docker",
    },
)

# Docker installation questions (exactly matching original installer prompts)
CONFIG_ITEM_DOCKER_EXTRA_USERS = ListOfStringsConfigItem(
    key=KEY_INSTALLATION_ITEM_DOCKER_EXTRA_USERS,
    label='Docker Users',
    default_value=GetNonRootMalcolmUserNames(),
    accept_blank=True,
    validator=lambda x: isinstance(x, list) and all(isinstance(user, str) for user in x),
    widget_type=WidgetType.TEXT,
    question="Add non-root users to the 'docker' group during installation (comma separated list, blank for none)",
    metadata={
        "visible_when_runtime": "docker",
    },
)

CONFIG_ITEM_INSTALL_DOCKER_IF_MISSING = ConfigItem(
    key=KEY_INSTALLATION_ITEM_INSTALL_DOCKER_IF_MISSING,
    label="Install Docker if Missing",
    default_value=True,
    validator=lambda x: isinstance(x, bool),
    question="If Docker not detect on system should Malcolm attempt to install Docker?",
    widget_type=WidgetType.CHECKBOX,
    metadata={
        "visible_when_runtime": "docker",
    },
)

CONFIG_ITEM_TRY_DOCKER_REPOSITORY = ConfigItem(
    key=KEY_INSTALLATION_ITEM_TRY_DOCKER_REPOSITORY,
    label="Try Docker Repository Installation",
    default_value=True,
    validator=lambda x: isinstance(x, bool),
    question="Attempt to install Docker using official repositories?",
    widget_type=WidgetType.CHECKBOX,
    metadata={
        "visible_when_runtime": "docker",
    },
)

CONFIG_ITEM_TRY_DOCKER_CONVENIENCE_SCRIPT = ConfigItem(
    key=KEY_INSTALLATION_ITEM_TRY_DOCKER_CONVENIENCE_SCRIPT,
    label="Try Docker Convenience Script",
    default_value=False,
    validator=lambda x: isinstance(x, bool),
    question="Docker not installed via official repositories. Attempt to install Docker via convenience script (please read https://github.com/docker/docker-install)?",
    widget_type=WidgetType.CHECKBOX,
    metadata={
        "visible_when_runtime": "docker",
    },
)


def get_linux_installation_config_item_dict():
    """Get all Linux-specific installation ConfigItem objects from this module.

    Returns:
        Dict mapping configuration key strings to their ConfigItem objects
    """
    config_items = {}
    # Iterate over globals to find all defined ConfigItem objects in this module
    for key_name, key_value in globals().items():
        # Check if this is a ConfigItem object
        if isinstance(key_value, ConfigItem):
            # Store the entire ConfigItem object with its key as the dictionary key
            config_items[key_value.key] = key_value

    # Include shared installation items
    from scripts.installer.configs.installation_items.shared import (
        ALL_SHARED_INSTALLATION_CONFIG_ITEMS_DICT,
    )

    config_items.update(ALL_SHARED_INSTALLATION_CONFIG_ITEMS_DICT)

    return config_items


# A dictionary mapping configuration keys to their ConfigItem objects, created once at module load.
ALL_LINUX_INSTALLATION_CONFIG_ITEMS_DICT = get_linux_installation_config_item_dict()

if __name__ == "__main__":
    print("Linux installation config items:")
    print(list(ALL_LINUX_INSTALLATION_CONFIG_ITEMS_DICT.keys()))
