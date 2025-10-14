#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2025 Battelle Energy Alliance, LLC.  All rights reserved.

"""
Installation configuration items for Malcolm installer.

This module consolidates all installation-specific configuration items
from different platforms (shared, linux, macos, windows) into a single
importable interface.
"""

from .shared import ALL_SHARED_INSTALLATION_CONFIG_ITEMS_DICT
from .linux import ALL_LINUX_INSTALLATION_CONFIG_ITEMS_DICT
from .macos import ALL_MACOS_INSTALLATION_CONFIG_ITEMS_DICT
from .windows import ALL_WINDOWS_INSTALLATION_CONFIG_ITEMS_DICT

# Consolidate all installation config items into a single dictionary
ALL_INSTALLATION_CONFIG_ITEMS_DICT = {}
ALL_INSTALLATION_CONFIG_ITEMS_DICT.update(ALL_SHARED_INSTALLATION_CONFIG_ITEMS_DICT)
ALL_INSTALLATION_CONFIG_ITEMS_DICT.update(ALL_LINUX_INSTALLATION_CONFIG_ITEMS_DICT)
ALL_INSTALLATION_CONFIG_ITEMS_DICT.update(ALL_MACOS_INSTALLATION_CONFIG_ITEMS_DICT)
ALL_INSTALLATION_CONFIG_ITEMS_DICT.update(ALL_WINDOWS_INSTALLATION_CONFIG_ITEMS_DICT)

# Export the consolidated dictionary
__all__ = ["ALL_INSTALLATION_CONFIG_ITEMS_DICT"]
