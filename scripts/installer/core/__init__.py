#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2025 Battelle Energy Alliance, LLC.  All rights reserved.

"""Core components for Malcolm installer.

This module contains the central configuration management, dependency system,
and installation context for the Malcolm installer.
"""

from .malcolm_config import MalcolmConfig
from .config_env_mapper import EnvMapper, EnvVariable
from .install_context import InstallContext
from .dependency_manager import DependencyManager
from .dependencies import DEPENDENCY_CONFIG, DependencySpec, VisibilityRule, ValueRule

__all__ = [
    "MalcolmConfig",
    "EnvMapper",
    "EnvVariable",
    "InstallContext",
    "DependencyManager",
    "DEPENDENCY_CONFIG",
    "DependencySpec",
    "VisibilityRule",
    "ValueRule",
]
