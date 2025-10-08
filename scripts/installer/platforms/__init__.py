#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2025 Battelle Energy Alliance, LLC.  All rights reserved.

"""Platform-specific installer implementations for Malcolm."""

import platform

from scripts.malcolm_constants import OrchestrationFramework
from scripts.malcolm_utils import GetPlatformOSRelease
from scripts.malcolm_utils import get_platform_name

from .base import BaseInstaller
from .linux import LinuxInstaller
from .macos import MacInstaller


def get_platform_installer(
    orchestration_mode: OrchestrationFramework,
    ui,
    debug: bool = False,
    control_flow=None,
) -> BaseInstaller:
    """Determine the current host platform and return the matching installer."""

    platform_name = get_platform_name()

    if platform_name == "linux":
        return LinuxInstaller(orchestration_mode, ui, debug, control_flow=control_flow)
    elif platform_name == "macos":
        return MacInstaller(orchestration_mode, ui, debug, control_flow=control_flow)
    elif platform_name == "windows":
        raise NotImplementedError(
            "Windows installation is not yet supported. Please use Linux or macOS."
        )
    else:
        raise NotImplementedError(f"Platform '{platform_name}' is not supported")


__all__ = [
    "BaseInstaller",
    "LinuxInstaller",
    "MacInstaller",
    "get_platform_installer",
]
