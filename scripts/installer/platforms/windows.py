#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2025 Battelle Energy Alliance, LLC.  All rights reserved.

"""Windows-specific installer implementation for Malcolm."""

from scripts.malcolm_common import (
    OrchestrationFramework,
)

from .base import BaseInstaller


class WindowsInstaller(BaseInstaller):
    """Windows-specific Malcolm installer implementation."""

    def __init__(
        self,
        orchestration_mode: OrchestrationFramework,
        ui,
        debug: bool = False,
        control_flow=None,
    ):
        """Initialize the Windows installer."""
        super().__init__(orchestration_mode, ui, debug, control_flow)

    def install_docker(self, install_context):
        """Windows installer does not automate Docker installation in tests."""
        # Keep behavior minimal for mocks: signal not implemented/handled here
        return False

    def install_dependencies(self) -> bool:
        """Windows dependency installation is not implemented in mocks."""
        return False

    def install(
        self,
        malcolm_config,
        config_dir: str,
        ctx,
        logger=None,
    ) -> bool:
        """Windows is not supported: provide a clear message and return False."""
        from scripts.installer.utils.logger_utils import InstallerLogger

        InstallerLogger.error(
            "Windows is not supported by the Malcolm installer. Please use Linux or macOS."
        )
        return False
