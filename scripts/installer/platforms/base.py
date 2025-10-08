#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2025 Battelle Energy Alliance, LLC.  All rights reserved.

"""Base installer class for Malcolm platform-specific installers."""

import abc
import os
import platform
import subprocess
import time
from enum import Enum
from typing import Dict, Tuple, Optional, List, Callable

from scripts.malcolm_constants import OrchestrationFramework
from scripts.malcolm_utils import (
    SYSTEM_INFO,
    flatten,
    get_iterable,
)

from scripts.installer.configs.constants.enums import (
    InstallerResult,
    ControlFlow,
)
from scripts.installer.utils.logger_utils import InstallerLogger
from scripts.installer.utils.logger_utils import SkipReasons


 


class BaseInstaller(abc.ABC):
    """Abstract base class for platform-specific Malcolm installers."""

    def __init__(
        self,
        orchestration_mode: OrchestrationFramework,
        ui,
        debug: bool = False,
        control_flow: ControlFlow | None = None,
    ):
        """Initialize the base installer.

        Args:
            orchestration_mode: Container orchestration framework to use
            ui: User interface implementation for user interactions
            debug: Enable debug output
            config_only: Only generate configuration/ancillary files; skip installation steps
            dry_run: Log intended actions; make no changes (no file writes)
        """
        self.orchestration_mode = orchestration_mode
        self.ui = ui
        self.debug = debug
        # control flow (required for deterministic behavior)
        self.control_flow: ControlFlow = control_flow or ControlFlow.INSTALL
        self.config_only = self.control_flow.is_config_only()
        self.dry_run = self.control_flow.is_dry_run()

        # populate system details from SYSTEM_INFO
        self.platform = SYSTEM_INFO.get("platform", platform.system().lower())
        self.codename = SYSTEM_INFO.get("codename", "")
        self.version = SYSTEM_INFO.get("version", "")
        self.total_memory_gigs = SYSTEM_INFO.get("total_mem_gb", 0.0)
        self.total_cores = SYSTEM_INFO.get("cpu_cores", 0)

        # convenience helpers derived from ControlFlow

    def is_dry_run(self) -> bool:
        return self.control_flow.is_dry_run()

    def is_config_only(self) -> bool:
        return self.control_flow.is_config_only()

    def should_write_files(self) -> bool:
        return self.control_flow.should_write_files()

    def should_run_install_steps(self) -> bool:
        return self.control_flow.should_run_install_steps()

    @abc.abstractmethod
    def install(
        self,
        malcolm_config,
        config_dir: str,
        ctx,
        logger=None,
    ) -> bool:
        """Execute the full installation flow for this platform.

        Platforms implement the complete ordered sequence here, delegating to
        platform-owned methods for OS-specific actions and to shared helpers
        where logic is cross-platform (e.g., config generation and docker ops).

        Must honor ControlFlow: dry-run makes no changes; config-only writes
        files but skips installation; install runs all steps.
        """
        raise NotImplementedError

    @abc.abstractmethod
    def install_docker(self, install_context: "InstallContext") -> bool:
        """Install Docker/container runtime on this platform

        Returns:
            True if successful, False otherwise
        """
        pass

    @abc.abstractmethod
    def install_dependencies(self) -> bool:
        """Install platform-specific dependencies.

        Returns:
            True if successful, False otherwise
        """
        pass

    

    def run_installation(
        self,
        malcolm_config,
        config_dir: str,
        ctx,
        logger=None,
    ) -> bool:
        """Run the installation process for this platform via install()."""
        try:
            return self.install(malcolm_config, config_dir, ctx, logger)
        except Exception as e:
            InstallerLogger.error(f"Installation failed: {e}")
            return False

    def run_process(
        self,
        command: List[str],
        privileged: bool = False,
        stdin: str = None,
        retry: int = 1,
        retry_sleep_sec: int = 5,
        stderr: bool = True,
    ) -> Tuple[int, List[str]]:
        """Run a system process with optional privilege escalation."""
        if privileged and os.geteuid() != 0:
            command = ["sudo"] + command

        retcode = -1
        output = []
        flat_command = list(flatten(get_iterable(command)))

        for i in range(retry + 1):
            try:
                process = subprocess.run(
                    flat_command,
                    input=(
                        (stdin.encode() if isinstance(stdin, str) else stdin)
                        if stdin
                        else None
                    ),
                    capture_output=True,
                    check=False,
                    text=True,
                    errors="ignore",
                )
                retcode = process.returncode
                if process.stdout:
                    output.extend(process.stdout.splitlines())
                if stderr and process.stderr:
                    output.extend(process.stderr.splitlines())
                break
            except FileNotFoundError:
                output = [
                    f"Command {' '.join(flat_command)} not found or unable to execute"
                ]
                retcode = 127
                break
            except Exception as e:
                output = [f"Error executing command {' '.join(flat_command)}: {e}"]
                retcode = 1

            if i < retry:
                InstallerLogger.warning(
                    f"Command failed (attempt {i+1}/{retry+1}). Retrying in {retry_sleep_sec} seconds..."
                )
                time.sleep(retry_sleep_sec)

        if self.debug:
            InstallerLogger.debug(
                f"Command {' '.join(flat_command)} returned {retcode}: {output}"
            )

        return retcode, output

    def run_process_streaming(
        self, command: List[str], privileged: bool = False
    ) -> int:
        """Run a system process with live output streaming (for progress indicators)."""
        if privileged and os.geteuid() != 0:
            command = ["sudo"] + command

        flat_command = list(flatten(get_iterable(command)))

        if self.debug:
            InstallerLogger.debug(
                f"Running streaming command: {' '.join(flat_command)}"
            )

        try:
            result = subprocess.run(flat_command, check=False, text=True)
            return result.returncode
        except FileNotFoundError:
            InstallerLogger.error(f"Command not found: {' '.join(flat_command)}")
            return 127
        except Exception as e:
            InstallerLogger.error(
                f"Error executing command {' '.join(flat_command)}: {e}"
            )
            return 1

    def package_is_installed(self, package_name: str) -> bool:
        """Check if a package is installed."""
        return False

    def install_package(self, packages: List[str]) -> bool:
        """Install packages using platform package manager."""
        return False

    def is_docker_installed(self) -> bool:
        """Return True if Docker CLI and daemon are accessible.

        Default implementation attempts "docker info" and treats a zero
        return code as a working installation. Platforms may override for
        more nuanced checks.
        """
        try:
            err, _ = self.run_process(["docker", "info"], stderr=False)
            return err == 0
        except Exception:
            return False

    def install_docker_compose(self) -> bool:
        """Install docker compose on this platform (optional).

        Platforms that support package-managed compose should override this
        and return True on success. Default returns False.
        """
        return False

    def is_docker_package_installed(self) -> bool:
        return False

    
