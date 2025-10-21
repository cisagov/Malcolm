#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2025 Battelle Energy Alliance, LLC.  All rights reserved.

"""macOS-specific installer implementation for Malcolm."""

import os
from typing import List, Optional

from scripts.malcolm_constants import OrchestrationFramework

# no direct UI imports needed here

from scripts.installer.core.install_context import InstallContext
from scripts.installer.utils.logger_utils import InstallerLogger
from scripts.installer.configs.constants.configuration_item_keys import KEY_CONFIG_ITEM_RUNTIME_BIN

from .base import BaseInstaller


class MacInstaller(BaseInstaller):
    """macOS-specific Malcolm installer implementation."""

    def __init__(
        self,
        orchestration_mode: OrchestrationFramework,
        ui,
        debug: bool = False,
        control_flow=None,
    ):
        """Initialize the macOS installer."""
        super().__init__(orchestration_mode, ui, debug, control_flow)

        self.use_brew = False

    def setup_homebrew(self, install_context: InstallContext):
        """Setup Homebrew package manager for macOS using InstallContext decisions."""
        # First see if brew is already installed and runnable
        if install_context.use_homebrew:
            err, out = self.run_process(["brew", "info"])
            self.use_brew = err == 0
        else:
            self.use_brew = False

    def _get_required_dependencies(self) -> List[str]:
        """Get the list of required dependencies for macOS."""
        # afaik, htpassd, make, openssl, and xz are all included on MacOS
        return []

    def install_dependencies(self) -> bool:
        """Install macOS-specific dependencies."""
        if not self.use_brew:
            InstallerLogger.warning("Homebrew not available, cannot install dependencies automatically")
            return False

        return self.install_package(self._get_required_dependencies())

    def package_is_installed(self, package_name: str) -> bool:
        """Check if a package is installed on macOS."""
        if not self.use_brew:
            return False

        # Check with brew
        err, out = self.run_process(["brew", "list", package_name])
        if err == 0:
            return True

        # Check with brew cask
        err, out = self.run_process(["brew", "list", "--cask", package_name])
        return err == 0

    def is_docker_package_installed(self, runtime_bin: Optional[str] = "docker") -> bool:
        """Check if Docker package is installed via Homebrew."""
        if not self.use_brew:
            return False
        return self.package_is_installed(runtime_bin)

    def is_docker_compose_package_installed(self, runtime_bin: Optional[str] = "docker") -> bool:
        """Check if compose package is installed via Homebrew."""
        if not self.use_brew:
            return False
        return self.package_is_installed(f"{runtime_bin}-compose")

    def install_package(self, packages: List[str]) -> bool:
        """Install packages using Homebrew.

        When Homebrew is not explicitly enabled (use_brew=False), attempt best-effort
        installs using brew commands directly. This supports test mocks and environments
        where brew is available without a prior setup stage.
        """
        if self.config_only or self.dry_run:
            if self.dry_run:
                InstallerLogger.info(f"Dry run: would install packages via brew: {packages}")
            return True

        if not self.use_brew:
            return False

        success = True
        for package in packages:
            # Try regular brew install first
            err, out = self.run_process(["brew", "install", package])
            if err != 0:
                # Try cask install as fallback
                err, out = self.run_process(["brew", "install", "--cask", package])
                if err != 0:
                    InstallerLogger.error(f"Failed to install package {package}: {out}")
                    success = False
                else:
                    if self.debug:
                        InstallerLogger.info(f"Successfully installed {package} via brew cask")
            else:
                if self.debug:
                    InstallerLogger.info(f"Successfully installed {package} via brew")

        return success

    def install_docker(self, install_context: InstallContext, runtime_bin: Optional[str] = "docker") -> bool:
        """Install Docker on macOS using InstallContext decisions.

        Note: This method assumes Docker is NOT already installed - the caller
        (docker_install.py step) should check for existing installation first.
        """
        import requests
        import tempfile

        # macOS Docker constants from original installer
        MAC_BREW_DOCKER_PACKAGE = runtime_bin
        MAC_BREW_DOCKER_COMPOSE_PACKAGE = f"{runtime_bin}-compose"
        MAC_BREW_DOCKER_SETTINGS = (
            "/Users/{}/Library/Group Containers/group.com.docker/settings.json" if runtime_bin == "docker" else None
        )

        result = False
        script_user = os.environ.get("USER", os.environ.get("LOGNAME", ""))

        if self.orchestration_mode == OrchestrationFramework.DOCKER_COMPOSE:
            if self.config_only:
                InstallerLogger.info(
                    f"Dry run: would install/start {runtime_bin} if missing and configure resources if enabled"
                )
                return True

            # see if docker is running
            result = self.is_docker_installed(runtime_bin=runtime_bin)

            # Check if Docker is installed via brew but not running
            if self.is_docker_package_installed(runtime_bin):
                if not result:
                    InstallerLogger.warning(
                        f"{runtime_bin} is installed but not running. Please start {runtime_bin}... "
                    )

            elif install_context.install_docker_if_missing:
                if self.use_brew:
                    # Install docker via brew
                    docker_packages = [
                        MAC_BREW_DOCKER_PACKAGE,
                        MAC_BREW_DOCKER_COMPOSE_PACKAGE,
                    ]
                    InstallerLogger.info(f"Installing {runtime_bin} packages: {docker_packages}")
                    if self.install_package(docker_packages):
                        InstallerLogger.info(
                            f"Installation of {runtime_bin} apparently succeeded. Please start {runtime_bin}..."
                        )
                    else:
                        InstallerLogger.error(f"Installation of {runtime_bin} packages failed")

                elif runtime_bin == "docker":
                    # Install docker via downloaded dmg file
                    dl_dir_name = f"/Users/{script_user}/Downloads"
                    if os.path.isdir(dl_dir_name):
                        temp_filename = os.path.join(dl_dir_name, "Docker.dmg")
                    else:
                        with tempfile.NamedTemporaryFile(suffix=".dmg", delete=False) as temp_file:
                            temp_filename = temp_file.name

                    docker_dmg_url = f"https://desktop.docker.com/mac/main/{image_architecture}/Docker.dmg"
                    if (
                        DownloadToFile(docker_dmg_url, temp_filename)
                        and os.path.isfile(temp_filename)
                        and os.path.getsize(temp_filename) > 0
                    ):
                        InstallerLogger.info(f"Install {temp_filename} and start {runtime_bin}...")
                    else:
                        InstallerLogger.error(f"Failed to download {docker_dmg_url} to {temp_filename}")

                # At this point we either have installed docker successfully or we have to give up
                result = self.is_docker_installed(retry=12, retry_sleep_sec=5, runtime_bin=runtime_bin)

            else:
                # No Docker found and user chose not to install
                if runtime_bin.startswith("docker"):
                    raise Exception(
                        f"install.py requires {runtime_bin}, please see https://docs.docker.com/desktop/install/mac/"
                    )
                else:
                    raise Exception(f"install.py requires {runtime_bin}, please consult your platform's documentation")

            if result and MAC_BREW_DOCKER_SETTINGS:
                settings_file = MAC_BREW_DOCKER_SETTINGS.format(script_user)
                if os.path.isfile(settings_file) and install_context.configure_docker_resources:
                    # Tweak CPU/RAM usage for Docker in Mac based on InstallContext decision
                    self._configure_docker_resources(settings_file)

        return result

    def _configure_docker_resources(self, settings_file: str):
        """Configure Docker Desktop resource allocation."""
        import json

        # Adjust CPU and RAM based on system resources (logic from original installer)
        if self.total_cores >= 16:
            new_cpus = 12
        elif self.total_cores >= 12:
            new_cpus = 8
        elif self.total_cores >= 8:
            new_cpus = 6
        elif self.total_cores >= 4:
            new_cpus = 4
        else:
            new_cpus = 2

        if self.total_memory_gigs >= 64.0:
            new_memory_gib = 32
        elif self.total_memory_gigs >= 32.0:
            new_memory_gib = 24
        elif self.total_memory_gigs >= 24.0:
            new_memory_gib = 16
        elif self.total_memory_gigs >= 16.0:
            new_memory_gib = 12
        elif self.total_memory_gigs >= 8.0:
            new_memory_gib = 8
        elif self.total_memory_gigs >= 4.0:
            new_memory_gib = 4
        else:
            new_memory_gib = 2

        try:
            with open(settings_file, "r") as f:
                settings = json.load(f)

            # Update Docker settings
            settings["cpus"] = new_cpus
            settings["memoryMiB"] = new_memory_gib * 1024

            with open(settings_file, "w") as f:
                json.dump(settings, f, indent=2)

            InstallerLogger.info(f"Docker configured to use {new_cpus} CPUs and {new_memory_gib}GB RAM")

        except Exception as e:
            InstallerLogger.error(f"Failed to configure Docker resources: {e}")

    def install_docker_compose(self, runtime_bin: Optional[str] = "docker") -> bool:
        """attempt to install Docker Compose on macOS using Homebrew.

        detection and verification are handled by the step; this method only
        performs installation using brew (Docker Desktop + docker-compose formula).
        """
        if self.config_only:
            InstallerLogger.info(f"Dry run: would install {runtime_bin} and Compose via brew")
            return True

        return self.is_docker_compose_package_installed(runtime_bin) or self.install_package(
            [runtime_bin, f"{runtime_bin}-compose"]
            if not self.is_docker_installed(runtime_bin=runtime_bin)
            else [f"{runtime_bin}-compose"]
        )

    def install(
        self,
        malcolm_config,
        config_dir: str,
        ctx,
        orchestration_file=None,
        logger=None,
    ) -> bool:
        """Execute full macOS installation flow honoring ControlFlow.

        Order:
          1) Filesystem (shared)
          2) Docker + Compose (platform) [compose orchestration only]
          3) Runtime config (shared)
          4) Orchestration files (shared) [compose only]
          5) SSL env (shared)
          6) Docker operations (shared) [compose only, install mode]
        """
        from scripts.malcolm_constants import OrchestrationFramework
        from scripts.installer.configs.constants.enums import InstallerResult
        from scripts.installer.actions import shared as shared_actions

        def _ok(result) -> bool:
            if isinstance(result, tuple):
                result = result[0]
            if isinstance(result, bool):
                return result
            if isinstance(result, InstallerResult):
                return result in (InstallerResult.SUCCESS, InstallerResult.SKIPPED)
            return True

        runtime_bin = malcolm_config.get_value(KEY_CONFIG_ITEM_RUNTIME_BIN) or "docker"

        # 1) Filesystem (shared)
        if not _ok(shared_actions.filesystem_prepare(malcolm_config, config_dir, self, ctx)):
            return False

        # 2) Docker + Compose (platform) for docker-compose orchestration
        if self.orchestration_mode == OrchestrationFramework.DOCKER_COMPOSE:
            if self.should_run_install_steps():
                self.setup_homebrew(ctx)
                if not self.is_docker_installed(runtime_bin=runtime_bin):
                    if not self.install_docker(ctx):
                        return False
                if not self.is_docker_compose_package_installed(runtime_bin):
                    self.install_docker_compose(runtime_bin)  # best effort; verify later
            else:
                InstallerLogger.info(f"Dry run/config-only: would install {runtime_bin} and Compose")

        # 3) Orchestration files (shared) [compose only]
        if self.orchestration_mode == OrchestrationFramework.DOCKER_COMPOSE:
            if not _ok(shared_actions.update_compose_files(malcolm_config, config_dir, orchestration_file, self, ctx)):
                return False

        # 4) SSL env (shared)
        if not _ok(shared_actions.ensure_ssl_env(malcolm_config, config_dir, self, ctx)):
            return False

        # 5) Docker operations (shared) [compose only and install mode]
        if self.orchestration_mode == OrchestrationFramework.DOCKER_COMPOSE and self.should_run_install_steps():
            if not _ok(shared_actions.perform_docker_operations(malcolm_config, config_dir, self, ctx)):
                return False

        return True
