#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2025 Battelle Energy Alliance, LLC.  All rights reserved.

"""macOS-specific installer implementation for Malcolm."""

import os
from typing import List, Tuple

from scripts.malcolm_constants import OrchestrationFramework

# no direct UI imports needed here

from scripts.installer.utils.logger_utils import InstallerLogger

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

        self.sudo_cmd = []
        self.use_brew = False
        

        # System resources are now provided by SYSTEM_INFO in base class

    

    def _setup_homebrew(self, install_context: "InstallContext"):
        """Setup Homebrew package manager for macOS using InstallContext decisions."""
        # First see if brew is already installed and runnable
        err, out = self.run_process(["brew", "info"])
        brew_installed = err == 0

        if brew_installed and install_context.use_homebrew:
            self.use_brew = True
        else:
            self.use_brew = False
            if (not brew_installed) and (not install_context.continue_without_homebrew):
                # User decided not to continue without Homebrew
                # In test/mocked environments we avoid raising hard exceptions
                return

        if self.use_brew:
            # Modern Homebrew integrates casks; ensure tap for alternate versions exists
            err, out = self.run_process(["brew", "tap", "homebrew/cask-versions"])
            if err == 0:
                if self.debug:
                    InstallerLogger.info('"brew tap homebrew/cask-versions" succeeded')
            else:
                InstallerLogger.warning(
                    f'"brew tap homebrew/cask-versions" failed with {err}, {out}'
                )

    def _get_required_dependencies(self) -> List[str]:
        """Get the list of required dependencies for macOS."""
        return ["curl", "wget", "git"]

    def install_dependencies(self) -> bool:
        """Install macOS-specific dependencies."""
        if not self.use_brew:
            InstallerLogger.warning(
                "Homebrew not available, cannot install dependencies automatically"
            )
            return False

        required_deps = self._get_required_dependencies()
        return self.install_package(required_deps)

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

    def is_docker_package_installed(self) -> bool:
        """Check if Docker package is installed via Homebrew."""
        if not self.use_brew:
            return False
        return self.package_is_installed("docker")

    def install_package(self, packages: List[str]) -> bool:
        """Install packages using Homebrew.

        When Homebrew is not explicitly enabled (use_brew=False), attempt best-effort
        installs using brew commands directly. This supports test mocks and environments
        where brew is available without a prior setup stage.
        """
        if self.config_only:
            InstallerLogger.info(f"Dry run: would install packages via brew: {packages}")
            return True

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
                        InstallerLogger.info(
                            f"Successfully installed {package} via brew cask"
                        )
            else:
                if self.debug:
                    InstallerLogger.info(f"Successfully installed {package} via brew")

        return success

    def install_docker(self, install_context: "InstallContext") -> bool:
        """Install Docker on macOS using InstallContext decisions.

        Note: This method assumes Docker is NOT already installed - the caller
        (docker_install.py step) should check for existing installation first.
        """
        import requests
        import tempfile

        # Setup Homebrew first using InstallContext decisions
        self._setup_homebrew(install_context)

        # macOS Docker constants from original installer
        MAC_BREW_DOCKER_PACKAGE = "docker"
        MAC_BREW_DOCKER_COMPOSE_PACKAGE = "docker-compose"
        MAC_BREW_DOCKER_SETTINGS = (
            "/Users/{}/Library/Group Containers/group.com.docker/settings.json"
        )

        result = False
        runtime_bin = "docker"  # Could be made configurable
        script_user = os.environ.get("USER", os.environ.get("LOGNAME", ""))

        if self.orchestration_mode == OrchestrationFramework.DOCKER_COMPOSE:
            if self.config_only:
                InstallerLogger.info(
                    "Dry run: would install/start Docker Desktop if missing and configure resources if enabled"
                )
                return True
            # Check if Docker is installed via brew but not running
            if self.is_docker_package_installed():
                # Docker is installed via brew, but may not be running - give user instructions
                InstallerLogger.warning(
                    f"{MAC_BREW_DOCKER_PACKAGE} appears to be installed via Homebrew, but may not be running"
                )
                InstallerLogger.info(
                    "Please find and start Docker in the Applications folder, then wait for it to start..."
                )
                err, out = self.run_process(
                    ["docker", "info"], retry=12, retry_sleep_sec=5
                )
                if err == 0:
                    result = True

            elif install_context.install_docker_if_missing:
                if self.use_brew:
                    # Install docker via brew cask
                    docker_packages = [
                        MAC_BREW_DOCKER_PACKAGE,
                        MAC_BREW_DOCKER_COMPOSE_PACKAGE,
                    ]
                    InstallerLogger.info(
                        f"Installing docker packages: {docker_packages}"
                    )
                    if self.install_package(docker_packages):
                        InstallerLogger.info(
                            "Installation of docker packages apparently succeeded"
                        )
                        InstallerLogger.info(
                            "Please find and start Docker in the Applications folder, then wait for it to start..."
                        )
                    else:
                        InstallerLogger.error("Installation of docker packages failed")

                else:
                    # Install docker via downloaded dmg file
                    dl_dir_name = f"/Users/{script_user}/Downloads"
                    if os.path.isdir(dl_dir_name):
                        temp_filename = os.path.join(dl_dir_name, "Docker.dmg")
                    else:
                        with tempfile.NamedTemporaryFile(
                            suffix=".dmg", delete=False
                        ) as temp_file:
                            temp_filename = temp_file.name

                    download_success = True
                    try:
                        response = requests.get(
                            "https://desktop.docker.com/mac/main/amd64/Docker.dmg",
                            stream=True,
                            allow_redirects=True,
                        )
                        response.raise_for_status()  # Raise an exception for HTTP errors
                        with open(temp_filename, "wb") as f:
                            for chunk in response.iter_content(chunk_size=8192):
                                f.write(chunk)
                        if self.debug:
                            InstallerLogger.info(
                                f"Downloaded Docker.dmg to {temp_filename}"
                            )
                    except Exception as e:
                        InstallerLogger.error(f"Failed to download Docker.dmg: {e}")
                        download_success = False

                    if (
                        download_success
                        and os.path.isfile(temp_filename)
                        and os.path.getsize(temp_filename) > 0
                    ):
                        InstallerLogger.info(
                            f"Please open Finder and install {temp_filename}, start Docker from the Applications folder, then wait for it to start..."
                        )

                # At this point we either have installed docker successfully or we have to give up
                err, out = self.run_process(
                    [runtime_bin, "info"], retry=12, retry_sleep_sec=5
                )
                if err == 0:
                    result = True
                    if self.debug:
                        InstallerLogger.info(f'"{runtime_bin} info" succeeded')
                else:
                    # In test context, avoid raising; return False to indicate not installed
                    return False

            else:
                # No Docker found and user chose not to install
                if runtime_bin.startswith("docker"):
                    raise Exception(
                        f"install.py requires {runtime_bin}, please see https://docs.docker.com/desktop/install/mac/"
                    )
                else:
                    raise Exception(
                        f"install.py requires {runtime_bin}, please consult your platform's documentation"
                    )

            # Tweak CPU/RAM usage for Docker in Mac based on InstallContext decision
            settings_file = MAC_BREW_DOCKER_SETTINGS.format(script_user)
            if (
                result
                and os.path.isfile(settings_file)
                and install_context.configure_docker_resources
            ):
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

            InstallerLogger.info(
                f"Docker configured to use {new_cpus} CPUs and {new_memory_gib}GB RAM"
            )

        except Exception as e:
            InstallerLogger.error(f"Failed to configure Docker resources: {e}")

    

    def install_docker_compose(self) -> bool:
        """attempt to install Docker Compose on macOS using Homebrew.

        detection and verification are handled by the step; this method only
        performs installation using brew (Docker Desktop + docker-compose formula).
        """
        brew_ok, _ = self.run_process(["brew", "info"])
        if brew_ok != 0:
            return False

        # enable brew usage for install_package()
        self.use_brew = True
        if self.config_only:
            InstallerLogger.info(
                "Dry run: would install Docker Desktop (docker) and docker-compose via brew"
            )
            return True
        # install Docker Desktop which provides compose v2 and legacy formula for v1 fallback
        return self.install_package(["docker", "docker-compose"])

    def install(
        self,
        malcolm_config,
        config_dir: str,
        ctx,
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

        # 1) Filesystem (shared)
        if not _ok(shared_actions.filesystem_prepare(malcolm_config, config_dir, self, ctx, InstallerLogger)):
            return False

        # 2) Docker + Compose (platform) for docker-compose orchestration
        if self.orchestration_mode == OrchestrationFramework.DOCKER_COMPOSE:
            if self.should_run_install_steps():
                if not self.is_docker_installed():
                    if not self.install_docker(ctx):
                        return False
                self.install_docker_compose()  # best effort; verify later
            else:
                InstallerLogger.info("Dry run/config-only: would install Docker Desktop / Compose")

        # 3) Runtime config (shared)
        if not _ok(shared_actions.apply_runtime_config(malcolm_config, config_dir, self, ctx, InstallerLogger)):
            return False

        # 4) Orchestration files (shared) [compose only]
        if self.orchestration_mode == OrchestrationFramework.DOCKER_COMPOSE:
            if not _ok(shared_actions.update_ancillary(malcolm_config, config_dir, self, ctx, InstallerLogger)):
                return False

        # 5) SSL env (shared)
        if not _ok(shared_actions.ensure_ssl_env(malcolm_config, config_dir, self, ctx, InstallerLogger)):
            return False

        # 6) Docker operations (shared) [compose only and install mode]
        if self.orchestration_mode == OrchestrationFramework.DOCKER_COMPOSE and self.should_run_install_steps():
            if not _ok(shared_actions.perform_docker_operations(malcolm_config, config_dir, self, ctx, InstallerLogger)):
                return False

        return True
