#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2025 Battelle Energy Alliance, LLC.  All rights reserved.

"""Linux-specific installer implementation for Malcolm."""

import os
import tempfile
from collections import namedtuple
from typing import List, Tuple

try:
    import distro

    DISTRO_AVAILABLE = True
except ImportError:
    DISTRO_AVAILABLE = False

from scripts.malcolm_constants import OrchestrationFramework

from scripts.installer.core.malcolm_config import MalcolmConfig
from scripts.installer.utils.logger_utils import InstallerLogger

from .base import BaseInstaller


class LinuxInstaller(BaseInstaller):
    """Linux-specific Malcolm installer implementation."""

    def __init__(
        self,
        orchestration_mode: OrchestrationFramework,
        ui,
        debug: bool = False,
        control_flow=None,
    ):
        """Initialize the Linux installer."""
        super().__init__(orchestration_mode, ui, debug, control_flow)

        # Detect specific Linux distribution information
        if DISTRO_AVAILABLE:
            self.distro = distro.id()
            self.codename = distro.codename()
            self.release = distro.version()
        else:
            # Fallback if distro package not available
            self.distro = "linux"
            self.codename = ""
            self.release = ""

        if self.debug:
            InstallerLogger.info(
                f"Linux installer initialized for {self.distro} {self.codename} {self.release}"
            )

    

    def _uses_apt(self):
        """Check if this distribution uses apt package manager.

        Default to apt for unknown generic Linux IDs used in tests.
        """
        if self.distro in [
            "ubuntu",
            "debian",
            "linuxmint",
            "pop",
            "elementary",
            "zorin",
        ]:
            return True
        if self.distro.startswith("ubuntu") or self.distro.startswith("debian"):
            return True
        # Fallback: treat generic or empty identifiers as apt-based for test/mocked environments
        return self.distro in ("linux", "")

    def _uses_dnf_yum(self):
        """Check if this distribution uses dnf/yum package manager."""
        return (
            self.distro in ["fedora", "centos", "rhel", "rocky", "alma"]
            or self.distro.startswith("fedora")
            or self.distro.startswith("centos")
        )

    def _get_required_dependencies(self) -> List[str]:
        """Get the list of required dependencies for this Linux platform."""
        basic_deps = ["curl", "wget", "git", "ethtool"]

        if self._uses_apt():
            basic_deps.extend(
                ["apt-transport-https", "ca-certificates", "gnupg", "lsb-release"]
            )
        elif self._uses_dnf_yum():
            basic_deps.extend(["dnf-plugins-core"])

        return basic_deps

    def install_dependencies(self) -> bool:
        """Install Linux-specific dependencies."""
        required_deps = self._get_required_dependencies()
        return self.install_package(required_deps)

    def package_is_installed(self, package_name: str) -> bool:
        """Check if a package is installed on Linux."""
        if self._uses_apt():
            check_cmd = ["dpkg", "-s"]
        elif self._uses_dnf_yum():
            check_cmd = ["rpm", "-q"]
        else:
            # Don't know how to check packages on this platform
            return False

        err, _ = self.run_process(check_cmd + [package_name], stderr=False)
        return err == 0

    def install_package(self, packages: List[str]) -> bool:
        """Install packages using Linux package manager."""
        packages_to_install = [p for p in packages if not self.package_is_installed(p)]
        if self.config_only or self.dry_run:
            if packages_to_install:
                InstallerLogger.info(
                    f"Dry run: would install packages: {packages_to_install}"
                )
            else:
                InstallerLogger.info(
                    f"Dry run: all packages already installed: {packages}"
                )
            return True
        if not packages_to_install:
            if self.debug:
                InstallerLogger.info(f"All packages already installed: {packages}")
            return True

        if self._uses_apt():
            install_cmd = ["apt-get", "update"]
            err, out = self.run_process(install_cmd, privileged=True)
            if err == 0:
                install_cmd = ["apt-get", "install", "-y"]
            else:
                InstallerLogger.error(f"Failed to update package lists: {out}")
                return False
        elif self._uses_dnf_yum():
            install_cmd = ["dnf", "install", "-y"]
        else:
            InstallerLogger.error(
                f"Unsupported Linux distribution for package installation: {self.distro}"
            )
            return False

        err, out = self.run_process(install_cmd + packages_to_install, privileged=True)
        if err != 0:
            InstallerLogger.error(
                f"Failed to install packages {packages_to_install}: {out}"
            )
            return False

        if self.debug:
            InstallerLogger.info(
                f"Successfully installed packages: {packages_to_install}"
            )
        return True

    def install_docker(self, install_context: "InstallContext") -> bool:
        """Install Docker on Linux using platform-appropriate methods."""
        # Quick check: if Docker is already available and responsive, nothing to do.
        try:
            err, _ = self.run_process(["docker", "info"], stderr=False)
            if err == 0:
                return True
        except Exception:
            pass
        # Dry run: report intended actions, skip changes
        if self.config_only or self.dry_run:
            actions = []
            if install_context.try_docker_repository_install:
                actions.append("install from official repository")
            if install_context.try_docker_convenience_script:
                actions.append("install via convenience script")
            if not actions:
                actions.append("no install (skipped by context)")
            InstallerLogger.info(
                f"Dry run: would attempt Docker installation: {', '.join(actions)}"
            )
            return True

        # Use InstallContext decisions for installation method
        if not install_context.install_docker_if_missing:
            return False

        # Try repository installation first
        if install_context.try_docker_repository_install:
            if self._install_docker_from_repo():
                return self._finalize_docker_installation(install_context)

        # Fall back to convenience script
        if install_context.try_docker_convenience_script:
            InstallerLogger.info(
                "Docker not installed via official repositories. Attempting to install Docker via convenience script (see https://github.com/docker/docker-install)"
            )
            if self._install_docker_convenience_script():
                return self._finalize_docker_installation(install_context)

        return False

    def _finalize_docker_installation(self, install_context: "InstallContext") -> bool:
        """Complete Docker installation with service setup and user configuration."""
        runtime_bin = "docker"

        # Configure Docker service
        self._configure_docker_service()

        # Verify installation
        err, out = self.run_process(
            [runtime_bin, "info"], privileged=True, retry=6, retry_sleep_sec=5
        )
        if err == 0:
            self._add_users_to_docker_group(install_context.docker_extra_users)
            return True
        else:
            raise Exception(f"Docker installation verification failed: {out}")

    def _install_docker_from_repo(self) -> bool:
        """Install Docker from official repositories."""
        # Install required packages for repo-based install
        required_repo_packages = []

        if self._uses_apt():
            required_repo_packages = [
                "apt-transport-https",
                "ca-certificates",
                "curl",
                "gnupg",
                "software-properties-common",
            ]
        elif self._uses_dnf_yum():
            required_repo_packages = ["dnf-plugins-core"]

        if required_repo_packages:
            InstallerLogger.info(
                f"Installing required packages: {required_repo_packages}"
            )
            if not self.install_package(required_repo_packages):
                return False

        # Add Docker repository and install Docker packages
        docker_packages = []

        if self._uses_apt():
            # Add Docker GPG key and repository for apt-based distributions
            if self._setup_docker_apt_repo():
                docker_packages = [
                    "docker-ce",
                    "docker-ce-cli",
                    "docker-compose-plugin",
                    "containerd.io",
                ]

        elif self._uses_dnf_yum():
            # Add Docker repository for dnf/yum-based distributions
            repo_url = "https://download.docker.com/linux/fedora/docker-ce.repo"
            if self.distro.startswith("centos") or self.distro in [
                "rhel",
                "rocky",
                "alma",
            ]:
                repo_url = "https://download.docker.com/linux/centos/docker-ce.repo"

            err, out = self.run_process(
                ["dnf", "config-manager", "-y", "--add-repo", repo_url], privileged=True
            )
            if err == 0:
                docker_packages = [
                    "docker-ce",
                    "docker-ce-cli",
                    "docker-compose-plugin",
                    "containerd.io",
                ]

        if docker_packages:
            InstallerLogger.info(f"Installing Docker packages: {docker_packages}")
            if self.install_package(docker_packages):
                InstallerLogger.info("Docker packages installed successfully")
                return True
            else:
                InstallerLogger.error("Docker package installation failed")

        return False

    def _setup_docker_apt_repo(self) -> bool:
        """Setup Docker APT repository for apt-based distributions."""
        try:
            import requests

            # Download and add Docker GPG key
            if self.debug:
                InstallerLogger.info("Requesting Docker GPG key for package signing")

            # Map distribution to Docker repository name
            repo_distro = self.distro
            if self.distro in ["linuxmint", "pop", "elementary", "zorin"]:
                repo_distro = "ubuntu"  # These are Ubuntu-based
            elif self.distro.startswith("ubuntu"):
                repo_distro = "ubuntu"
            elif self.distro.startswith("debian"):
                repo_distro = "debian"

            docker_gpg_key = requests.get(
                f"https://download.docker.com/linux/{repo_distro}/gpg",
                allow_redirects=True,
            )

            err, out = self.run_process(
                ["apt-key", "add"],
                stdin=docker_gpg_key.content.decode("utf-8"),
                privileged=True,
                stderr=False,
            )

            if err == 0:
                # Verify GPG key fingerprint
                err, out = self.run_process(
                    ["apt-key", "fingerprint", "0EBFCD88"],
                    privileged=True,
                    stderr=False,
                )

            # Add Docker repository
            if err == 0:
                if self.debug:
                    InstallerLogger.info("Adding Docker repository")

                repo_url = f"deb [arch=amd64] https://download.docker.com/linux/{repo_distro} {self.codename} stable"

                # Remove existing repo first
                self.run_process(
                    ["add-apt-repository", "-y", "-r", repo_url], privileged=True
                )

                # Add the repo
                err, out = self.run_process(
                    ["add-apt-repository", "-y", "-u", repo_url], privileged=True
                )

            return err == 0

        except ImportError:
            InstallerLogger.warning(
                "requests module not available for Docker repository setup"
            )
            return False
        except Exception as e:
            InstallerLogger.error(f"Failed to setup Docker APT repository: {e}")
            return False

    def _install_docker_convenience_script(self) -> bool:
        """Install Docker using the convenience script from get.docker.com."""
        try:
            import requests

            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".sh", delete=False
            ) as temp_file:
                temp_filename = temp_file.name

                # Download the convenience script
                response = requests.get("https://get.docker.com/", allow_redirects=True)
                temp_file.write(response.text)

            # Make script executable and run it
            os.chmod(temp_filename, 0o755)
            err, out = self.run_process([temp_filename], privileged=True)

            # Clean up
            os.unlink(temp_filename)

            if err == 0:
                InstallerLogger.info(
                    "Docker installation via convenience script succeeded"
                )
                return True
            else:
                InstallerLogger.error(
                    f"Docker installation via convenience script failed: {out}"
                )
                return False

        except Exception as e:
            InstallerLogger.error(
                f"Failed to download or execute Docker convenience script: {e}"
            )
            return False

    def _configure_docker_service(self):
        """Configure Docker service on systemd systems (attempt on all distros)."""
        if self.config_only or self.dry_run:
            InstallerLogger.info(
                "Dry run: would start and enable Docker service where applicable"
            )
            return
        # Attempt to start and enable the service regardless of distro to keep behaviour predictable
        err, out = self.run_process(["systemctl", "start", "docker"], privileged=True)
        if err == 0:
            err, out = self.run_process(
                ["systemctl", "enable", "docker"], privileged=True
            )
            if err != 0:
                InstallerLogger.error(f"Enabling Docker service failed: {out}")
        else:
            InstallerLogger.error(f"Starting Docker service failed: {out}")

    def _add_users_to_docker_group(self, users_to_add: List[str]):
        """Add users to the docker group for non-root access."""
        script_user = os.environ.get("USER", os.environ.get("LOGNAME", ""))

        if script_user != "root" and script_user not in users_to_add:
            users_to_add.append(script_user)

        for user in users_to_add:
            if self.config_only or self.dry_run:
                InstallerLogger.info(f"Dry run: would add {user} to docker group")
                continue
            err, out = self.run_process(
                ["usermod", "-a", "-G", "docker", user], privileged=True
            )
            if err == 0:
                if self.debug:
                    InstallerLogger.info(f'Adding {user} to "docker" group succeeded')
            else:
                InstallerLogger.error(f'Adding {user} to "docker" group failed')

    def install_docker_compose(self) -> bool:
        """Attempt to install the docker compose plugin on linux.

        detection and verification are handled by the step; this method only
        performs installation via the platform package manager.
        """
        return self.install_package(["docker-compose-plugin"])

    # new unified orchestration entry point
    def install(
        self,
        malcolm_config: "MalcolmConfig",
        config_dir: str,
        ctx,
        logger=None,
    ) -> bool:
        """Execute full Linux installation flow honoring ControlFlow and orchestration.

        Order:
          1) Filesystem (shared)
          2) Dependencies (platform)
          3) Docker + Compose (platform) [compose orchestration only]
          4) Runtime config (shared)
          5) Orchestration files (shared) [compose only]
          6) SSL env (shared)
          7) Linux tweaks (platform-owned logic) when enabled
          8) Docker operations (shared) [compose only]
        """
        from scripts.malcolm_constants import OrchestrationFramework
        from scripts.installer.actions import shared as shared_actions
        from scripts.installer.platforms.utils import linux_tweaks
        from scripts.installer.configs.constants.enums import InstallerResult
        
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

        # 2) Dependencies (platform)
        if self.should_run_install_steps():
            if not self.install_dependencies():
                return False
        else:
            InstallerLogger.info("Dry run/config-only: would install system dependencies")

        # 3) Docker + Compose when using docker-compose orchestration
        if self.orchestration_mode == OrchestrationFramework.DOCKER_COMPOSE:
            if self.should_run_install_steps():
                # Docker
                if not self.is_docker_installed():
                    if not self.install_docker(ctx):
                        return False
                # Compose
                if not self.install_docker_compose():
                    # non-fatal if compose already present; verify via docker_ops later
                    pass
            else:
                InstallerLogger.info("Dry run/config-only: would install Docker if missing")
                InstallerLogger.info("Dry run/config-only: would install Docker Compose")

        # 4) Runtime config (shared)
        if not _ok(shared_actions.apply_runtime_config(malcolm_config, config_dir, self, ctx, InstallerLogger)):
            return False

        # 5) Orchestration files (shared) [compose only]
        if self.orchestration_mode == OrchestrationFramework.DOCKER_COMPOSE:
            if not _ok(shared_actions.update_ancillary(malcolm_config, config_dir, self, ctx, InstallerLogger)):
                return False

        # 6) SSL env (shared)
        if not _ok(shared_actions.ensure_ssl_env(malcolm_config, config_dir, self, ctx, InstallerLogger)):
            return False

        # 7) Linux tweaks (only in install mode)
        if self.should_run_install_steps():
            status, _ = linux_tweaks.apply_all(
                malcolm_config, config_dir, self, ctx, InstallerLogger
            )
            if status == InstallerResult.FAILURE:
                return False
        else:
            InstallerLogger.info("Dry run/config-only: would apply Linux system tweaks")

        # 8) Docker operations (shared) [compose only and install mode]
        if self.orchestration_mode == OrchestrationFramework.DOCKER_COMPOSE:
            if self.should_run_install_steps():
                if not _ok(shared_actions.perform_docker_operations(malcolm_config, config_dir, self, ctx, InstallerLogger)):
                    return False
            else:
                InstallerLogger.info("Dry run/config-only: would perform docker operations (start/load)")

        return True
