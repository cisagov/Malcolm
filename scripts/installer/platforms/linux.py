#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2025 Battelle Energy Alliance, LLC.  All rights reserved.

"""Linux-specific installer implementation for Malcolm."""

import os
from typing import List, Optional

from scripts.malcolm_utils import which, temporary_filename
from scripts.malcolm_common import (
    DownloadToFile,
    SYSTEM_INFO,
    get_system_image_architecture,
)
from scripts.malcolm_constants import (
    ImageArchitecture,
    OrchestrationFramework,
    PLATFORM_LINUX,
    PLATFORM_LINUX_ALMA,
    PLATFORM_LINUX_AMAZON,
    PLATFORM_LINUX_CENTOS,
    PLATFORM_LINUX_DEBIAN,
    PLATFORM_LINUX_ELEMENTARY,
    PLATFORM_LINUX_FEDORA,
    PLATFORM_LINUX_MINT,
    PLATFORM_LINUX_POP,
    PLATFORM_LINUX_RHEL,
    PLATFORM_LINUX_ROCKY,
    PLATFORM_LINUX_UBUNTU,
    PLATFORM_LINUX_ZORIN,
)
from scripts.installer.configs.constants.installation_item_keys import (
    KEY_INSTALLATION_ITEM_DOCKER_COMPOSE_INSTALL_METHOD,
)
from scripts.installer.configs.constants.enums import (
    DockerComposeInstallMethod,
)

from scripts.installer.core.malcolm_config import MalcolmConfig
from scripts.installer.core.install_context import InstallContext
from scripts.installer.utils.logger_utils import InstallerLogger
from scripts.installer.actions.shared import discover_compose_command

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

        self.distro, self.codename, self.ubuntu_codename, self.release = (
            SYSTEM_INFO["distro"],
            SYSTEM_INFO["codename"],
            SYSTEM_INFO["ubuntu_codename"],
            SYSTEM_INFO["release"],
        )
        self.check_package_cmd = self._get_check_package_command()
        self.install_package_cmd = self._get_install_package_command()
        self.update_repo_cmd = self._get_update_repo_command()
        self.add_repo_cmd = self._get_add_repo_command()

        if self.debug:
            InstallerLogger.info(
                f"{PLATFORM_LINUX} installer initialized for {self.distro} {self.codename} {self.release} ({self.ubuntu_codename if self.ubuntu_codename else ''})"
            )

    def _get_check_package_command(self) -> Optional[List[str]]:
        """Determine command to use to query if a package is installed."""
        if which('dpkg'):
            os.environ["DEBIAN_FRONTEND"] = "noninteractive"
            return ['dpkg', '-s']
        elif which('rpm'):
            return ['rpm', '-q']
        elif which('dnf'):
            return ['dnf', 'list', 'installed']
        elif which('yum'):
            return ['yum', 'list', 'installed']
        else:
            return None

    def _get_install_package_command(self) -> Optional[List[str]]:
        """Determine command to use to query if a package is installed."""
        if which('apt-get'):
            return ['apt-get', 'install', '-y', '-qq']
        elif which('apt'):
            return ['apt', 'install', '-y', '-qq']
        elif which('dnf'):
            return ['dnf', '-y', 'install', '--nobest']
        elif which('yum'):
            return ['yum', '-y', 'install']
        else:
            return None

    def _get_update_repo_command(self) -> Optional[List[str]]:
        """Determine command to use to query if a package is installed."""
        if which('apt-get'):
            return ['apt-get', 'update', '-y', '-qq']
        elif which('apt'):
            return ['apt', 'update', '-y', '-qq']
        elif which('dnf'):
            return ['dnf', '-y', 'check-update']
        elif which('yum'):
            return ['yum', '-y', 'makecache']
        else:
            return None

    def _get_add_repo_command(self) -> Optional[List[str]]:
        """Determine command to use to query if a package is installed."""
        if self.distro in (PLATFORM_LINUX_FEDORA,):
            return [
                'dnf',
                'config-manager',
                'addrepo',
                '--from-repofile',
            ]
        elif self.distro in (
            PLATFORM_LINUX_ALMA,
            PLATFORM_LINUX_ROCKY,
        ):
            return [
                'dnf',
                'config-manager',
                '-y',
                '--add-repo',
            ]
        elif self.distro in (PLATFORM_LINUX_CENTOS):
            return [
                'yum-config-manager',
                '-y',
                '--add-repo',
            ]
        else:
            return None

    def _get_required_dependencies(self) -> List[str]:
        """Get the list of required dependencies for this Linux platform"""

        result = []
        if self.distro in (
            PLATFORM_LINUX_DEBIAN,
            PLATFORM_LINUX_ELEMENTARY,
            PLATFORM_LINUX_MINT,
            PLATFORM_LINUX_POP,
            PLATFORM_LINUX_UBUNTU,
            PLATFORM_LINUX_ZORIN,
        ):
            result.extend(
                [
                    'apache2-utils',
                    'make',
                    'openssl',
                    'xz-utils',
                ]
            )
        elif self.distro in (
            PLATFORM_LINUX_ALMA,
            PLATFORM_LINUX_AMAZON,
            PLATFORM_LINUX_CENTOS,
            PLATFORM_LINUX_FEDORA,
            PLATFORM_LINUX_RHEL,
            PLATFORM_LINUX_ROCKY,
        ):
            result.extend(
                [
                    'httpd-tools',
                    'make',
                    'openssl',
                    'xz',
                ]
            )

        InstallerLogger.info(f"{self.distro=} {result=}")
        return result

    def install_dependencies(self) -> bool:
        """Install Linux-specific dependencies."""
        required_deps = self._get_required_dependencies()
        return self.install_package(required_deps)

    def package_is_installed(self, package_name: str) -> bool:
        """Check if a package is installed on Linux."""
        if self.check_package_cmd:
            err, _ = self.run_process(self.check_package_cmd + [package_name], stderr=False)
            return err == 0
        else:
            return False

    def install_package(self, packages: List[str]) -> bool:
        """Install packages using Linux package manager."""
        if self.update_repo_cmd:
            err, out = self.run_process(self.update_repo_cmd)
            if err != 0 and self.debug:
                InstallerLogger.warning(f"Failed to update package lists: {out}")

        packages_to_install = [p for p in packages if not self.package_is_installed(p)]
        if self.config_only or self.dry_run:
            if packages_to_install:
                InstallerLogger.info(f"Dry run: would install packages: {packages_to_install}")
            else:
                InstallerLogger.info(f"Dry run: all packages already installed: {packages}")
            return True
        if not packages_to_install:
            if self.debug:
                InstallerLogger.info(f"All packages already installed: {packages}")
            return True

        err, out = self.run_process(self.install_package_cmd + packages_to_install)
        if err != 0:
            InstallerLogger.error(f"Failed to install packages {packages_to_install}: {out}")
            return False

        if self.debug:
            InstallerLogger.info(f"Successfully installed packages: {packages_to_install}")
        return True

    def install_docker(self, install_context: InstallContext) -> bool:
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
            InstallerLogger.info(f"Dry run: would attempt Docker installation: {', '.join(actions)}")
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

    def _finalize_docker_installation(self, install_context: InstallContext) -> bool:
        """Complete Docker installation with service setup and user configuration."""

        # Configure Docker service
        self._configure_docker_service()

        # Verify installation
        err, out = self.run_process(["docker", "info"], retry=6, retry_sleep_sec=5)
        if err == 0:
            self._add_users_to_docker_group(install_context.docker_extra_users)
            return True
        else:
            raise Exception(f"Docker installation verification failed: {out}")

    def _install_docker_from_repo(self) -> bool:
        """Install Docker from official repositories."""
        # Install required packages for repo-based install
        required_repo_packages = []

        if self.distro in (
            PLATFORM_LINUX_DEBIAN,
            PLATFORM_LINUX_ELEMENTARY,
            PLATFORM_LINUX_MINT,
            PLATFORM_LINUX_POP,
            PLATFORM_LINUX_UBUNTU,
            PLATFORM_LINUX_ZORIN,
        ):
            required_repo_packages = [
                'apt-transport-https',
                'ca-certificates',
                'curl',
                'gpg-agent',
            ]
        elif self.distro == PLATFORM_LINUX_FEDORA:
            required_repo_packages = ['dnf-plugins-core']
        elif self.distro in (
            PLATFORM_LINUX_CENTOS,
            PLATFORM_LINUX_RHEL,
        ):
            required_repo_packages = ['yum-utils', 'device-mapper-persistent-data', 'lvm2']
        elif self.distro in (
            PLATFORM_LINUX_ALMA,
            PLATFORM_LINUX_AMAZON,
            PLATFORM_LINUX_ROCKY,
        ):
            required_repo_packages = ['dnf-utils']
        else:
            required_repo_packages = []

        if required_repo_packages:
            InstallerLogger.info(f"Installing required packages: {required_repo_packages}")
            if not self.install_package(required_repo_packages):
                return False

        # Add Docker repository and install Docker packages
        docker_packages = []
        repo_url = ""
        if (
            self.distro
            in (
                PLATFORM_LINUX_DEBIAN,
                PLATFORM_LINUX_ELEMENTARY,
                PLATFORM_LINUX_MINT,
                PLATFORM_LINUX_POP,
                PLATFORM_LINUX_UBUNTU,
                PLATFORM_LINUX_ZORIN,
            )
            and self._setup_docker_apt_repo()
        ):
            docker_packages = [
                "docker-ce",
                "docker-ce-cli",
                "docker-compose-plugin",
                "containerd.io",
            ]
        elif self.distro == PLATFORM_LINUX_FEDORA:
            repo_url = "https://download.docker.com/linux/fedora/docker-ce.repo"
            docker_packages = [
                'docker-ce',
                'docker-ce-cli',
                'docker-compose-plugin',
                'containerd.io',
            ]
        elif self.distro == PLATFORM_LINUX_CENTOS:
            repo_url = "https://download.docker.com/linux/centos/docker-ce.repo"
            docker_packages = [
                'docker-ce',
                'docker-ce-cli',
                'docker-compose-plugin',
                'containerd.io',
            ]
        elif self.distro in (
            PLATFORM_LINUX_ALMA,
            PLATFORM_LINUX_ROCKY,
        ):
            repo_url = "https://download.docker.com/linux/centos/docker-ce.repo"
            docker_packages = [
                'docker-ce',
                'docker-ce-cli',
                'docker-compose-plugin',
                'containerd.io',
            ]
        elif self.distro == PLATFORM_LINUX_AMAZON:
            docker_packages = ['docker']

        if self.add_repo_cmd and repo_url:
            if self.debug and self.add_repo_cmd:
                InstallerLogger.info(f"Adding Docker repository for {self.distro}")
            err, out = self.run_process(self.add_repo_cmd + [repo_url])
            if err != 0:
                docker_packages = []

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
        err = 1
        try:

            # Download and add Docker GPG key
            if self.debug:
                InstallerLogger.info("Requesting Docker GPG key for package signing")

            # Map distribution to Docker repository name
            repo_distro = self.distro
            if (
                self.distro
                in (
                    PLATFORM_LINUX_ELEMENTARY,
                    PLATFORM_LINUX_MINT,
                    PLATFORM_LINUX_POP,
                    PLATFORM_LINUX_UBUNTU,
                    PLATFORM_LINUX_ZORIN,
                )
                or self.distro.startswith(PLATFORM_LINUX_UBUNTU)
                or self.ubuntu_codename
            ):
                repo_distro = PLATFORM_LINUX_UBUNTU
            elif self.distro.startswith(PLATFORM_LINUX_DEBIAN):
                repo_distro = PLATFORM_LINUX_DEBIAN

            if repo_distro and (self.codename or self.ubuntu_codename):
                # get GPG key and store in /usr/share/keyrings
                dearmored_gpg_filename = "/usr/share/keyrings/docker-archive-keyring.gpg"
                repo_list_filename = '/etc/apt/sources.list.d/docker.list'
                with temporary_filename('.gpg') as armored_gpg_filename:
                    if DownloadToFile(
                        f"https://download.docker.com/linux/{repo_distro}/gpg",
                        armored_gpg_filename,
                    ):
                        try:
                            os.unlink(dearmored_gpg_filename)
                        except Exception:
                            pass
                        if which('gpg'):
                            err, out = self.run_process(
                                ["gpg", "--dearmor", "--output", dearmored_gpg_filename, armored_gpg_filename],
                                stderr=False,
                            )
                        else:
                            err, out = self.run_process(["cp", armored_gpg_filename, dearmored_gpg_filename])

                if os.path.isfile(dearmored_gpg_filename):
                    # Add Docker repository
                    if err == 0:
                        if self.debug:
                            InstallerLogger.info(f"Adding Docker repository for {self.distro}")
                        with open(repo_list_filename, 'w') as repo_list_file:
                            repo_list_file.write(
                                f"deb [signed-by={dearmored_gpg_filename}] https://download.docker.com/linux/{repo_distro} {self.ubuntu_codename if self.ubuntu_codename else self.codename} stable\n"
                            )
                        if self.update_repo_cmd:
                            up_err, out = self.run_process(self.update_repo_cmd)
                            if up_err != 0 and self.debug:
                                InstallerLogger.warning(f"Failed to update package lists: {out}")

        except Exception as e:
            InstallerLogger.error(f"Failed to setup Docker APT repository: {e}")

        return err == 0

    def _install_docker_convenience_script(self) -> bool:
        """Install Docker using the convenience script from get.docker.com."""
        try:
            with temporary_filename('.sh') as temp_filename:
                if DownloadToFile("https://get.docker.com/", temp_filename, self.debug):
                    os.chmod(temp_filename, 0o755)
                    err, out = self.run_process([temp_filename])
                    if err == 0:
                        InstallerLogger.info("Docker installation via convenience script succeeded")
                        return True
                    else:
                        InstallerLogger.error(f"Docker installation via convenience script failed: {out}")
        except Exception as e:
            InstallerLogger.error(f"Failed to download or execute Docker convenience script: {e}")
        return False

    def _configure_docker_service(self):
        """Configure Docker service on systemd systems (attempt on all distros)."""
        if self.config_only or self.dry_run:
            InstallerLogger.info("Dry run: would start and enable Docker service where applicable")
            return
        if which('systemctl'):
            # Attempt to start and enable the service regardless of distro to keep behaviour predictable
            err, out = self.run_process(["systemctl", "start", "docker"])
            if err == 0:
                err, out = self.run_process(["systemctl", "enable", "docker"])
                if err != 0:
                    InstallerLogger.error(f"Enabling Docker service failed: {out}")
            else:
                InstallerLogger.error(f"Starting Docker service failed: {out}")

    def _add_users_to_docker_group(self, users_to_add: List[str]):
        """Add users to the docker group for non-root access."""
        for user in users_to_add:
            if self.config_only or self.dry_run:
                InstallerLogger.info(f"Dry run: would add {user} to docker group")
                continue
            err, out = self.run_process(["usermod", "-a", "-G", "docker", user])
            if err == 0:
                if self.debug:
                    InstallerLogger.info(f'Adding {user} to "docker" group succeeded')
            else:
                InstallerLogger.error(f'Adding {user} to "docker" group failed')

    def install_docker_compose(self, install_context: InstallContext) -> bool:
        """Attempt to install the docker compose plugin on linux.

        With most platforms we're already installing Compose alongside Docker
        with docker-compose-plugin. As such, this function is a fallback
        to get it from GitHub instead.
        """
        import pathlib

        if discover_compose_command("docker", self):
            return True

        elif (
            install_context.get_value(KEY_INSTALLATION_ITEM_DOCKER_COMPOSE_INSTALL_METHOD)
            == DockerComposeInstallMethod.GITHUB
        ):
            with temporary_filename() as tmp_compose_script:
                if DownloadToFile(
                    f"https://github.com/docker/compose/releases/latest/download/docker-compose-linux-{'aarch64' if get_system_image_architecture() == ImageArchitecture.ARM64 else 'x86_64'}",
                    tmp_compose_script,
                ):
                    os.chmod(tmp_compose_script, 0o755)
                    for final_compose_script in [
                        "/usr/local/lib/docker/cli-plugins/docker-compose",
                        "/usr/local/bin/docker-compose",
                    ]:
                        pathlib.Path(os.path.dirname(final_compose_script)).mkdir(parents=True, exist_ok=True)
                        err, out = self.run_process(["cp", tmp_compose_script, final_compose_script])
                        if err == 0:
                            if discover_compose_command("docker", self):
                                InstallerLogger.info("Getting Docker Compose from GitHub succeeded")
                                return True
                            else:
                                InstallerLogger.error(
                                    "Getting Docker Compose from GitHub succeeded, but it failed to run"
                                )
                                try:
                                    os.unlink(final_compose_script)
                                except Exception:
                                    pass
                        else:
                            InstallerLogger.error(f"Getting Docker Compose from GitHub failed: {out}")

        return False

    # new unified orchestration entry point
    def install(
        self,
        malcolm_config: "MalcolmConfig",
        config_dir: str,
        ctx,
        orchestration_file=None,
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
                if not self.install_docker_compose(ctx):
                    # non-fatal if compose already present; verify via docker_ops later
                    pass
            else:
                InstallerLogger.info("Dry run/config-only: would install Docker if missing")
                InstallerLogger.info("Dry run/config-only: would install Docker Compose")

        # 4) Orchestration files (shared) [compose only]
        if self.orchestration_mode == OrchestrationFramework.DOCKER_COMPOSE:
            if not _ok(
                shared_actions.update_compose_files(
                    malcolm_config, config_dir, orchestration_file, self, ctx, InstallerLogger
                )
            ):
                return False

        # 5) SSL env (shared)
        if not _ok(shared_actions.ensure_ssl_env(malcolm_config, config_dir, self, ctx, InstallerLogger)):
            return False

        # 6) Linux tweaks (only in install mode)
        if self.should_run_install_steps():
            status, _ = linux_tweaks.apply_all(malcolm_config, config_dir, self, ctx, InstallerLogger)
            if status == InstallerResult.FAILURE:
                return False
        else:
            InstallerLogger.info(f"Dry run/config-only: would apply {PLATFORM_LINUX} system tweaks")

        # 7) Docker operations (shared) [compose only and install mode]
        if self.orchestration_mode == OrchestrationFramework.DOCKER_COMPOSE:
            if self.should_run_install_steps():
                if not _ok(
                    shared_actions.perform_docker_operations(malcolm_config, config_dir, self, ctx, InstallerLogger)
                ):
                    return False
            else:
                InstallerLogger.info("Dry run/config-only: would perform docker operations (start/load)")

        return True
