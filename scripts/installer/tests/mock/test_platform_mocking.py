#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2025 Battelle Energy Alliance, LLC.  All rights reserved.

"""Unit tests for platform-specific operations with comprehensive mocking."""

import os
import sys
import unittest
from unittest.mock import patch, mock_open

# Add the project root directory to the Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..")))

from scripts.installer.platforms.linux import LinuxInstaller
from scripts.installer.platforms.macos import MacInstaller
from scripts.malcolm_constants import OrchestrationFramework
from scripts.installer.tests.mock.test_framework import BaseInstallerTest


class TestLinuxPlatformMocking(BaseInstallerTest):
    """Test Linux platform with comprehensive mocking."""

    def setUp(self):
        super().setUp()
        self.linux_installer = LinuxInstaller(OrchestrationFramework.DOCKER_COMPOSE, self.mock_ui, debug=True)

    def test_linux_docker_installation(self):
        """Test Linux Docker installation."""
        ctx = self.create_test_context()

        # Test 1: Already installed
        with patch.object(self.linux_installer, "run_process") as mock_run:
            mock_run.return_value = (0, ["Docker running"])
            result = self.linux_installer.install_docker(ctx)
        self.assertTrue(result)
        self.assertEqual(len(mock_run.call_args_list), 1)

        # Test 2: Repository installation
        self.mock_ui.responses = {
            '"docker info" failed, attempt to install Docker?': True,
            "Attempt to install Docker using official repositories?": True,
        }
        with patch.object(self.linux_installer, "_install_docker_from_repo", return_value=True), patch.object(
            self.linux_installer, "_finalize_docker_installation", return_value=True
        ):
            with patch.object(self.linux_installer, "run_process", return_value=(1, ["Docker not found"])):
                result = self.linux_installer.install_docker(ctx)
        self.assertTrue(result)

    def test_linux_package_management_and_dependencies(self):
        """Test Linux package management and dependency installation."""
        self.linux_installer.distro = "ubuntu"
        packages = ["curl", "wget", "git"]

        def fake_run_process(command, privileged=False, **kwargs):
            if command[:2] == ["dpkg", "-s"]:
                return (
                    (1, ["package not installed"]) if command[-1] != "docker" else (0, ["Status: install ok installed"])
                )
            if command[:2] == ["apt-get", "update"]:
                return (0, ["update successful"])
            if command[:4] == ["apt-get", "install", "-y", "-qq"]:
                return (0, ["install successful"])
            raise AssertionError(f"Unexpected command: {command}")

        # Test package installation
        with patch.object(self.linux_installer, "run_process", side_effect=fake_run_process):
            result = self.linux_installer.install_package(packages)
        self.assertTrue(result)

        # Test package check
        with patch.object(self.linux_installer, "run_process", side_effect=fake_run_process):
            result = self.linux_installer.package_is_installed("docker")
        self.assertTrue(result)

        # Test dependency installation
        recorded_installs = []

        def fake_run_with_tracking(command, privileged=False, **kwargs):
            result = fake_run_process(command, privileged, **kwargs)
            if command[:4] == ["apt-get", "install", "-y", "-qq"]:
                recorded_installs.append(command[4:])
            return result

        with patch.object(self.linux_installer, "run_process", side_effect=fake_run_with_tracking):
            result = self.linux_installer.install_dependencies()
        self.assertTrue(result)
        for package in ["apache2-utils", "make", "openssl", "xz-utils"]:
            self.assertIn(package, recorded_installs[0])


class TestMacOSPlatformMocking(BaseInstallerTest):
    """Test macOS platform with comprehensive mocking."""

    def setUp(self):
        super().setUp()
        with patch.object(MacInstaller, "_setup_homebrew", return_value=None):
            self.macos_installer = MacInstaller(OrchestrationFramework.DOCKER_COMPOSE, self.mock_ui, debug=True)

    def test_macos_docker_and_package_management(self):
        """Test macOS Docker installation and package management via Homebrew."""
        ctx = self.create_test_context()

        # Test Docker installation
        def enable_homebrew(install_context):
            self.macos_installer.use_brew = True

        with patch.object(self.macos_installer, "_setup_homebrew", side_effect=enable_homebrew), patch.object(
            self.macos_installer, "is_docker_package_installed", return_value=False
        ), patch.object(
            self.macos_installer, "install_package", return_value=True
        ) as mock_install_package, patch.object(
            self.macos_installer, "run_process", return_value=(0, ["Docker running"])
        ):
            result = self.macos_installer.install_docker(ctx)
        self.assertTrue(result)
        mock_install_package.assert_called_once_with(["docker", "docker-compose"])

        # Test package management
        packages = ["curl", "wget", "git"]
        with patch.object(self.macos_installer, "run_process", return_value=(0, ["Package installed"])) as mock_run:
            result = self.macos_installer.install_package(packages)
        self.assertTrue(result)
        self.assertEqual(len(mock_run.call_args_list), len(packages))

    def test_macos_docker_resource_configuration(self):
        """Test macOS Docker resource configuration."""
        self.macos_installer.total_cores = 8
        self.macos_installer.total_memory_gigs = 16.0
        mock_settings = {"cpus": 4, "memoryMiB": 8192}

        m = mock_open(read_data='{"cpus": 4, "memoryMiB": 8192}')
        with patch("os.path.isfile", return_value=True), patch("builtins.open", m), patch(
            "json.load", return_value=mock_settings
        ), patch("json.dump") as mock_dump:
            self.macos_installer._configure_docker_resources("/test/settings.json")

        mock_dump.assert_called_once()
        updated_settings = mock_dump.call_args[0][0]
        self.assertEqual(updated_settings.get("cpus"), 6)
        self.assertEqual(updated_settings.get("memoryMiB"), 12288)


class TestPlatformMockingIntegration(BaseInstallerTest):
    """Test mock platform tracking and state management."""

    def test_mock_platform_tracking(self):
        """Test mock platform command and package state tracking."""
        # Test command tracking
        self.mock_platform.run_process(["docker", "info"])
        self.mock_platform.run_process(["apt-get", "update"], privileged=True)
        self.assertEqual(len(self.mock_platform.executed_commands), 2)
        self.assertEqual(self.mock_platform.executed_commands[0]["command"], "docker info")
        self.assertFalse(self.mock_platform.executed_commands[0]["privileged"])
        self.assertEqual(self.mock_platform.executed_commands[1]["command"], "apt-get update")
        self.assertTrue(self.mock_platform.executed_commands[1]["privileged"])

        # Test package state tracking
        self.assertFalse(self.mock_platform.package_is_installed("docker"))
        self.mock_platform.install_package(["docker", "docker-compose"])
        self.assertTrue(self.mock_platform.package_is_installed("docker"))
        self.assertTrue(self.mock_platform.package_is_installed("docker-compose"))
        self.assertFalse(self.mock_platform.package_is_installed("uninstalled-package"))


if __name__ == "__main__":
    unittest.main()
