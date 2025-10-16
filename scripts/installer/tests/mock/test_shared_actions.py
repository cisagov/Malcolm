#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2025 Battelle Energy Alliance, LLC.  All rights reserved.

"""Unit tests for shared installer actions and platform orchestration."""

import os
import sys
import unittest
from unittest.mock import patch

# Add the project root directory to the Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..")))

from scripts.installer.configs.constants.enums import InstallerResult
from scripts.installer.tests.mock.test_framework import BaseInstallerTest


class TestPlatformDockerInstall(BaseInstallerTest):
    """Validate platform-level docker install orchestration handles success/failure."""

    def test_platform_docker_install_success(self):
        ctx = self.create_test_context()
        with patch.object(self.mock_platform, "install_docker", return_value=True) as mock_install:
            result = self.mock_platform.install_docker(ctx)
        self.assertTrue(result)
        mock_install.assert_called_once_with(ctx)

    def test_platform_docker_install_failure(self):
        ctx = self.create_test_context()
        with patch.object(self.mock_platform, "install_docker", return_value=False) as mock_install:
            result = self.mock_platform.install_docker(ctx)
        self.assertFalse(result)
        mock_install.assert_called_once_with(ctx)


class TestDockerComposeInstall(BaseInstallerTest):
    def test_docker_compose_install_calls_platform(self):
        with patch.object(self.mock_platform, "install_docker_compose", return_value=True) as mock_install:
            ok = self.mock_platform.install_docker_compose()
        self.assertTrue(ok)
        mock_install.assert_called_once()


class TestFilesystemAction(BaseInstallerTest):

    def test_filesystem_step_success(self):
        """Test successful filesystem preparation."""
        from scripts.installer.actions import shared as shared_actions

        config = self.create_test_config()
        ctx = self.create_test_context()

        # Mock successful filesystem operations
        with patch("os.makedirs"), patch("os.path.exists", return_value=False), patch(
            "scripts.malcolm_utils.ChownRecursive"
        ):

            result = shared_actions.filesystem_prepare(config, self.temp_dir, self.mock_platform, ctx)

        self.assertTrue(result)

    def test_filesystem_step_directories_exist(self):
        """Test filesystem preparation when directories already exist."""
        from scripts.installer.actions import shared as shared_actions

        config = self.create_test_config()
        ctx = self.create_test_context()

        # Mock directories already exist
        with patch("os.path.exists", return_value=True):
            result = shared_actions.filesystem_prepare(config, self.temp_dir, self.mock_platform, ctx)

        self.assertTrue(result)

    def test_filesystem_step_exception(self):
        """Test filesystem preparation exception handling."""
        from scripts.installer.actions import shared as shared_actions

        config = self.create_test_config()
        ctx = self.create_test_context()
        # Use a directory that does not exist to trigger makedirs
        missing_dir = os.path.join(self.temp_dir, "missing-config")

        # Mock exception during directory creation
        with patch("os.makedirs", side_effect=Exception("Permission denied")):
            result = shared_actions.filesystem_prepare(config, missing_dir, self.mock_platform, ctx)
        # Expect InstallerResult.FAILURE enum
        from scripts.installer.configs.constants.enums import InstallerResult as _IR

        self.assertEqual(result, _IR.FAILURE)


class TestDockerOpsAction(BaseInstallerTest):

    def test_docker_ops_step_success(self):
        """Test successful Docker operations."""
        from scripts.installer.actions import shared as shared_actions

        config = self.create_test_config()
        ctx = self.create_test_context()

        # Mock docker-compose file exists
        with patch("os.path.isfile", return_value=True), patch(
            "scripts.installer.actions.shared.discover_compose_command",
            return_value=["docker", "compose"],
        ):
            result = shared_actions.perform_docker_operations(config, self.temp_dir, self.mock_platform, ctx)

        self.assertTrue(result)

    def test_docker_ops_step_no_compose_file(self):
        """Test Docker operations when no compose file exists."""
        from scripts.installer.actions import shared as shared_actions

        config = self.create_test_config()
        ctx = self.create_test_context()

        # Mock no docker-compose file
        with patch("os.path.isfile", return_value=False):
            result = shared_actions.perform_docker_operations(config, self.temp_dir, self.mock_platform, ctx)

        self.assertEqual(
            result,
            (
                InstallerResult.SUCCESS,
                "Compose file missing; docker operations skipped",
            ),
        )  # Should gracefully handle missing compose file

    def test_docker_ops_step_no_compose_command(self):
        """Test Docker operations when no compose command is available."""
        from scripts.installer.actions import shared as shared_actions

        config = self.create_test_config()
        ctx = self.create_test_context()

        # Mock compose file exists but no compose command
        with patch("os.path.isfile", return_value=True), patch(
            "scripts.installer.actions.shared.discover_compose_command",
            return_value=None,
        ):
            result = shared_actions.perform_docker_operations(config, self.temp_dir, self.mock_platform, ctx)

        self.assertEqual(
            result,
            (
                InstallerResult.SUCCESS,
                "Compose command unavailable; manual start required",
            ),
        )  # Should continue despite missing compose command


if __name__ == "__main__":
    unittest.main()
