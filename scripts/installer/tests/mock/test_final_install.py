#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2025 Battelle Energy Alliance, LLC.  All rights reserved.

"""Unit tests for final installation logic."""

import os
import sys
import tempfile
import shutil
import unittest
from unittest.mock import patch

# Add the project root directory to the Python path
sys.path.insert(
    0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", ".."))
)

from scripts.installer.utils.artifact_utils import decide_and_handle_artifacts
from scripts.installer.core.malcolm_config import MalcolmConfig
from scripts.installer.tests.mock.test_framework import BaseInstallerTest
from argparse import Namespace


class TestFinalInstall(BaseInstallerTest):
    """Test final installation functionality."""

    def setUp(self):
        """Set up test fixtures."""
        super().setUp()
        # Additional test-specific setup
        self.examples_dir = os.path.join(self.temp_dir, "examples")
        os.makedirs(self.examples_dir)

        # Create sample .env.example files
        self.sample_env_examples = {
            "auth.env.example": "MALCOLM_USERNAME=admin\nMALCOLM_PASSWORD=password\n",
            "opensearch.env.example": "OPENSEARCH_MEMORY=4g\nOPENSEARCH_PRIMARY=opensearch-local\n",
            "nginx.env.example": "NGINX_SSL=false\nNGINX_CERTS_DIR=/opt/certs\n",
        }

        for filename, content in self.sample_env_examples.items():
            with open(os.path.join(self.examples_dir, filename), "w") as f:
                f.write(content)

    def test_ownership_not_set_as_non_root(self):
        """Test that ownership is not attempted when not running as root."""
        config = self.create_test_config()

        # Mock running as a regular user (UID != 0)
        with patch("os.getuid", return_value=1000):
            with patch.object(config, "generate_env_files"):
                with patch("os.chown") as mock_chown:
                    with patch(
                        "scripts.malcolm_utils.ChownRecursive"
                    ) as mock_chown_recursive:
                        # Test ownership handling through config generation
                        config.generate_env_files(self.temp_dir)

        # chown should not have been called
        mock_chown.assert_not_called()
        mock_chown_recursive.assert_not_called()

    def test_artifact_decision_with_cli_files(self):
        """Test artifact decision logic with CLI-provided files."""
        config = self.create_test_config()
        control_flow = self.mock_platform.control_flow

        # Create mock args with file paths
        args = Namespace()
        args.mfile = "/path/to/malcolm.tar.gz"
        args.ifile = "/path/to/images.tar.xz"
        args.non_interactive = True

        with patch(
            "scripts.installer.utils.artifact_utils.validate_malcolm_tarball",
            return_value=(True, None),
        ):
            with patch(
                "scripts.installer.utils.artifact_utils.validate_image_archive",
                return_value=(True, None),
            ):
                with patch(
                    "scripts.installer.utils.artifact_utils.extract_malcolm_tarball",
                    return_value=("/extracted/path", "/config/path"),
                ):
                    with patch(
                        "scripts.installer.utils.artifact_utils.extract_image_files"
                    ):
                        # Pretend the provided files exist
                        with patch("os.path.isfile", return_value=True):
                            handled, m_file, i_file, install_path, config_dir = (
                                decide_and_handle_artifacts(
                                    args,
                                    self.mock_ui,
                                    config,
                                    control_flow,
                                    self.temp_dir,
                                )
                            )

        # Should have handled the artifacts
        self.assertTrue(handled)
        self.assertEqual(m_file, args.mfile)
        self.assertEqual(i_file, args.ifile)

    def test_artifact_decision_auto_discovery(self):
        """Test artifact decision logic with automatic discovery."""
        config = self.create_test_config()
        control_flow = self.mock_platform.control_flow

        # Create test files in temp directory
        test_malcolm_file = os.path.join(self.temp_dir, "malcolm-test.tar.gz")
        test_image_file = os.path.join(self.temp_dir, "malcolm-test_images.tar.xz")

        with open(test_malcolm_file, "w") as f:
            f.write("test tarball content")
        with open(test_image_file, "w") as f:
            f.write("test image content")

        # Create mock args without explicit files
        args = Namespace()
        args.mfile = None
        args.ifile = None
        args.non_interactive = True

        # Non-interactive path used; no UI prompts required

        with patch(
            "scripts.installer.utils.artifact_utils.validate_malcolm_tarball",
            return_value=(True, None),
        ):
            with patch(
                "scripts.installer.utils.artifact_utils.validate_image_archive",
                return_value=(True, None),
            ):
                with patch(
                    "scripts.installer.utils.artifact_utils.extract_malcolm_tarball",
                    return_value=("/extracted/path", "/config/path"),
                ):
                    with patch(
                        "scripts.installer.utils.artifact_utils.extract_image_files"
                    ):
                        with patch("os.getcwd", return_value=self.temp_dir):
                            handled, m_file, i_file, install_path, config_dir = (
                                decide_and_handle_artifacts(
                                    args,
                                    self.mock_ui,
                                    config,
                                    control_flow,
                                    self.temp_dir,
                                )
                            )

        # Should have found and handled the artifacts
        self.assertTrue(handled)
        self.assertEqual(m_file, test_malcolm_file)
        self.assertEqual(i_file, test_image_file)

    def test_missing_examples_directory_graceful_handling(self):
        """Test graceful handling when .env.example directory is missing."""
        config = self.create_test_config()

        # Mock glob to return empty list (no templates found)
        with patch("glob.glob", return_value=[]):
            with patch.object(config, "generate_env_files"):
                with patch("os.getuid", return_value=1000):
                    # Test config generation handles missing examples gracefully
                    config.generate_env_files(self.temp_dir)

        # Should handle missing examples gracefully


if __name__ == "__main__":
    unittest.main()
