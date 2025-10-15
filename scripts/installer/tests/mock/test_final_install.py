#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2025 Battelle Energy Alliance, LLC.  All rights reserved.

"""Unit tests for artifact handling during installation."""

import os
import sys
import unittest
from unittest.mock import patch

# Add the project root directory to the Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "..")))

from scripts.installer.utils.artifact_utils import decide_and_handle_artifacts
from scripts.installer.tests.mock.test_framework import BaseInstallerTest
from argparse import Namespace


class TestArtifactHandling(BaseInstallerTest):
    """Test artifact handling (Malcolm tarballs and image archives)."""

    def test_artifact_handling_with_cli_and_auto_discovery(self):
        """Test artifact handling with both CLI-provided files and auto-discovery."""
        config = self.create_test_config()
        control_flow = self.mock_platform.control_flow

        # Create mock args with file paths
        args = Namespace()
        args.mfile = "/path/to/malcolm.tar.gz"
        args.ifile = "/path/to/images.tar.xz"
        args.non_interactive = True

        with patch("scripts.installer.utils.artifact_utils.validate_malcolm_tarball", return_value=(True, None)):
            with patch("scripts.installer.utils.artifact_utils.validate_image_archive", return_value=(True, None)):
                with patch("scripts.installer.utils.artifact_utils.extract_malcolm_tarball", return_value=("/extracted/path", "/config/path")):
                    with patch("scripts.installer.utils.artifact_utils.extract_image_files"):
                        with patch("os.path.isfile", return_value=True):
                            handled, m_file, i_file, _, _ = decide_and_handle_artifacts(
                                args, self.mock_ui, config, control_flow, self.temp_dir
                            )

        self.assertTrue(handled)
        self.assertEqual(m_file, args.mfile)
        self.assertEqual(i_file, args.ifile)

        # Test 2: Auto-discovery
        test_malcolm_file = os.path.join(self.temp_dir, "malcolm-test.tar.gz")
        test_image_file = os.path.join(self.temp_dir, "malcolm-test_images.tar.xz")

        with open(test_malcolm_file, "w") as f:
            f.write("test tarball content")
        with open(test_image_file, "w") as f:
            f.write("test image content")

        args_auto = Namespace()
        args_auto.mfile = None
        args_auto.ifile = None
        args_auto.non_interactive = True

        with patch("scripts.installer.utils.artifact_utils.validate_malcolm_tarball", return_value=(True, None)):
            with patch("scripts.installer.utils.artifact_utils.validate_image_archive", return_value=(True, None)):
                with patch("scripts.installer.utils.artifact_utils.extract_malcolm_tarball", return_value=("/extracted/path", "/config/path")):
                    with patch("scripts.installer.utils.artifact_utils.extract_image_files"):
                        with patch("os.getcwd", return_value=self.temp_dir):
                            handled, m_file, i_file, _, _ = decide_and_handle_artifacts(
                                args_auto, self.mock_ui, config, control_flow, self.temp_dir
                            )

        self.assertTrue(handled)
        self.assertEqual(m_file, test_malcolm_file)
        self.assertEqual(i_file, test_image_file)


if __name__ == "__main__":
    unittest.main()
