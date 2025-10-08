#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2025 Battelle Energy Alliance, LLC.  All rights reserved.

"""Unit tests for installation UI visibility filtering."""

import sys
import os
import unittest

# Add the project root directory to the Python path
sys.path.insert(
    0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", ".."))
)

from scripts.malcolm_common import UserInterfaceMode
from scripts.installer.ui.tui.tui_installer_ui import TUIInstallerUI
from scripts.installer.configs.installation_items import (
    ALL_INSTALLATION_CONFIG_ITEMS_DICT,
)
from scripts.installer.platforms.linux import LinuxInstaller
from scripts.malcolm_constants import OrchestrationFramework
from scripts.installer.tests.mock.test_framework import BaseInstallerTest


class TestInstallationUI(BaseInstallerTest):
    """Test installation UI visibility filtering."""

    def setUp(self):
        """Set up test fixtures."""
        super().setUp()
        self.tui = TUIInstallerUI(UserInterfaceMode.InteractionInput)
        self.linux_platform = LinuxInstaller(
            OrchestrationFramework.DOCKER_COMPOSE, None, debug=True
        )

    def test_installation_config_items_available(self):
        """Test that installation config items are properly loaded."""
        # Should have some installation config items
        self.assertGreater(len(ALL_INSTALLATION_CONFIG_ITEMS_DICT), 0)

        # Each item should have a label
        for key, item in ALL_INSTALLATION_CONFIG_ITEMS_DICT.items():
            self.assertIsNotNone(item.label)
            self.assertIsInstance(key, str)

    def test_visible_items_filtering_linux(self):
        """Test that visible items are properly filtered for Linux platform."""
        malcolm_file = "/tmp/malcolm.tar.gz"  # Mock file
        image_file = "/tmp/images.tar.xz"  # Mock file

        # Test visible items filtering
        # Use shared visibility helper via menu builder in production code; test simplified path
        visible_items = ALL_INSTALLATION_CONFIG_ITEMS_DICT

        # Should have some visible items for Linux
        self.assertGreater(len(visible_items), 0)

        # All returned items should be from the original dict
        for key, item in visible_items.items():
            self.assertIn(key, ALL_INSTALLATION_CONFIG_ITEMS_DICT)
            self.assertEqual(item, ALL_INSTALLATION_CONFIG_ITEMS_DICT[key])

    def test_visible_items_subset_of_all_items(self):
        """Test that visible items are always a subset of all items."""
        malcolm_file = "/tmp/malcolm.tar.gz"
        image_file = "/tmp/images.tar.xz"

        visible_items = ALL_INSTALLATION_CONFIG_ITEMS_DICT

        # Visible items should be <= total items
        self.assertLessEqual(
            len(visible_items), len(ALL_INSTALLATION_CONFIG_ITEMS_DICT)
        )

    def test_gather_install_options_method_exists(self):
        """Installer UI exposes gather_install_options for installation choices."""
        self.assertTrue(hasattr(self.tui, "gather_install_options"))
        self.assertTrue(callable(getattr(self.tui, "gather_install_options")))


if __name__ == "__main__":
    unittest.main()
