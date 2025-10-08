#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2025 Battelle Energy Alliance, LLC.  All rights reserved.

"""Unit tests for consolidated system tweaks functionality."""

import os
import sys
import tempfile
import shutil
import unittest
from unittest.mock import patch, MagicMock

# Add the project root directory to the Python path
sys.path.insert(
    0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", ".."))
)

from scripts.installer.core.install_context import InstallContext
from scripts.installer.platforms.utils import linux_tweaks
from scripts.installer.core.malcolm_config import MalcolmConfig
from scripts.installer.tests.mock.test_framework import BaseInstallerTest


class TestSystemTweaks(BaseInstallerTest):
    """Test consolidated system tweaks functionality."""

    def setUp(self):
        """Set up test fixtures."""
        super().setUp()
        # Additional setup if needed

    def test_sysctl_tweaks_auto_mode(self):
        """Test sysctl tweaks in auto mode."""
        from scripts.installer.configs.constants.installation_item_keys import (
            KEY_INSTALLATION_ITEM_AUTO_TWEAKS,
        )

        ctx = InstallContext()
        ctx.initialize_for_platform("linux")
        ctx.set_item_value(KEY_INSTALLATION_ITEM_AUTO_TWEAKS, True)

        config = self.create_test_config()
        status, _ = linux_tweaks.apply_sysctl(
            config, self.temp_dir, self.mock_platform, ctx, self.mock_logger
        )
        self.assertIn(status.name, ("SUCCESS", "SKIPPED"))

    def test_sysctl_tweaks_manual_mode_all_disabled(self):
        """Test sysctl tweaks in manual mode with all disabled."""
        from scripts.installer.configs.constants.installation_item_keys import (
            KEY_INSTALLATION_ITEM_AUTO_TWEAKS,
        )

        ctx = InstallContext()
        ctx.initialize_for_platform("linux")
        ctx.set_item_value(KEY_INSTALLATION_ITEM_AUTO_TWEAKS, False)

        config = self.create_test_config()
        status, _ = linux_tweaks.apply_sysctl(
            config, self.temp_dir, self.mock_platform, ctx, self.mock_logger
        )
        self.assertIn(status.name, ("SUCCESS", "SKIPPED"))

    def test_security_limits_auto_mode(self):
        """Test security limits in auto mode."""
        from scripts.installer.configs.constants.installation_item_keys import (
            KEY_INSTALLATION_ITEM_AUTO_TWEAKS,
        )

        ctx = InstallContext()
        ctx.initialize_for_platform("linux")
        ctx.set_item_value(KEY_INSTALLATION_ITEM_AUTO_TWEAKS, True)

        config = self.create_test_config()
        status, _ = linux_tweaks.apply_security_limits(
            config, self.temp_dir, self.mock_platform, ctx, self.mock_logger
        )
        self.assertIn(status.name, ("SUCCESS", "SKIPPED"))

    def test_grub_cgroup_auto_mode(self):
        """Test GRUB cgroup configuration in auto mode."""
        from scripts.installer.configs.constants.installation_item_keys import (
            KEY_INSTALLATION_ITEM_AUTO_TWEAKS,
        )

        ctx = InstallContext()
        ctx.initialize_for_platform("linux")
        ctx.set_item_value(KEY_INSTALLATION_ITEM_AUTO_TWEAKS, True)

        # Mock GRUB file doesn't exist
        with patch("os.path.exists", return_value=False):
            config = self.create_test_config()
            status, _ = linux_tweaks.apply_grub_cgroup(
                config, self.temp_dir, self.mock_platform, ctx, self.mock_logger
            )
            self.assertIn(status.name, ("SUCCESS", "SKIPPED"))  # Should succeed (skip)

    def test_sysctl_tweak_definitions(self):
        """Test that sysctl tweak definitions are properly defined."""
        definitions = linux_tweaks.get_sysctl_tweak_definitions()
        self.assertIsInstance(definitions, list)
        self.assertGreater(len(definitions), 0)

        # Check structure of definitions
        for definition in definitions:
            self.assertIn("id", definition)
            self.assertIn("description", definition)
            self.assertIn("value_display", definition)


if __name__ == "__main__":
    unittest.main()
