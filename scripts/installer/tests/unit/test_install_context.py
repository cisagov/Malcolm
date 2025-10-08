#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Unit tests for InstallContext core functionality.

Tests the InstallContext dataclass including:
- Initialization and defaults
- Platform-specific item loading
- Item value get/set operations
"""

import os
import sys
import unittest
from unittest.mock import MagicMock

# Add the project root directory to the Python path
sys.path.insert(
    0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
)

from scripts.installer.core.install_context import InstallContext
from scripts.installer.core.config_item import ConfigItem


class TestInstallContext(unittest.TestCase):
    """Test InstallContext core functionality."""

    def setUp(self):
        """Set up test fixtures."""
        self.context = InstallContext()

    def test_initialization_defaults(self):
        """Test InstallContext initialization with defaults."""
        # Test default values
        self.assertEqual(self.context.image_source, "registry")
        self.assertIsNone(self.context.image_archive_path)
        self.assertFalse(self.context.load_images_from_archive)
        self.assertTrue(self.context.run_network_reachability_check)
        self.assertFalse(self.context.offline_mode)
        self.assertFalse(self.context.config_only)
        self.assertEqual(self.context.docker_extra_users, [])
        self.assertFalse(self.context.user_confirmed_install)
        self.assertEqual(self.context.items, {})

    def test_initialization_with_parameters(self):
        """Test InstallContext initialization with parameters."""
        context = InstallContext(
            image_source="archive",
            image_archive_path="/path/to/archive",
            offline_mode=True,
            docker_extra_users=["user1", "user2"],
        )

        self.assertEqual(context.image_source, "archive")
        self.assertEqual(context.image_archive_path, "/path/to/archive")
        self.assertTrue(context.offline_mode)
        self.assertEqual(context.docker_extra_users, ["user1", "user2"])

    def test_item_operations_no_items(self):
        """Test item operations when no items are loaded."""
        # Getting non-existent item should return None
        result = self.context.get_item_value("NONEXISTENT_KEY")
        self.assertIsNone(result)

        # Setting non-existent item should return False
        result = self.context.set_item_value("NONEXISTENT_KEY", "value")
        self.assertFalse(result)

    def test_initialize_for_platform_shared(self):
        """Test platform initialization with shared items."""
        try:
            self.context.initialize_for_platform("shared")
            # Should not raise an exception and should have loaded items
            self.assertIsInstance(self.context.items, dict)
        except Exception as e:
            self.fail(f"initialize_for_platform('shared') raised an exception: {e}")

    def test_initialize_for_platform_linux(self):
        """Test platform initialization with linux items."""
        try:
            self.context.initialize_for_platform("linux")
            # Should not raise an exception and should have loaded items
            self.assertIsInstance(self.context.items, dict)
        except Exception as e:
            self.fail(f"initialize_for_platform('linux') raised an exception: {e}")

    def test_string_representations(self):
        """Test string representations of InstallContext."""
        # These should not raise exceptions
        str_repr = str(self.context)
        repr_str = repr(self.context)

        self.assertIsInstance(str_repr, str)
        self.assertIsInstance(repr_str, str)
        self.assertIn("InstallContext", repr_str)

    def test_auto_tweaks_property(self):
        """Test auto_tweaks property."""
        # Default should be True (when no items are loaded)
        self.assertTrue(self.context.auto_tweaks)

    def test_install_docker_if_missing_property(self):
        """Test install_docker_if_missing property."""
        # Default should be True (when no items are loaded)
        self.assertTrue(self.context.install_docker_if_missing)


if __name__ == "__main__":
    unittest.main()
