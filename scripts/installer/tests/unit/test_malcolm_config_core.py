#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Unit tests for MalcolmConfig core functionality.

Tests the MalcolmConfig core features including:
- Configuration item access
- Value getting and setting
- Validation functionality
"""

import os
import sys
import tempfile
import unittest

# Add the project root directory to the Python path
sys.path.insert(
    0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", ".."))
)

from scripts.installer.core.malcolm_config import MalcolmConfig
from scripts.installer.configs.constants.configuration_item_keys import (
    KEY_CONFIG_ITEM_LIVE_ZEEK,
)


class TestMalcolmConfigCore(unittest.TestCase):
    """Test MalcolmConfig core functionality."""

    def setUp(self):
        """Set up test fixtures."""
        self.config = MalcolmConfig()

    def test_initialization(self):
        """Test MalcolmConfig initialization."""
        # Should initialize without error
        self.assertIsNotNone(self.config)

    def test_get_value_existing_key(self):
        """Test getting value for existing configuration key."""
        # Try to get a value for a known key - should not raise
        try:
            value = self.config.get_value(KEY_CONFIG_ITEM_LIVE_ZEEK)
            # Should return a boolean (the default value)
            self.assertIsInstance(value, bool)
        except Exception as e:
            self.fail(f"get_value raised an exception: {e}")

    def test_get_value_nonexistent_key(self):
        """Test getting value for non-existent key."""
        # Should return None for non-existent key
        value = self.config.get_value("NONEXISTENT_KEY")
        self.assertIsNone(value)

    def test_set_value_valid_key(self):
        """Test setting a valid configuration value."""
        # Try to set a valid value - should not raise
        try:
            self.config.set_value(KEY_CONFIG_ITEM_LIVE_ZEEK, True)
            # Verify it was set
            value = self.config.get_value(KEY_CONFIG_ITEM_LIVE_ZEEK)
            self.assertTrue(value)
        except Exception as e:
            self.fail(f"set_value raised an exception: {e}")

    def test_all_keys_method(self):
        """Test that all_keys method works."""
        try:
            keys = self.config.all_keys()
            self.assertIsInstance(keys, (list, set, tuple))
            self.assertGreater(len(keys), 0)  # Should have some keys
        except Exception as e:
            self.fail(f"all_keys raised an exception: {e}")

    def test_env_file_roundtrip(self):
        """Test basic env file generation and loading."""
        with tempfile.TemporaryDirectory() as temp_dir:
            try:
                # Generate env files
                self.config.generate_env_files(temp_dir)

                # Create new config and load from files
                new_config = MalcolmConfig()
                new_config.load_from_env_files(temp_dir)

                # Should complete without errors
                self.assertIsNotNone(new_config)
            except Exception as e:
                self.fail(f"Env file roundtrip raised an exception: {e}")

    # Removed brittle private attribute check; behavior covered by dependency tests


if __name__ == "__main__":
    unittest.main()
