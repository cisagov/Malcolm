#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Unit test for configuration file import/export roundtrip validation.

This test validates that MalcolmConfig can export its settings to a YAML or JSON
file and that importing that file back into a new MalcolmConfig instance
results in the same configuration.
"""

import os
import tempfile
import unittest
import json
import sys

# Add the project root directory to the Python path
sys.path.insert(
    0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", ".."))
)

from scripts.installer.core.malcolm_config import MalcolmConfig
from scripts.installer.core.install_context import InstallContext
from scripts.installer.utils.settings_file_handler import SettingsFileHandler
from scripts.malcolm_utils import get_default_config_dir


class TestConfigFileRoundtrip(unittest.TestCase):
    """Test configuration file import/export roundtrip functionality."""

    def setUp(self):
        """Set up test fixtures."""
        self.config = MalcolmConfig()
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        """Clean up temporary directory."""
        # clean up the temporary directory
        for root, dirs, files in os.walk(self.temp_dir, topdown=False):
            for name in files:
                os.remove(os.path.join(root, name))
            for name in dirs:
                os.rmdir(os.path.join(root, name))
        os.rmdir(self.temp_dir)

    def test_config_roundtrip(self):
        """Test configuration file roundtrip for both YAML and JSON formats."""
        # 1. Load .env files into the config
        self.config.load_from_env_files(get_default_config_dir())

        # Create install context for SettingsFileHandler and initialize with platform items
        install_context = InstallContext()
        install_context.initialize_for_platform("linux")  # Use linux as test platform

        # 2. Export to YAML and JSON using SettingsFileHandler
        yaml_path = os.path.join(self.temp_dir, "config.yaml")
        json_path = os.path.join(self.temp_dir, "config.json")

        settings_handler = SettingsFileHandler(self.config, install_context)
        settings_handler.save_to_file(yaml_path, file_format="yaml")
        settings_handler.save_to_file(json_path, file_format="json")

        # 3. Create new configs and import from the exported files
        yaml_config = MalcolmConfig()
        json_config = MalcolmConfig()
        yaml_install_context = InstallContext()
        yaml_install_context.initialize_for_platform("linux")
        json_install_context = InstallContext()
        json_install_context.initialize_for_platform("linux")

        yaml_settings_handler = SettingsFileHandler(yaml_config, yaml_install_context)
        json_settings_handler = SettingsFileHandler(json_config, json_install_context)

        # Track any validation errors during import
        import logging

        logging.basicConfig(level=logging.WARNING)

        # capture warning messages to detect validation failures
        import io

        log_capture = io.StringIO()
        handler = logging.StreamHandler(log_capture)
        logger = logging.getLogger("scripts.installer.utils.settings_file_handler")
        logger.addHandler(handler)

        yaml_settings_handler.load_from_file(yaml_path)
        json_settings_handler.load_from_file(json_path)

        # check for validation errors in log output
        log_output = log_capture.getvalue()
        validation_errors = [
            line
            for line in log_output.split("\n")
            if "Failed to set" in line and "Invalid value" in line
        ]

        if validation_errors:
            self.fail(
                f"Roundtrip validation failed with {len(validation_errors)} errors:\n"
                + "\n".join(validation_errors)
            )

        # 4. Compare the MalcolmConfig items
        for key in self.config.all_keys():
            original_value = self.config.get_value(key)
            yaml_value = yaml_config.get_value(key)
            json_value = json_config.get_value(key)

            self.assertEqual(
                original_value,
                yaml_value,
                f"YAML roundtrip failed for config key {key}",
            )
            self.assertEqual(
                original_value,
                json_value,
                f"JSON roundtrip failed for config key {key}",
            )

        # 5. Compare the InstallContext items
        for key in install_context.items.keys():
            original_value = install_context.get_item_value(key)
            yaml_value = yaml_install_context.get_item_value(key)
            json_value = json_install_context.get_item_value(key)
            self.assertEqual(
                original_value,
                yaml_value,
                f"YAML roundtrip failed for install key {key}",
            )
            self.assertEqual(
                original_value,
                json_value,
                f"JSON roundtrip failed for install key {key}",
            )


if __name__ == "__main__":
    unittest.main()
