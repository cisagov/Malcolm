#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Unit tests for InstallContext import/export roundtrip.

Focuses specifically on installation items (including enums) to ensure that
export to settings file and re-import preserves values and types.
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
from scripts.installer.core.install_context import InstallContext
from scripts.installer.utils.settings_file_handler import SettingsFileHandler
from scripts.installer.configs.constants.installation_item_keys import (
    KEY_INSTALLATION_ITEM_AUTO_TWEAKS,
    KEY_INSTALLATION_ITEM_INSTALLATION_PATH,
    KEY_INSTALLATION_ITEM_LOAD_MALCOLM_IMAGES,
    KEY_INSTALLATION_ITEM_PULL_MALCOLM_IMAGES,
    KEY_INSTALLATION_ITEM_DOCKER_INSTALL_METHOD,
    KEY_INSTALLATION_ITEM_DOCKER_COMPOSE_INSTALL_METHOD,
    KEY_INSTALLATION_ITEM_INSTALL_DOCKER_IF_MISSING,
    KEY_INSTALLATION_ITEM_TRY_DOCKER_REPOSITORY,
    KEY_INSTALLATION_ITEM_TRY_DOCKER_CONVENIENCE_SCRIPT,
)
from scripts.installer.configs.constants.enums import (
    DockerInstallMethod,
    DockerComposeInstallMethod,
)


class TestInstallContextRoundtrip(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.yaml_path = os.path.join(self.temp_dir, "install.yaml")
        self.json_path = os.path.join(self.temp_dir, "install.json")

        # Prepare original config + install context with linux items
        self.config = MalcolmConfig()
        self.ctx = InstallContext()
        self.ctx.initialize_for_platform("linux")

        # Set a representative subset of install items (exercise enums and booleans)
        self.ctx.set_item_value(
            KEY_INSTALLATION_ITEM_AUTO_TWEAKS, False
        )  # flip default True -> False
        self.ctx.set_item_value(
            KEY_INSTALLATION_ITEM_INSTALLATION_PATH, os.path.join(self.temp_dir, "dest")
        )
        # Enums
        self.ctx.set_item_value(
            KEY_INSTALLATION_ITEM_DOCKER_INSTALL_METHOD,
            DockerInstallMethod.CONVENIENCE_SCRIPT,
        )
        self.ctx.set_item_value(
            KEY_INSTALLATION_ITEM_DOCKER_COMPOSE_INSTALL_METHOD,
            DockerComposeInstallMethod.PIP_USER,
        )
        # Toggle booleans
        self.ctx.set_item_value(KEY_INSTALLATION_ITEM_INSTALL_DOCKER_IF_MISSING, False)
        self.ctx.set_item_value(KEY_INSTALLATION_ITEM_TRY_DOCKER_REPOSITORY, False)
        self.ctx.set_item_value(KEY_INSTALLATION_ITEM_TRY_DOCKER_CONVENIENCE_SCRIPT, True)
        # Image source toggles (mutual exclusivity exercised inside set_item_value)
        self.ctx.set_item_value(KEY_INSTALLATION_ITEM_LOAD_MALCOLM_IMAGES, True)
        self.ctx.set_item_value(KEY_INSTALLATION_ITEM_PULL_MALCOLM_IMAGES, False)

        # Save using SettingsFileHandler
        handler = SettingsFileHandler(self.config, self.ctx)
        handler.save_to_file(self.yaml_path, file_format="yaml")
        handler.save_to_file(self.json_path, file_format="json")

    def tearDown(self):
        for root, dirs, files in os.walk(self.temp_dir, topdown=False):
            for name in files:
                try:
                    os.remove(os.path.join(root, name))
                except Exception:
                    pass
            for name in dirs:
                try:
                    os.rmdir(os.path.join(root, name))
                except Exception:
                    pass
        try:
            os.rmdir(self.temp_dir)
        except Exception:
            pass

    def _roundtrip_and_compare(self, path: str):
        # Fresh instances for import
        cfg_new = MalcolmConfig()
        ctx_new = InstallContext()
        ctx_new.initialize_for_platform("linux")

        SettingsFileHandler(cfg_new, ctx_new).load_from_file(path)

        # Compare a curated set of keys
        checks = [
            (KEY_INSTALLATION_ITEM_AUTO_TWEAKS, bool),
            (KEY_INSTALLATION_ITEM_INSTALLATION_PATH, str),
            (KEY_INSTALLATION_ITEM_DOCKER_INSTALL_METHOD, DockerInstallMethod),
            (
                KEY_INSTALLATION_ITEM_DOCKER_COMPOSE_INSTALL_METHOD,
                DockerComposeInstallMethod,
            ),
            (KEY_INSTALLATION_ITEM_INSTALL_DOCKER_IF_MISSING, bool),
            (KEY_INSTALLATION_ITEM_TRY_DOCKER_REPOSITORY, bool),
            (KEY_INSTALLATION_ITEM_TRY_DOCKER_CONVENIENCE_SCRIPT, bool),
            (KEY_INSTALLATION_ITEM_LOAD_MALCOLM_IMAGES, bool),
            (KEY_INSTALLATION_ITEM_PULL_MALCOLM_IMAGES, bool),
        ]

        for key, expected_type in checks:
            original = self.ctx.get_item_value(key)
            loaded = ctx_new.get_item_value(key)

            # Type check for enums
            if expected_type in (DockerInstallMethod, DockerComposeInstallMethod):
                self.assertIsInstance(
                    loaded, expected_type, f"Loaded type mismatch for {key}"
                )

            self.assertEqual(original, loaded, f"Roundtrip mismatch for {key}")

    def test_yaml_roundtrip(self):
        self._roundtrip_and_compare(self.yaml_path)

    def test_json_roundtrip(self):
        self._roundtrip_and_compare(self.json_path)


if __name__ == "__main__":
    unittest.main()

