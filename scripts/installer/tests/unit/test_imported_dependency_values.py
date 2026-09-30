#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import os
import tempfile
import unittest

from scripts.malcolm_constants import PROFILE_HEDGEHOG
from scripts.installer.configs.constants.config_env_var_keys import (
    KEY_ENV_ARKIME_LIVE_CAPTURE,
    KEY_ENV_PROFILE_KEY,
    KEY_ENV_ZEEK_LIVE_CAPTURE,
)
from scripts.installer.configs.constants.configuration_item_keys import (
    KEY_CONFIG_ITEM_CAPTURE_LIVE_NETWORK_TRAFFIC,
    KEY_CONFIG_ITEM_LIVE_ARKIME,
    KEY_CONFIG_ITEM_LIVE_ZEEK,
    KEY_CONFIG_ITEM_MALCOLM_PROFILE,
)
from scripts.installer.core.malcolm_config import MalcolmConfig
from scripts.installer.utils.settings_file_handler import SettingsFileHandler


class TestImportedDependencyValues(unittest.TestCase):
    def test_authoritative_env_value_survives_dependency_updates(self):
        cfg = MalcolmConfig()
        candidates = {
            KEY_CONFIG_ITEM_LIVE_ARKIME: [(KEY_ENV_ARKIME_LIVE_CAPTURE, False)],
            KEY_CONFIG_ITEM_MALCOLM_PROFILE: [(KEY_ENV_PROFILE_KEY, PROFILE_HEDGEHOG)],
            KEY_CONFIG_ITEM_CAPTURE_LIVE_NETWORK_TRAFFIC: [(KEY_ENV_ZEEK_LIVE_CAPTURE, True)],
            KEY_CONFIG_ITEM_LIVE_ZEEK: [(KEY_ENV_ZEEK_LIVE_CAPTURE, True)],
        }

        cfg._apply_env_candidates(candidates)

        self.assertFalse(cfg.get_value(KEY_CONFIG_ITEM_LIVE_ARKIME))
        self.assertTrue(cfg.get_item(KEY_CONFIG_ITEM_LIVE_ARKIME).is_modified)
        self.assertNotIn(KEY_CONFIG_ITEM_LIVE_ARKIME, cfg.get_all_config_items(modified_only=True))

    def test_settings_file_values_are_explicit_but_not_reported_as_changes(self):
        cfg = MalcolmConfig()
        settings = {
            "configuration": {
                KEY_CONFIG_ITEM_LIVE_ARKIME: False,
                KEY_CONFIG_ITEM_MALCOLM_PROFILE: PROFILE_HEDGEHOG,
                KEY_CONFIG_ITEM_CAPTURE_LIVE_NETWORK_TRAFFIC: True,
                KEY_CONFIG_ITEM_LIVE_ZEEK: True,
            }
        }

        with tempfile.TemporaryDirectory() as temp_dir:
            path = os.path.join(temp_dir, "settings.json")
            with open(path, "w") as f:
                json.dump(settings, f)

            missing = SettingsFileHandler(cfg).load_from_file(path, config_only=True)

        self.assertFalse(cfg.get_value(KEY_CONFIG_ITEM_LIVE_ARKIME))
        self.assertTrue(cfg.get_item(KEY_CONFIG_ITEM_LIVE_ARKIME).is_modified)
        self.assertNotIn(KEY_CONFIG_ITEM_LIVE_ARKIME, missing["missing_configuration"])
        self.assertNotIn(KEY_CONFIG_ITEM_LIVE_ARKIME, cfg.get_all_config_items(modified_only=True))


if __name__ == "__main__":
    unittest.main()
