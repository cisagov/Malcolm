#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import tempfile
import unittest

from scripts.installer.core.malcolm_config import MalcolmConfig
from scripts.installer.configs.constants.config_env_var_keys import (
    KEY_ENV_ZEEK_VTOT_API2_KEY,
    KEY_ENV_OPENSEARCH_INDEX_SIZE_PRUNE_LIMIT,
)
from scripts.installer.configs.constants.configuration_item_keys import (
    KEY_CONFIG_ITEM_VTOT_API_KEY,
    KEY_CONFIG_ITEM_INDEX_PRUNE_SIZE_LIMIT,
)


class TestEnvSentinels(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        for root, dirs, files in os.walk(self.temp_dir, topdown=False):
            for name in files:
                os.remove(os.path.join(root, name))
            for name in dirs:
                os.rmdir(os.path.join(root, name))
        os.rmdir(self.temp_dir)

    def test_env_sentinel_zero_values(self):
        # Seed a temp env with sentinel '0' values and verify proper import
        ref = MalcolmConfig()
        mapper = ref.get_env_mapper()

        vt_env = mapper.env_var_by_map_key[KEY_ENV_ZEEK_VTOT_API2_KEY]
        prune_env = mapper.env_var_by_map_key[KEY_ENV_OPENSEARCH_INDEX_SIZE_PRUNE_LIMIT]

        os.makedirs(self.temp_dir, exist_ok=True)
        with open(os.path.join(self.temp_dir, vt_env.file_name), "a") as f:
            f.write(f"{vt_env.variable_name}=0\n")
        with open(os.path.join(self.temp_dir, prune_env.file_name), "a") as f:
            f.write(f"{prune_env.variable_name}=0\n")

        cfg2 = MalcolmConfig()
        cfg2.load_from_env_files(self.temp_dir)

        # Expect both to be treated as unset/empty
        vtot = cfg2.get_value(KEY_CONFIG_ITEM_VTOT_API_KEY)
        prune = cfg2.get_value(KEY_CONFIG_ITEM_INDEX_PRUNE_SIZE_LIMIT)
        self.assertTrue(vtot is None or vtot == "")
        self.assertTrue(prune is None or prune == "")

    def test_generate_writes_zero_for_empty_prune_limit(self):
        # By default the prune limit is empty; generation should write '0'
        cfg = MalcolmConfig()
        cfg.generate_env_files(self.temp_dir)

        ref = MalcolmConfig()
        mapper = ref.get_env_mapper()
        prune_env = mapper.env_var_by_map_key[KEY_ENV_OPENSEARCH_INDEX_SIZE_PRUNE_LIMIT]
        path = os.path.join(self.temp_dir, prune_env.file_name)
        with open(path, "r") as f:
            content = f.read()
        self.assertIn("OPENSEARCH_INDEX_SIZE_PRUNE_LIMIT=0", content)


if __name__ == "__main__":
    unittest.main()

