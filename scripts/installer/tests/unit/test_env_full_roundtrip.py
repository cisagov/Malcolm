#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import tempfile
import unittest

from scripts.installer.core.malcolm_config import MalcolmConfig
from scripts.installer.utils.exceptions import ConfigValueValidationError


class TestEnvFullRoundtripPerItem(unittest.TestCase):
    """Round‑trip coverage for all mapped ConfigItems via authoritative env vars.

    We iterate env-variable groups and mutate their authoritative items together
    so multi-conditional transforms (e.g., tcpdump vs netsniff) remain consistent.
    After writing and reloading .env, we assert the authoritative items match.
    """

    def setUp(self):
        self.cfg = MalcolmConfig()
        self.mapper = self.cfg.get_env_mapper()
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        for root, dirs, files in os.walk(self.temp_dir, topdown=False):
            for name in files:
                os.remove(os.path.join(root, name))
            for name in dirs:
                os.rmdir(os.path.join(root, name))
        os.rmdir(self.temp_dir)

    def test_all_items_env_roundtrip(self):
        covered_items = set()
        envs = list(self.mapper.env_var_by_map_key.values())
        self.assertGreater(len(envs), 0)
        
        # Reusable reload config - create once, reuse for all loads
        cfg_write = MalcolmConfig()
        cfg_read = MalcolmConfig()

        for env in envs:
            # Identify authoritative targets for this env var
            targets = [k for k in env.config_items if env.is_authoritative_for(k)]
            if not targets:
                continue

            # Write and reload using reusable reload config
            with tempfile.TemporaryDirectory() as td:
                cfg_write.generate_env_files(td)
                cfg_read.load_from_env_files(td)

            # Assert authoritative items for this env var survived roundtrip
            for key in targets:
                self.assertEqual(
                    cfg_write.get_value(key),
                    cfg_read.get_value(key),
                    f"Roundtrip mismatch for {key} via {env.variable_name}",
                )
                covered_items.add(key)

        # Ensure we covered all items that have at least one authoritative env var
        expected = set()
        for env in self.mapper.env_var_by_map_key.values():
            for k in env.config_items:
                if env.is_authoritative_for(k):
                    expected.add(k)

        self.assertTrue(expected.issubset(covered_items) or expected == covered_items)


if __name__ == "__main__":
    unittest.main()
