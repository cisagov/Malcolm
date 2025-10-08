#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import tempfile
import unittest

from scripts.installer.core.malcolm_config import MalcolmConfig
from scripts.installer.configs.constants.config_env_var_keys import (
    KEY_ENV_FILEBEAT_SYSLOG_TCP_LISTEN,
    KEY_ENV_FILEBEAT_SYSLOG_TCP_PORT,
    KEY_ENV_FILEBEAT_SYSLOG_UDP_LISTEN,
    KEY_ENV_FILEBEAT_SYSLOG_UDP_PORT,
    KEY_ENV_ZEEK_FILE_ENABLE_VTOT,
)
from scripts.installer.configs.constants.configuration_item_keys import (
    KEY_CONFIG_ITEM_SYSLOG_TCP_PORT,
    KEY_CONFIG_ITEM_SYSLOG_UDP_PORT,
    KEY_CONFIG_ITEM_VTOT_API_KEY,
)


def _write_env(mapper, temp_dir, env_key, value):
    ev = mapper.env_var_by_map_key[env_key]
    path = os.path.join(temp_dir, ev.file_name)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "a") as f:
        f.write(f"{ev.variable_name}={value}\n")


class TestEnvDerivedNoop(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.ref_cfg = MalcolmConfig()

    def tearDown(self):
        for root, dirs, files in os.walk(self.temp_dir, topdown=False):
            for name in files:
                os.remove(os.path.join(root, name))
            for name in dirs:
                os.rmdir(os.path.join(root, name))
        os.rmdir(self.temp_dir)

    def test_syslog_listen_flags_do_not_set_ports(self):
        mapper = self.ref_cfg.get_env_mapper()

        # Only the derived listen flags present -> should not set port config items
        _write_env(mapper, self.temp_dir, KEY_ENV_FILEBEAT_SYSLOG_TCP_LISTEN, "true")
        _write_env(mapper, self.temp_dir, KEY_ENV_FILEBEAT_SYSLOG_UDP_LISTEN, "true")

        cfg = MalcolmConfig()
        cfg.load_from_env_files(self.temp_dir)

        self.assertIsNone(cfg.get_value(KEY_CONFIG_ITEM_SYSLOG_TCP_PORT))
        self.assertIsNone(cfg.get_value(KEY_CONFIG_ITEM_SYSLOG_UDP_PORT))

        # Now set explicit ports along with conflicting listen flags; ports must win
        _write_env(mapper, self.temp_dir, KEY_ENV_FILEBEAT_SYSLOG_TCP_PORT, "5514")
        _write_env(mapper, self.temp_dir, KEY_ENV_FILEBEAT_SYSLOG_UDP_PORT, "5514")

        cfg2 = MalcolmConfig()
        cfg2.load_from_env_files(self.temp_dir)
        self.assertEqual(cfg2.get_value(KEY_CONFIG_ITEM_SYSLOG_TCP_PORT), 5514)
        self.assertEqual(cfg2.get_value(KEY_CONFIG_ITEM_SYSLOG_UDP_PORT), 5514)

    def test_vtot_enable_flag_does_not_set_api_key(self):
        mapper = self.ref_cfg.get_env_mapper()

        # Present only the derived enable flag -> should not set API key
        _write_env(mapper, self.temp_dir, KEY_ENV_ZEEK_FILE_ENABLE_VTOT, "true")

        cfg = MalcolmConfig()
        cfg.load_from_env_files(self.temp_dir)

        # Expect empty/None API key since the flag cannot reconstruct the secret
        val = cfg.get_value(KEY_CONFIG_ITEM_VTOT_API_KEY)
        self.assertTrue(val is None or val == "")


if __name__ == "__main__":
    unittest.main()
