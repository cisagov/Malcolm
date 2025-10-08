#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import tempfile
import unittest

from scripts.malcolm_constants import OrchestrationFramework
from scripts.installer.core.malcolm_config import MalcolmConfig
from scripts.installer.configs.constants.config_env_var_keys import (
    KEY_ENV_CONTAINER_RUNTIME_KEY,
    KEY_ENV_ZEEK_FILE_WATCHER_POLLING,
    KEY_ENV_FILEBEAT_WATCHER_POLLING,
    KEY_ENV_PCAP_PIPELINE_POLLING,
    KEY_ENV_ZEEK_ROTATED_PCAP,
    KEY_ENV_ZEEK_LIVE_CAPTURE,
    KEY_ENV_ARKIME_LIVE_CAPTURE,
    KEY_ENV_ARKIME_ROTATED_PCAP,
    KEY_ENV_SURICATA_LIVE_CAPTURE,
    KEY_ENV_SURICATA_ROTATED_PCAP,
    KEY_ENV_NETBOX_MODE,
    KEY_ENV_NETBOX_URL,
)
from scripts.installer.configs.constants.configuration_item_keys import (
    KEY_CONFIG_ITEM_DOCKER_ORCHESTRATION_MODE,
    KEY_CONFIG_ITEM_RUNTIME_BIN,
    KEY_CONFIG_ITEM_LIVE_ZEEK,
    KEY_CONFIG_ITEM_LIVE_ARKIME,
    KEY_CONFIG_ITEM_LIVE_SURICATA,
    KEY_CONFIG_ITEM_NETBOX_MODE,
    KEY_CONFIG_ITEM_NETBOX_URL,
)


def _write_env(mapper, temp_dir, env_key, value):
    ev = mapper.env_var_by_map_key[env_key]
    path = os.path.join(temp_dir, ev.file_name)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "a") as f:
        f.write(f"{ev.variable_name}={value}\n")


class TestEnvReversePrecedence(unittest.TestCase):
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

    def test_orchestration_precedence_container_runtime_over_polling(self):
        mapper = self.ref_cfg.get_env_mapper()

        # Set derived polling flags to "true" (which imply Kubernetes)
        for ek in (
            KEY_ENV_ZEEK_FILE_WATCHER_POLLING,
            KEY_ENV_PCAP_PIPELINE_POLLING,
            KEY_ENV_FILEBEAT_WATCHER_POLLING,
        ):
            _write_env(mapper, self.temp_dir, ek, "true")

        # Also set CONTAINER_RUNTIME_KEY to podman (which implies docker-compose)
        _write_env(mapper, self.temp_dir, KEY_ENV_CONTAINER_RUNTIME_KEY, "podman")

        cfg = MalcolmConfig()
        cfg.load_from_env_files(self.temp_dir)

        self.assertEqual(
            cfg.get_value(KEY_CONFIG_ITEM_DOCKER_ORCHESTRATION_MODE),
            OrchestrationFramework.DOCKER_COMPOSE,
        )
        self.assertEqual(cfg.get_value(KEY_CONFIG_ITEM_RUNTIME_BIN), "podman")

    def test_live_capture_beats_rotated_flag(self):
        mapper = self.ref_cfg.get_env_mapper()

        # Both present: live=true and rotated=true => precedence should keep live=true
        _write_env(mapper, self.temp_dir, KEY_ENV_ZEEK_LIVE_CAPTURE, "true")
        _write_env(mapper, self.temp_dir, KEY_ENV_ZEEK_ROTATED_PCAP, "true")

        cfg = MalcolmConfig()
        cfg.load_from_env_files(self.temp_dir)

        self.assertTrue(cfg.get_value(KEY_CONFIG_ITEM_LIVE_ZEEK))

    def test_live_capture_precedence_for_arkime_and_suricata(self):
        mapper = self.ref_cfg.get_env_mapper()

        # Arkime: live=true, rotated=true => live should remain true
        _write_env(mapper, self.temp_dir, KEY_ENV_ARKIME_LIVE_CAPTURE, "true")
        _write_env(mapper, self.temp_dir, KEY_ENV_ARKIME_ROTATED_PCAP, "true")

        # Suricata: live=true, rotated=true => live should remain true
        _write_env(mapper, self.temp_dir, KEY_ENV_SURICATA_LIVE_CAPTURE, "true")
        _write_env(mapper, self.temp_dir, KEY_ENV_SURICATA_ROTATED_PCAP, "true")

        cfg = MalcolmConfig()
        cfg.load_from_env_files(self.temp_dir)

        self.assertTrue(cfg.get_value(KEY_CONFIG_ITEM_LIVE_ARKIME))
        self.assertTrue(cfg.get_value(KEY_CONFIG_ITEM_LIVE_SURICATA))

    def test_netbox_mode_precedence_and_url_implies_remote(self):
        mapper = self.ref_cfg.get_env_mapper()

        # Case 1: explicit mode local and URL present -> mode stays local, URL set
        _write_env(mapper, self.temp_dir, KEY_ENV_NETBOX_MODE, "local")
        _write_env(mapper, self.temp_dir, KEY_ENV_NETBOX_URL, "https://example.invalid")

        cfg = MalcolmConfig()
        cfg.load_from_env_files(self.temp_dir)
        self.assertEqual(cfg.get_value(KEY_CONFIG_ITEM_NETBOX_MODE), "local")
        self.assertEqual(
            cfg.get_value(KEY_CONFIG_ITEM_NETBOX_URL), "https://example.invalid"
        )

        # Reset temp dir for a clean import
        for root, dirs, files in os.walk(self.temp_dir, topdown=False):
            for name in files:
                os.remove(os.path.join(root, name))
            for name in dirs:
                os.rmdir(os.path.join(root, name))

        os.makedirs(self.temp_dir, exist_ok=True)

        # Case 2: mode absent, URL present -> mode should become remote, URL set
        _write_env(mapper, self.temp_dir, KEY_ENV_NETBOX_URL, "https://remote.invalid")

        cfg2 = MalcolmConfig()
        cfg2.load_from_env_files(self.temp_dir)
        self.assertEqual(cfg2.get_value(KEY_CONFIG_ITEM_NETBOX_MODE), "remote")
        self.assertEqual(
            cfg2.get_value(KEY_CONFIG_ITEM_NETBOX_URL), "https://remote.invalid"
        )


if __name__ == "__main__":
    unittest.main()
