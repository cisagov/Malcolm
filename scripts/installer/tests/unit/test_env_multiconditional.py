#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Unit tests for multi-conditional .env variable transforms.

Covers env variables whose values depend on two or more configuration items,
verifying forward (config -> env) and reverse (env -> config) behavior aligns
with custom_transforms + EnvMapper logic.
"""

import os
import tempfile
import unittest

from scripts.malcolm_constants import OrchestrationFramework
from scripts.installer.configs.constants.config_env_var_keys import (
    KEY_ENV_ARKIME_ROTATED_PCAP,
    KEY_ENV_SURICATA_ROTATED_PCAP,
    KEY_ENV_ZEEK_ROTATED_PCAP,
    KEY_ENV_PCAP_ENABLE_TCPDUMP,
    KEY_ENV_CONTAINER_RUNTIME_KEY,
    KEY_ENV_ZEEK_FILE_WATCHER_POLLING,
    KEY_ENV_PCAP_PIPELINE_POLLING,
    KEY_ENV_FILEBEAT_WATCHER_POLLING,
)
from scripts.installer.configs.constants.configuration_item_keys import (
    KEY_CONFIG_ITEM_AUTO_ARKIME,
    KEY_CONFIG_ITEM_LIVE_ARKIME,
    KEY_CONFIG_ITEM_AUTO_SURICATA,
    KEY_CONFIG_ITEM_LIVE_SURICATA,
    KEY_CONFIG_ITEM_AUTO_ZEEK,
    KEY_CONFIG_ITEM_LIVE_ZEEK,
    KEY_CONFIG_ITEM_PCAP_TCP_DUMP,
    KEY_CONFIG_ITEM_PCAP_NET_SNIFF,
    KEY_CONFIG_ITEM_DOCKER_ORCHESTRATION_MODE,
    KEY_CONFIG_ITEM_RUNTIME_BIN,
)
from scripts.installer.core.malcolm_config import MalcolmConfig


def _parse_env_file(path: str) -> dict:
    env = {}
    if not os.path.isfile(path):
        return env
    with open(path, "r") as f:
        for line in f:
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            if "=" not in s:
                continue
            k, v = s.split("=", 1)
            env[k.strip()] = v.strip()
    return env


class TestEnvMultiConditional(unittest.TestCase):
    def setUp(self):
        self.cfg = MalcolmConfig()
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        for root, dirs, files in os.walk(self.temp_dir, topdown=False):
            for name in files:
                os.remove(os.path.join(root, name))
            for name in dirs:
                os.rmdir(os.path.join(root, name))
        os.rmdir(self.temp_dir)

    def _env_path_for(self, env_key: str) -> str:
        ev = self.cfg.get_env_mapper().env_var_by_map_key.get(env_key)
        self.assertIsNotNone(ev, f"Env key not mapped: {env_key}")
        return os.path.join(self.temp_dir, ev.file_name)

    def test_rotated_pcap_flags_forward(self):
        # auto=true, live=false -> 'true'
        self.cfg.set_value(KEY_CONFIG_ITEM_AUTO_ARKIME, True)
        self.cfg.set_value(KEY_CONFIG_ITEM_LIVE_ARKIME, False)
        self.cfg.set_value(KEY_CONFIG_ITEM_AUTO_SURICATA, True)
        self.cfg.set_value(KEY_CONFIG_ITEM_LIVE_SURICATA, False)
        self.cfg.set_value(KEY_CONFIG_ITEM_AUTO_ZEEK, True)
        self.cfg.set_value(KEY_CONFIG_ITEM_LIVE_ZEEK, False)

        self.cfg.generate_env_files(self.temp_dir)

        for env_key in (
            KEY_ENV_ARKIME_ROTATED_PCAP,
            KEY_ENV_SURICATA_ROTATED_PCAP,
            KEY_ENV_ZEEK_ROTATED_PCAP,
        ):
            env_path = self._env_path_for(env_key)
            env_map = _parse_env_file(env_path)
            var_name = (
                self.cfg.get_env_mapper().env_var_by_map_key[env_key].variable_name
            )
            self.assertEqual(env_map.get(var_name), "true", f"{env_key} should be true")

        # auto=true, live=true -> 'false'
        self.cfg.set_value(KEY_CONFIG_ITEM_LIVE_ARKIME, True)
        self.cfg.set_value(KEY_CONFIG_ITEM_LIVE_SURICATA, True)
        self.cfg.set_value(KEY_CONFIG_ITEM_LIVE_ZEEK, True)
        self.cfg.generate_env_files(self.temp_dir)
        for env_key in (
            KEY_ENV_ARKIME_ROTATED_PCAP,
            KEY_ENV_SURICATA_ROTATED_PCAP,
            KEY_ENV_ZEEK_ROTATED_PCAP,
        ):
            env_path = self._env_path_for(env_key)
            env_map = _parse_env_file(env_path)
            var_name = (
                self.cfg.get_env_mapper().env_var_by_map_key[env_key].variable_name
            )
            self.assertEqual(
                env_map.get(var_name), "false", f"{env_key} should be false"
            )

        # auto=false, live=false -> 'false'
        self.cfg.set_value(KEY_CONFIG_ITEM_AUTO_ARKIME, False)
        self.cfg.set_value(KEY_CONFIG_ITEM_AUTO_SURICATA, False)
        self.cfg.set_value(KEY_CONFIG_ITEM_AUTO_ZEEK, False)
        self.cfg.set_value(KEY_CONFIG_ITEM_LIVE_ARKIME, False)
        self.cfg.set_value(KEY_CONFIG_ITEM_LIVE_SURICATA, False)
        self.cfg.set_value(KEY_CONFIG_ITEM_LIVE_ZEEK, False)
        self.cfg.generate_env_files(self.temp_dir)
        for env_key in (
            KEY_ENV_ARKIME_ROTATED_PCAP,
            KEY_ENV_SURICATA_ROTATED_PCAP,
            KEY_ENV_ZEEK_ROTATED_PCAP,
        ):
            env_path = self._env_path_for(env_key)
            env_map = _parse_env_file(env_path)
            var_name = (
                self.cfg.get_env_mapper().env_var_by_map_key[env_key].variable_name
            )
            self.assertEqual(
                env_map.get(var_name), "false", f"{env_key} should be false"
            )

    def test_rotated_pcap_flags_reverse_live_set(self):
        # Write rotated flag = true and ensure live=false after load
        for env_key, live_key in [
            (KEY_ENV_ARKIME_ROTATED_PCAP, KEY_CONFIG_ITEM_LIVE_ARKIME),
            (KEY_ENV_SURICATA_ROTATED_PCAP, KEY_CONFIG_ITEM_LIVE_SURICATA),
            (KEY_ENV_ZEEK_ROTATED_PCAP, KEY_CONFIG_ITEM_LIVE_ZEEK),
        ]:
            env_path = self._env_path_for(env_key)
            os.makedirs(os.path.dirname(env_path), exist_ok=True)
            var_name = (
                self.cfg.get_env_mapper().env_var_by_map_key[env_key].variable_name
            )
            with open(env_path, "w") as f:
                f.write(f"{var_name}=true\n")

        new_cfg = MalcolmConfig()
        new_cfg.load_from_env_files(self.temp_dir)

        self.assertFalse(new_cfg.get_value(KEY_CONFIG_ITEM_LIVE_ARKIME))
        self.assertFalse(new_cfg.get_value(KEY_CONFIG_ITEM_LIVE_SURICATA))
        self.assertFalse(new_cfg.get_value(KEY_CONFIG_ITEM_LIVE_ZEEK))

    def test_pcap_enable_tcpdump(self):
        # tcpdump=true, netsniff=false -> 'true'
        self.cfg.set_value(KEY_CONFIG_ITEM_PCAP_TCP_DUMP, True)
        self.cfg.set_value(KEY_CONFIG_ITEM_PCAP_NET_SNIFF, False)
        self.cfg.generate_env_files(self.temp_dir)
        env_path = self._env_path_for(KEY_ENV_PCAP_ENABLE_TCPDUMP)
        env_map = _parse_env_file(env_path)
        var_name = (
            self.cfg.get_env_mapper()
            .env_var_by_map_key[KEY_ENV_PCAP_ENABLE_TCPDUMP]
            .variable_name
        )
        self.assertEqual(env_map.get(var_name), "true")

        # tcpdump=true, netsniff=true -> 'false'
        self.cfg.set_value(KEY_CONFIG_ITEM_PCAP_NET_SNIFF, True)
        self.cfg.generate_env_files(self.temp_dir)
        env_map = _parse_env_file(env_path)
        self.assertEqual(env_map.get(var_name), "false")

        # tcpdump=false, netsniff=false -> 'false'
        self.cfg.set_value(KEY_CONFIG_ITEM_PCAP_TCP_DUMP, False)
        self.cfg.set_value(KEY_CONFIG_ITEM_PCAP_NET_SNIFF, False)
        self.cfg.generate_env_files(self.temp_dir)
        env_map = _parse_env_file(env_path)
        self.assertEqual(env_map.get(var_name), "false")

    def test_container_runtime_key_forward_and_reverse(self):
        # Orchestration: Kubernetes -> 'kubernetes'
        self.cfg.set_value(
            KEY_CONFIG_ITEM_DOCKER_ORCHESTRATION_MODE, OrchestrationFramework.KUBERNETES
        )
        self.cfg.set_value(KEY_CONFIG_ITEM_RUNTIME_BIN, "docker")
        self.cfg.generate_env_files(self.temp_dir)
        env_path = self._env_path_for(KEY_ENV_CONTAINER_RUNTIME_KEY)
        env_map = _parse_env_file(env_path)
        var_name = (
            self.cfg.get_env_mapper()
            .env_var_by_map_key[KEY_ENV_CONTAINER_RUNTIME_KEY]
            .variable_name
        )
        self.assertEqual(env_map.get(var_name), "kubernetes")

        # Reverse: 'podman' -> DOCKER_COMPOSE + runtimeBin='podman'
        # overwrite with podman and ensure polling flags are set to docker-compose semantics
        os.makedirs(os.path.dirname(env_path), exist_ok=True)
        with open(env_path, "w") as f:
            f.write(f"{var_name}=podman\n")
        # set derived polling flags to false so they don't override orchestration
        for ek in (
            KEY_ENV_ZEEK_FILE_WATCHER_POLLING,
            KEY_ENV_PCAP_PIPELINE_POLLING,
            KEY_ENV_FILEBEAT_WATCHER_POLLING,
        ):
            p = self._env_path_for(ek)
            os.makedirs(os.path.dirname(p), exist_ok=True)
            vn = self.cfg.get_env_mapper().env_var_by_map_key[ek].variable_name
            with open(p, "w") as f:
                f.write(f"{vn}=false\n")
        new_cfg = MalcolmConfig()
        new_cfg.load_from_env_files(self.temp_dir)
        self.assertEqual(
            new_cfg.get_value(KEY_CONFIG_ITEM_DOCKER_ORCHESTRATION_MODE),
            OrchestrationFramework.DOCKER_COMPOSE,
        )
        self.assertEqual(new_cfg.get_value(KEY_CONFIG_ITEM_RUNTIME_BIN), "podman")


if __name__ == "__main__":
    unittest.main()
