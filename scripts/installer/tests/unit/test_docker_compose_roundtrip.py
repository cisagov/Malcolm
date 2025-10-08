#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Unit test for docker-compose.yml roundtrip validation.

This test validates that MalcolmConfig can write docker configuration items
to docker-compose.yml and read them back correctly, similar to the .env
file roundtrip test.
"""

import os
import tempfile
import unittest
from ruamel.yaml import YAML as RuamelYAML

from scripts.installer.configs.constants.configuration_item_keys import (
    KEY_CONFIG_ITEM_MALCOLM_RESTART_POLICY,
    KEY_CONFIG_ITEM_MALCOLM_AUTO_RESTART,
    KEY_CONFIG_ITEM_CONTAINER_NETWORK_NAME,
)
from scripts.installer.configs.constants.enums import DockerRestartPolicy
from scripts.installer.core.malcolm_config import MalcolmConfig
from scripts.malcolm_utils import deep_get


class TestDockerComposeRoundtrip(unittest.TestCase):
    """Test docker-compose.yml roundtrip functionality."""

    def setUp(self):
        """Set up test fixtures."""
        self.config = MalcolmConfig()
        self.temp_dir = tempfile.mkdtemp()

        # create a minimal docker-compose.yml template for testing
        self.compose_template = {
            "version": "3.7",
            "services": {
                "test-service-1": {"image": "test:latest", "restart": "no"},
                "test-service-2": {"image": "test2:latest", "restart": "no"},
            },
            "networks": {"default": {"external": False}},
        }

        # write template to temp directory
        self.template_path = os.path.join(self.temp_dir, "docker-compose.yml")
        with open(self.template_path, "w") as f:
            ryaml = RuamelYAML(typ="safe", pure=True)
            ryaml.dump(self.compose_template, f)

    def tearDown(self):
        """Clean up temporary directory."""
        # clean up the temporary directory
        for root, dirs, files in os.walk(self.temp_dir, topdown=False):
            for name in files:
                os.remove(os.path.join(root, name))
            for name in dirs:
                os.rmdir(os.path.join(root, name))
        os.rmdir(self.temp_dir)

    def test_restart_policy_roundtrip(self):
        """Test restart policy configuration roundtrip."""
        # 1. set restart policy in config
        test_policy = DockerRestartPolicy.ALWAYS
        self.config.set_value(KEY_CONFIG_ITEM_MALCOLM_RESTART_POLICY, test_policy)

        # 2. generate docker-compose.yml
        self.config.generate_docker_compose_file(self.temp_dir, self.template_path)

        # 3. read the generated file and verify values
        output_path = os.path.join(self.temp_dir, "docker-compose.yml")
        with open(output_path, "r") as f:
            ryaml = RuamelYAML(typ="safe", pure=True)
            compose_data = ryaml.load(f)

        # 4. verify restart policy was applied to all services
        for service_name in ["test-service-1", "test-service-2"]:
            restart_value = deep_get(
                compose_data, ["services", service_name, "restart"]
            )
            self.assertEqual(
                restart_value,
                test_policy.value,
                f"Restart policy not correctly applied to {service_name}",
            )

    def test_auto_restart_roundtrip(self):
        """Test auto-restart configuration roundtrip."""
        # 1. set auto-restart in config (should result in 'unless-stopped')
        self.config.set_value(KEY_CONFIG_ITEM_MALCOLM_AUTO_RESTART, True)

        # 2. generate docker-compose.yml
        self.config.generate_docker_compose_file(self.temp_dir, self.template_path)

        # 3. read the generated file and verify values
        output_path = os.path.join(self.temp_dir, "docker-compose.yml")
        with open(output_path, "r") as f:
            ryaml = RuamelYAML(typ="safe", pure=True)
            compose_data = ryaml.load(f)

        # 4. verify auto-restart resulted in 'unless-stopped' for all services
        for service_name in ["test-service-1", "test-service-2"]:
            restart_value = deep_get(
                compose_data, ["services", service_name, "restart"]
            )
            self.assertEqual(
                restart_value,
                "unless-stopped",
                f"Auto-restart not correctly applied to {service_name}",
            )

    def test_external_network_roundtrip(self):
        """Test external network configuration roundtrip."""
        # 1. set external network name in config
        test_network = "malcolm-external-net"
        self.config.set_value(KEY_CONFIG_ITEM_CONTAINER_NETWORK_NAME, test_network)

        # 2. generate docker-compose.yml
        self.config.generate_docker_compose_file(self.temp_dir, self.template_path)

        # 3. read the generated file and verify values
        output_path = os.path.join(self.temp_dir, "docker-compose.yml")
        with open(output_path, "r") as f:
            ryaml = RuamelYAML(typ="safe", pure=True)
            compose_data = ryaml.load(f)

        # 4. verify external network configuration
        network_external = deep_get(compose_data, ["networks", "default", "external"])
        network_name = deep_get(compose_data, ["networks", "default", "name"])

        self.assertTrue(network_external, "External network not set to True")
        self.assertEqual(
            network_name, test_network, "External network name not correctly set"
        )

    def test_default_network_roundtrip(self):
        """Test default network configuration roundtrip."""
        # 1. ensure no external network is set (empty string)
        self.config.set_value(KEY_CONFIG_ITEM_CONTAINER_NETWORK_NAME, "")

        # 2. generate docker-compose.yml
        self.config.generate_docker_compose_file(self.temp_dir, self.template_path)

        # 3. read the generated file and verify values
        output_path = os.path.join(self.temp_dir, "docker-compose.yml")
        with open(output_path, "r") as f:
            ryaml = RuamelYAML(typ="safe", pure=True)
            compose_data = ryaml.load(f)

        # 4. verify default network configuration
        network_external = deep_get(compose_data, ["networks", "default", "external"])
        network_name = deep_get(compose_data, ["networks", "default", "name"])

        self.assertFalse(network_external, "Default network should not be external")
        self.assertIsNone(network_name, "Default network should not have a name")

    def test_policy_precedence_roundtrip(self):
        """Test that explicit restart policy takes precedence over auto-restart."""
        # 1. set both explicit policy and auto-restart
        test_policy = DockerRestartPolicy.ON_FAILURE
        self.config.set_value(KEY_CONFIG_ITEM_MALCOLM_RESTART_POLICY, test_policy)
        self.config.set_value(KEY_CONFIG_ITEM_MALCOLM_AUTO_RESTART, True)

        # 2. generate docker-compose.yml
        self.config.generate_docker_compose_file(self.temp_dir, self.template_path)

        # 3. read the generated file and verify values
        output_path = os.path.join(self.temp_dir, "docker-compose.yml")
        with open(output_path, "r") as f:
            ryaml = RuamelYAML(typ="safe", pure=True)
            compose_data = ryaml.load(f)

        # 4. verify explicit policy takes precedence (not 'unless-stopped')
        for service_name in ["test-service-1", "test-service-2"]:
            restart_value = deep_get(
                compose_data, ["services", service_name, "restart"]
            )
            self.assertEqual(
                restart_value,
                test_policy.value,
                f"Explicit restart policy should take precedence over auto-restart for {service_name}",
            )

    def test_multiple_config_roundtrip(self):
        """Test multiple docker configuration items applied together."""
        # 1. set multiple docker config values
        test_policy = DockerRestartPolicy.UNLESS_STOPPED
        test_network = "test-external-network"

        self.config.set_value(KEY_CONFIG_ITEM_MALCOLM_RESTART_POLICY, test_policy)
        self.config.set_value(KEY_CONFIG_ITEM_CONTAINER_NETWORK_NAME, test_network)

        # 2. generate docker-compose.yml
        self.config.generate_docker_compose_file(self.temp_dir, self.template_path)

        # 3. read the generated file and verify all values
        output_path = os.path.join(self.temp_dir, "docker-compose.yml")
        with open(output_path, "r") as f:
            ryaml = RuamelYAML(typ="safe", pure=True)
            compose_data = ryaml.load(f)

        # 4. verify restart policy
        for service_name in ["test-service-1", "test-service-2"]:
            restart_value = deep_get(
                compose_data, ["services", service_name, "restart"]
            )
            self.assertEqual(
                restart_value,
                test_policy.value,
                f"Restart policy not correctly applied to {service_name}",
            )

        # 5. verify network configuration
        network_external = deep_get(compose_data, ["networks", "default", "external"])
        network_name = deep_get(compose_data, ["networks", "default", "name"])

        self.assertTrue(network_external, "External network not set to True")
        self.assertEqual(
            network_name, test_network, "External network name not correctly set"
        )


if __name__ == "__main__":
    unittest.main()
