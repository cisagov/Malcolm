#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2025 Battelle Energy Alliance, LLC.  All rights reserved.

"""Integration tests for docker-compose update functionality."""

import os
import sys
import tempfile
import shutil
import unittest

# Add the project root directory to the Python path
script_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.abspath(os.path.join(script_dir, "..", "..", "..", ".."))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from scripts.malcolm_common import DumpYaml, LoadYaml
from scripts.installer.core.malcolm_config import MalcolmConfig
from scripts.installer.actions.shared import update_compose_files
from scripts.installer.core.install_context import InstallContext
from scripts.installer.tests.mock.test_framework import MockPlatform
from scripts.installer.configs.constants.configuration_item_keys import (
    KEY_CONFIG_ITEM_RUNTIME_BIN,
    KEY_CONFIG_ITEM_MALCOLM_RESTART_POLICY,
    KEY_CONFIG_ITEM_PCAP_DIR,
    KEY_CONFIG_ITEM_ZEEK_LOG_DIR,
    KEY_CONFIG_ITEM_CONTAINER_NETWORK_NAME,
)
from scripts.installer.tests.mock.test_framework import BaseInstallerTest


class TestDockerComposeIntegration(BaseInstallerTest):
    """Integration tests for docker-compose update functionality."""

    def setUp(self):
        """Set up test fixtures."""
        super().setUp()  # Get mock_logger and other utilities
        self.test_dir = tempfile.mkdtemp()
        self.config_dir = os.path.join(self.test_dir, "config")
        os.makedirs(self.config_dir)

        # Create a sample docker-compose.yml file
        self.sample_compose = {
            "services": {
                "opensearch": {
                    "image": "ghcr.io/idaholab/malcolm/opensearch:latest",
                    "restart": "no",
                    "logging": {"driver": "local"},
                    "volumes": ["./opensearch:/usr/share/opensearch/data"],
                },
                "arkime": {
                    "image": "ghcr.io/idaholab/malcolm/arkime:latest",
                    "restart": "no",
                    "logging": {"driver": "local"},
                    "volumes": ["./pcap:/data/pcap"],
                },
                "zeek": {
                    "image": "ghcr.io/idaholab/malcolm/zeek:latest",
                    "restart": "no",
                    "logging": {"driver": "local"},
                    # Use a container path that our remapper supports for the zeek service
                    # (upload directory under the zeek logs root)
                    "volumes": ["./zeek-logs:/zeek/upload"],
                },
            },
            "networks": {"default": {"name": "malcolm_default"}},
        }

        self.compose_file = os.path.join(self.test_dir, "docker-compose.yml")
        DumpYaml(self.sample_compose, self.compose_file)

    def tearDown(self):
        """Clean up test fixtures."""
        shutil.rmtree(self.test_dir)

    def test_docker_runtime_updates(self):
        """Test that docker-compose files are updated for Docker runtime."""
        malcolm_config = MalcolmConfig()
        malcolm_config.set_value(KEY_CONFIG_ITEM_RUNTIME_BIN, "docker")
        malcolm_config.set_value(KEY_CONFIG_ITEM_MALCOLM_RESTART_POLICY, "unless-stopped")

        result = update_compose_files(malcolm_config, self.test_dir, None, MockPlatform(), InstallContext())
        self.assertTrue(result)

        # Verify changes
        updated_data = LoadYaml(self.compose_file)

        for service in updated_data["services"]:
            # Docker doesn't use userns_mode
            self.assertNotIn("userns_mode", updated_data["services"][service])
            # Docker uses local logging driver
            self.assertEqual(updated_data["services"][service]["logging"]["driver"], "local")
            # Restart policy should be updated
            self.assertEqual(updated_data["services"][service]["restart"], "unless-stopped")

    def test_podman_runtime_updates(self):
        """Test that docker-compose files are updated for Podman runtime."""
        malcolm_config = MalcolmConfig()
        malcolm_config.set_value(KEY_CONFIG_ITEM_RUNTIME_BIN, "podman")
        malcolm_config.set_value(KEY_CONFIG_ITEM_MALCOLM_RESTART_POLICY, "always")

        result = update_compose_files(malcolm_config, self.test_dir, None, MockPlatform(), InstallContext())
        self.assertTrue(result)

        # Verify changes
        updated_data = LoadYaml(self.compose_file)

        for service in updated_data["services"]:
            # Podman uses userns_mode: keep-id
            self.assertEqual(updated_data["services"][service]["userns_mode"], "keep-id")
            # Podman uses json-file logging driver
            self.assertEqual(updated_data["services"][service]["logging"]["driver"], "json-file")
            # Restart policy should be updated
            self.assertEqual(updated_data["services"][service]["restart"], "always")

    def test_image_architecture_updates(self):
        """Test that image tags are processed without architecture suffixes."""
        import re

        malcolm_config = MalcolmConfig()

        result = update_compose_files(malcolm_config, self.test_dir, None, MockPlatform(), InstallContext())
        self.assertTrue(result)

        # Verify image tags remain unchanged (no architecture suffix)
        updated_data = LoadYaml(self.compose_file)

        expected_image_patterns = {
            "opensearch": r"ghcr\.io/idaholab/malcolm/opensearch:.*",
            "arkime": r"ghcr\.io/idaholab/malcolm/arkime:.*",
            "zeek": r"ghcr\.io/idaholab/malcolm/zeek:.*",
        }

        for service, pattern in expected_image_patterns.items():
            actual_image = updated_data["services"][service]["image"]
            self.assertIsNotNone(
                re.match(pattern, actual_image),
                f"Image {actual_image} doesn't match pattern {pattern}",
            )

    def test_volume_mount_updates(self):
        """Test that volume mounts are updated with custom paths."""
        malcolm_config = MalcolmConfig()
        # Create real temporary directories so RemapBoundPaths will remap
        custom_pcap = os.path.join(self.test_dir, "pcap-custom")
        custom_zeek = os.path.join(self.test_dir, "zeek-custom")
        os.makedirs(custom_pcap, exist_ok=True)
        os.makedirs(os.path.join(custom_zeek, "upload"), exist_ok=True)

        malcolm_config.set_value(KEY_CONFIG_ITEM_PCAP_DIR, custom_pcap)
        malcolm_config.set_value(KEY_CONFIG_ITEM_ZEEK_LOG_DIR, custom_zeek)

        result = update_compose_files(malcolm_config, self.test_dir, None, MockPlatform(), InstallContext())
        self.assertTrue(result)

        # Verify volume mount updates
        updated_data = LoadYaml(self.compose_file)

        # Check arkime pcap volume mount
        arkime_volumes = updated_data["services"]["arkime"]["volumes"]
        self.assertIn(f"{custom_pcap}:/data/pcap", arkime_volumes)

        # Check zeek log volume mount
        zeek_volumes = updated_data["services"]["zeek"]["volumes"]
        # For zeek, upload directory is remapped to <zeek_dir>/upload
        self.assertIn(f"{os.path.join(custom_zeek, 'upload')}:/zeek/upload", zeek_volumes)

    def test_network_configuration_updates(self):
        """Test that network configuration is updated."""
        malcolm_config = MalcolmConfig()
        malcolm_config.set_value(KEY_CONFIG_ITEM_CONTAINER_NETWORK_NAME, "custom_network")

        result = update_compose_files(malcolm_config, self.test_dir, None, MockPlatform(), InstallContext())
        self.assertTrue(result)

        # Verify network configuration
        updated_data = LoadYaml(self.compose_file)

        networks = updated_data.get("networks", {})
        for network_name in networks:
            network_config = networks[network_name]
            self.assertTrue(network_config.get("external"))
            self.assertEqual(network_config.get("name"), "custom_network")

    def test_missing_compose_files_handling(self):
        """Test graceful handling when no docker-compose files are found."""
        empty_dir = tempfile.mkdtemp()
        try:
            malcolm_config = MalcolmConfig()
            result = update_compose_files(malcolm_config, empty_dir, None, MockPlatform(), InstallContext())
            # Should return True (not an error) when no files found
            self.assertTrue(result)
        finally:
            shutil.rmtree(empty_dir)

    def test_generate_ancillary_configs_integration(self):
        """Test the complete ancillary configs generation flow."""
        from scripts.installer.platforms.linux import LinuxInstaller
        from scripts.installer.core.install_context import InstallContext
        from scripts.malcolm_constants import OrchestrationFramework

        malcolm_config = MalcolmConfig()
        malcolm_config.set_value(KEY_CONFIG_ITEM_RUNTIME_BIN, "podman")

        # Create platform and context for the run function
        platform = LinuxInstaller(OrchestrationFramework.DOCKER_COMPOSE, None, debug=True)
        ctx = InstallContext()

        result = update_compose_files(malcolm_config, self.config_dir, None, platform, ctx)
        self.assertTrue(result)

        # Verify that docker-compose files were updated
        updated_data = LoadYaml(self.compose_file)

        # Should have podman-specific configurations
        for service in updated_data["services"]:
            self.assertEqual(updated_data["services"][service]["userns_mode"], "keep-id")


def run_standalone_test():
    """Run the test as a standalone script for quick validation."""
    print("Running docker-compose integration tests...")

    # Create a MalcolmConfig instance
    malcolm_config = MalcolmConfig()

    # Set some test values
    malcolm_config.set_value(KEY_CONFIG_ITEM_RUNTIME_BIN, "podman")
    malcolm_config.set_value(KEY_CONFIG_ITEM_MALCOLM_RESTART_POLICY, "always")
    malcolm_config.set_value(KEY_CONFIG_ITEM_PCAP_DIR, "/custom/pcap")
    malcolm_config.set_value(KEY_CONFIG_ITEM_ZEEK_LOG_DIR, "/custom/zeek")

    # Test in project root directory (where docker-compose.yml files exist)
    malcolm_install_path = os.path.join(project_root)

    print(f"Testing docker-compose updates in: {malcolm_install_path}")

    # Test the update function directly
    result = update_compose_files(malcolm_config, malcolm_install_path, None, MockPlatform(), InstallContext())

    if result:
        print("✓ Docker-compose updates completed successfully")
    else:
        print("✗ Docker-compose updates failed")
        return False

    # Test the ancillary configs function
    config_dir = os.path.join(malcolm_install_path, "config")
    print(f"Testing ancillary config generation with config dir: {config_dir}")

    from scripts.installer.platforms.linux import LinuxInstaller
    from scripts.installer.core.install_context import InstallContext
    from scripts.malcolm_constants import OrchestrationFramework

    # Create platform and context for the run function
    platform = LinuxInstaller(OrchestrationFramework.DOCKER_COMPOSE, None, debug=True)
    ctx = InstallContext()

    result = update_compose_files(malcolm_config, config_dir, None, platform, ctx)

    if result:
        print("✓ Ancillary config generation completed successfully")
    else:
        print("✗ Ancillary config generation failed")
        return False

    return True


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--standalone":
        # Run as standalone integration test
        success = run_standalone_test()
        sys.exit(0 if success else 1)
    else:
        # Run as unit test
        unittest.main()
