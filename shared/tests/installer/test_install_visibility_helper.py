#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import unittest

from scripts.malcolm_constants import OrchestrationFramework
from scripts.installer.core.config_item import ConfigItem
from scripts.installer.core.visibility import install_item_is_visible as installation_item_is_visible
from scripts.installer.configs.constants.installation_item_keys import (
    KEY_INSTALLATION_ITEM_LOAD_MALCOLM_IMAGES,
    KEY_INSTALLATION_ITEM_DOCKER_INSTALL_METHOD,
    KEY_INSTALLATION_ITEM_DOCKER_COMPOSE_INSTALL_METHOD,
)


class TestInstallVisibilityHelper(unittest.TestCase):
    def test_k8s_hides_docker_and_podman_items(self):
        # item visible only for docker
        docker_item = ConfigItem(
            key="dummyDocker",
            label="Docker-only",
            default_value=False,
        )
        docker_item.metadata["visible_when_runtime"] = "docker"

        # item visible only for podman
        podman_item = ConfigItem(
            key="dummyPodman",
            label="Podman-only",
            default_value=False,
        )
        podman_item.metadata["visible_when_runtime"] = "podman"

        self.assertFalse(
            installation_item_is_visible(
                ctx=None,
                key=docker_item.key,
                item=docker_item,
                orchestration_mode=OrchestrationFramework.KUBERNETES,
                runtime_bin="docker",
                image_archive_path=None,
            )
        )
        self.assertFalse(
            installation_item_is_visible(
                ctx=None,
                key=podman_item.key,
                item=podman_item,
                orchestration_mode=OrchestrationFramework.KUBERNETES,
                runtime_bin="podman",
                image_archive_path=None,
            )
        )

    def test_runtime_filtering(self):
        item = ConfigItem(
            key="rtItem",
            label="Runtime",
            default_value=False,
        )
        item.metadata["visible_when_runtime"] = "docker"

        self.assertTrue(
            installation_item_is_visible(
                ctx=None,
                key=item.key,
                item=item,
                orchestration_mode=OrchestrationFramework.DOCKER_COMPOSE,
                runtime_bin="docker",
                image_archive_path=None,
            )
        )
        self.assertFalse(
            installation_item_is_visible(
                ctx=None,
                key=item.key,
                item=item,
                orchestration_mode=OrchestrationFramework.DOCKER_COMPOSE,
                runtime_bin="podman",
                image_archive_path=None,
            )
        )

    def test_load_from_file_requires_archive(self):
        load_item = ConfigItem(
            key=KEY_INSTALLATION_ITEM_LOAD_MALCOLM_IMAGES,
            label="Load images from file",
            default_value=False,
        )

        # hidden when no archive provided
        self.assertFalse(
            installation_item_is_visible(
                ctx=None,
                key=load_item.key,
                item=load_item,
                orchestration_mode=OrchestrationFramework.DOCKER_COMPOSE,
                runtime_bin="docker",
                image_archive_path=None,
            )
        )
        # visible when archive is present
        self.assertTrue(
            installation_item_is_visible(
                ctx=None,
                key=load_item.key,
                item=load_item,
                orchestration_mode=OrchestrationFramework.DOCKER_COMPOSE,
                runtime_bin="docker",
                image_archive_path="/tmp/images.tar",
            )
        )

    def test_docker_compose_gating_by_tool_availability(self):
        # Docker install method should be hidden when docker_installed True
        docker_install = ConfigItem(
            key=KEY_INSTALLATION_ITEM_DOCKER_INSTALL_METHOD,
            label="Docker Install Method",
            default_value=False,
        )
        docker_install.metadata["visible_when_runtime"] = "docker"

        self.assertFalse(
            installation_item_is_visible(
                ctx=None,
                key=docker_install.key,
                item=docker_install,
                orchestration_mode=OrchestrationFramework.DOCKER_COMPOSE,
                runtime_bin="docker",
                image_archive_path=None,
                docker_installed=True,
                compose_available=True,
            )
        )

        # Compose install method should be hidden when compose available
        compose_install = ConfigItem(
            key=KEY_INSTALLATION_ITEM_DOCKER_COMPOSE_INSTALL_METHOD,
            label="Compose Install Method",
            default_value=False,
        )
        compose_install.metadata["visible_when_runtime"] = "docker"

        self.assertFalse(
            installation_item_is_visible(
                ctx=None,
                key=compose_install.key,
                item=compose_install,
                orchestration_mode=OrchestrationFramework.DOCKER_COMPOSE,
                runtime_bin="docker",
                image_archive_path=None,
                docker_installed=True,
                compose_available=True,
            )
        )


if __name__ == "__main__":
    unittest.main()
