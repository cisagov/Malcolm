#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import unittest

from scripts.malcolm_constants import OrchestrationFramework
from scripts.installer.core.install_context import InstallContext
from scripts.installer.core.visibility import install_item_is_visible as is_item_visible
from scripts.installer.configs.constants.installation_item_keys import (
    KEY_INSTALLATION_ITEM_USE_HOMEBREW,
    KEY_INSTALLATION_ITEM_CONTINUE_WITHOUT_HOMEBREW,
    KEY_INSTALLATION_ITEM_CONFIGURE_DOCKER_RESOURCES,
    KEY_INSTALLATION_ITEM_DOCKER_INSTALL_METHOD,
    KEY_INSTALLATION_ITEM_DOCKER_COMPOSE_INSTALL_METHOD,
)


class TestInstallVisibilityMacOS(unittest.TestCase):
    def setUp(self):
        self.ctx = InstallContext()
        # Simulate macOS platform initialization
        self.ctx.initialize_for_platform("macos")

    def test_macos_items_present_and_visible_by_default(self):
        # These macOS-specific items should exist and default to visible
        for key in (
            KEY_INSTALLATION_ITEM_USE_HOMEBREW,
            KEY_INSTALLATION_ITEM_CONTINUE_WITHOUT_HOMEBREW,
            KEY_INSTALLATION_ITEM_CONFIGURE_DOCKER_RESOURCES,
        ):
            item = self.ctx.get_item(key)
            self.assertIsNotNone(item, f"macOS installation item missing: {key}")
            self.assertTrue(
                is_item_visible(
                    ctx=self.ctx,
                    key=key,
                    item=item,
                    orchestration_mode=OrchestrationFramework.DOCKER_COMPOSE,
                    runtime_bin="docker",
                    image_archive_path=None,
                )
            )

    def test_macos_tool_availability_gating_applies(self):
        # Even on macOS, docker/compose gating should hide install prompts when tools available
        for key in (
            KEY_INSTALLATION_ITEM_DOCKER_INSTALL_METHOD,
            KEY_INSTALLATION_ITEM_DOCKER_COMPOSE_INSTALL_METHOD,
        ):
            item = self.ctx.get_item(key)
            # Item might not be defined in macOS dict; if absent, skip test for that key
            if item is None:
                continue
            self.assertFalse(
                is_item_visible(
                    ctx=self.ctx,
                    key=key,
                    item=item,
                    orchestration_mode=OrchestrationFramework.DOCKER_COMPOSE,
                    runtime_bin="docker",
                    image_archive_path=None,
                    docker_installed=True,
                    compose_available=True,
                ),
                f"{key} should be hidden when docker/compose are available",
            )


if __name__ == "__main__":
    unittest.main()
