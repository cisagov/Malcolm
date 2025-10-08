#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import unittest

from scripts.installer.ui.shared.labels import installation_item_display_label
from scripts.installer.configs.constants.installation_item_keys import (
    KEY_INSTALLATION_ITEM_DOCKER_COMPOSE_INSTALL_METHOD,
    KEY_INSTALLATION_ITEM_DOCKER_INSTALL_METHOD,
)


class TestInstallLabelsHelper(unittest.TestCase):
    def test_podman_label_overrides(self):
        self.assertEqual(
            installation_item_display_label(
                KEY_INSTALLATION_ITEM_DOCKER_COMPOSE_INSTALL_METHOD,
                "Docker Compose Installation Method",
                "podman",
            ),
            "Podman Compose Installation Method",
        )
        self.assertIn(
            "Docker only",
            installation_item_display_label(
                KEY_INSTALLATION_ITEM_DOCKER_INSTALL_METHOD,
                "Docker Installation Method",
                "podman",
            ),
        )

    def test_non_podman_returns_base(self):
        base = "Docker Compose Installation Method"
        out = installation_item_display_label(
            KEY_INSTALLATION_ITEM_DOCKER_COMPOSE_INSTALL_METHOD, base, "docker"
        )
        self.assertEqual(base, out)


if __name__ == "__main__":
    unittest.main()
