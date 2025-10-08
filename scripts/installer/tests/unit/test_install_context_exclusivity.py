#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import unittest

from scripts.installer.core.install_context import InstallContext
from scripts.installer.configs.constants.installation_item_keys import (
    KEY_INSTALLATION_ITEM_LOAD_MALCOLM_IMAGES,
    KEY_INSTALLATION_ITEM_PULL_MALCOLM_IMAGES,
)


class TestInstallContextExclusivity(unittest.TestCase):
    def setUp(self):
        self.ctx = InstallContext()
        # use shared items; exclusivity logic is generic
        self.ctx.initialize_for_platform("shared")

    def test_defaults_both_false(self):
        # defaults mirror legacy: both false
        self.assertFalse(
            self.ctx.get_item_value(KEY_INSTALLATION_ITEM_LOAD_MALCOLM_IMAGES)
        )
        self.assertFalse(
            self.ctx.get_item_value(KEY_INSTALLATION_ITEM_PULL_MALCOLM_IMAGES)
        )
        self.assertFalse(self.ctx.pull_malcolm_images)

    def test_set_load_true_forces_pull_false_and_source_archive(self):
        self.ctx.set_item_value(KEY_INSTALLATION_ITEM_LOAD_MALCOLM_IMAGES, True)
        self.assertTrue(
            self.ctx.get_item_value(KEY_INSTALLATION_ITEM_LOAD_MALCOLM_IMAGES)
        )
        self.assertFalse(
            self.ctx.get_item_value(KEY_INSTALLATION_ITEM_PULL_MALCOLM_IMAGES)
        )
        self.assertEqual(self.ctx.image_source, "archive")
        self.assertTrue(self.ctx.load_images_from_archive)
        self.assertFalse(self.ctx.pull_malcolm_images)

    def test_set_pull_true_forces_load_false_and_source_registry(self):
        # flip load on first to then ensure pull overrides it
        self.ctx.set_item_value(KEY_INSTALLATION_ITEM_LOAD_MALCOLM_IMAGES, True)
        self.ctx.set_item_value(KEY_INSTALLATION_ITEM_PULL_MALCOLM_IMAGES, True)
        self.assertTrue(
            self.ctx.get_item_value(KEY_INSTALLATION_ITEM_PULL_MALCOLM_IMAGES)
        )
        self.assertFalse(
            self.ctx.get_item_value(KEY_INSTALLATION_ITEM_LOAD_MALCOLM_IMAGES)
        )
        self.assertEqual(self.ctx.image_source, "registry")
        self.assertFalse(self.ctx.load_images_from_archive)
        self.assertTrue(self.ctx.pull_malcolm_images)

    def test_setting_false_does_not_force_other_true(self):
        # explicitly setting one to false keeps the other unchanged (and default false)
        self.ctx.set_item_value(KEY_INSTALLATION_ITEM_LOAD_MALCOLM_IMAGES, False)
        self.ctx.set_item_value(KEY_INSTALLATION_ITEM_PULL_MALCOLM_IMAGES, False)
        self.assertFalse(
            self.ctx.get_item_value(KEY_INSTALLATION_ITEM_LOAD_MALCOLM_IMAGES)
        )
        self.assertFalse(
            self.ctx.get_item_value(KEY_INSTALLATION_ITEM_PULL_MALCOLM_IMAGES)
        )
        self.assertFalse(self.ctx.pull_malcolm_images)


if __name__ == "__main__":
    unittest.main()
