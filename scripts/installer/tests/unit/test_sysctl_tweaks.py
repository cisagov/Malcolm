#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import unittest

from scripts.installer.core.install_context import InstallContext


class TestSysctlTweakBehavior(unittest.TestCase):
    def setUp(self):
        self.ctx = InstallContext()
        self.ctx.initialize_for_platform("linux")

    def _sysctl_children(self):
        return [k for k in self.ctx.items.keys() if k.startswith("sysctl_")]

    def test_sysctl_enable_sets_children_true_and_hides_them(self):
        children = self._sysctl_children()
        self.assertTrue(len(children) > 0)

        # mark one child as user-modified to ensure it is not overridden
        override_child = children[0]
        self.ctx.set_item_value(override_child, False)  # same value but marks modified

        # enabling sysctl should set unmodified children True and hide them
        self.ctx.set_item_value("sysctl", True)

        for k in children:
            if k == override_child:
                # user-modified child should not be force-enabled
                self.assertFalse(self.ctx.get_item_value(k))
            else:
                self.assertTrue(self.ctx.get_item_value(k))
            # all children hidden when parent enabled
            self.assertFalse(self.ctx.is_item_visible(k))

    def test_sysctl_disable_reveals_children_without_changing_values(self):
        children = self._sysctl_children()
        self.assertTrue(len(children) > 1)

        a, b = children[0], children[1]

        # Enable all (sets unmodified children True and hides them)
        self.ctx.set_item_value("sysctl", True)
        # Manually change one child while hidden (still allowed via API)
        self.ctx.set_item_value(a, False)
        prev_values = {k: self.ctx.get_item_value(k) for k in children}

        # Disable parent: children should be visible and values unchanged
        self.ctx.set_item_value("sysctl", False)
        for k in children:
            self.assertTrue(self.ctx.is_item_visible(k))
            self.assertEqual(self.ctx.get_item_value(k), prev_values[k])


if __name__ == "__main__":
    unittest.main()

