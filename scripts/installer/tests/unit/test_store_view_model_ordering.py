#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import unittest
from typing import Any, Optional, Callable, List

from scripts.installer.ui.shared.store_view_model import build_rows_from_items
from scripts.installer.core.config_item import ConfigItem


class _FakeStore:
    def __init__(self, items):
        self._items = {k: v for k, v in items}
        self._visible = {k: True for k in self._items}
        self._observers = {}

    def get_item(self, key: str) -> Optional[ConfigItem]:
        return self._items.get(key)

    def get_value(self, key: str):
        it = self._items.get(key)
        return it.get_value() if it else None

    def set_value(self, key: str, value: Any) -> None:
        if key in self._items:
            self._items[key].set_value(value)

    def is_item_visible(self, key: str) -> bool:
        return bool(self._visible.get(key, False))

    def all_keys(self) -> List[str]:
        return list(self._items.keys())

    def observe(self, key: str, callback: Callable[[Any], None]) -> None:
        self._observers.setdefault(key, []).append(callback)


class TestStoreViewModelOrdering(unittest.TestCase):
    def test_roots_and_children_order(self):
        # Build a small tree: A has children B and C; D is separate
        A = ConfigItem(key="A", label="A")
        B = ConfigItem(key="B", label="B")
        C = ConfigItem(key="C", label="C")
        D = ConfigItem(key="D", label="D")
        # assign parents
        B.ui_parent = "A"
        C.ui_parent = "A"

        items = [("A", A), ("B", B), ("C", C), ("D", D)]
        store = _FakeStore(items)

        rows = build_rows_from_items(items, store, roots=["D", "A"])  # explicit order

        keys_by_depth = [(r.key, r.depth) for r in rows if r.visible]
        # Expect root D first, then root A, then its children B and C under A
        # Depth 0 for roots, depth 1 for children
        self.assertEqual(keys_by_depth[0], ("D", 0))
        self.assertEqual(keys_by_depth[1], ("A", 0))
        self.assertIn(keys_by_depth[2][0], ("B", "C"))
        self.assertEqual(keys_by_depth[2][1], 1)
        self.assertIn(keys_by_depth[3][0], ("B", "C"))
        self.assertEqual(keys_by_depth[3][1], 1)


if __name__ == "__main__":
    unittest.main()

