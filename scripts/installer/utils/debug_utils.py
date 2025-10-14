#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2025 Battelle Energy Alliance, LLC.  All rights reserved.

from scripts.installer.core.malcolm_config import MalcolmConfig

__all__ = [
    "debug_menu_structure",
]


def debug_menu_structure(malcolm_config: MalcolmConfig, main_menu_keys: list[str]):
    """Debug function to analyze the menu structure and find missing items."""
    print("\n--- DEBUG: Menu Structure Analysis ---")
    _ = main_menu_keys  # retained for signature compatibility

    # Build child map the same way as the main menu
    child_map: dict[str, list[str]] = {}
    all_items = malcolm_config.get_all_config_items()
    for key, item in all_items.items():
        if item.ui_parent and item.ui_parent in all_items:
            parent_key = item.ui_parent
            child_map.setdefault(parent_key, []).append(key)

    visible_items = malcolm_config.get_visible_items()
    hidden_items = malcolm_config.get_hidden_items()

    print(f"Visible items: {len(visible_items)}")
    print(f"Hidden items: {len(hidden_items)}")

    print("Press Enter to continue...")
    input()
