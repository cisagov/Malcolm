#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2025 Battelle Energy Alliance, LLC.  All rights reserved.

"""Dialog-based installation options menu using python3-dialog."""

from typing import Optional, TYPE_CHECKING, List, Tuple, Dict

from scripts.malcolm_common import (
    InstallerChooseOne,
    InstallerAskForString,
    InstallerDisplayMessage,
    UserInterfaceMode,
    DialogBackException,
    DialogCanceledException,
)
from scripts.installer.ui.shared.menu_builder import ValueFormatter
from scripts.installer.ui.shared.store_view_model import build_rows_from_items
from scripts.installer.ui.shared.prompt_utils import prompt_config_item_value
from scripts.installer.ui.shared.labels import installation_item_display_label
from scripts.installer.configs.constants.configuration_item_keys import (
    KEY_CONFIG_ITEM_RUNTIME_BIN,
)

if TYPE_CHECKING:
    from scripts.installer.platforms.base import BaseInstaller
    from scripts.installer.core.malcolm_config import MalcolmConfig
    from scripts.installer.core.install_context import InstallContext


BACK_LABEL = "Back"


class DialogInstallationMenu:
    def __init__(
        self,
        platform: "BaseInstaller",
        malcolm_config: "MalcolmConfig",
        install_context: "InstallContext",
        ui_mode: UserInterfaceMode = UserInterfaceMode.InteractionDialog,
    ) -> None:
        self.platform = platform
        self.mc = malcolm_config
        self.ctx = install_context
        self.ui_mode = ui_mode

        self.child_map: Dict[str, List[str]] = {}
        self._build_child_map()

    def _build_child_map(self) -> None:
        self.child_map = {}
        for key, item in self.ctx.items.items():
            parent = getattr(item, "ui_parent", None)
            if parent and parent in self.ctx.items:
                self.child_map.setdefault(parent, []).append(key)

    def run(self) -> Optional["InstallContext"]:
        try:
            ok = self._navigate(None)
            return self.ctx if ok else None
        except (KeyboardInterrupt, DialogCanceledException):
            return None

    def _visible_children(self, parent_key: Optional[str]) -> List[str]:
        if parent_key is None:
            keys = [k for k, v in self.ctx.items.items() if not getattr(v, "ui_parent", None)]
        else:
            keys = self.child_map.get(parent_key, [])
        return [k for k in keys if self.ctx.is_item_visible(k)]

    def _ordered_visible_children(self, parent_key: Optional[str]) -> List[str]:
        """Return visible children in a stable, view-model-driven order."""
        all_items = self.ctx.items.items()
        if parent_key is None:
            rows = build_rows_from_items(all_items, self.ctx)
            return [r.key for r in rows if r.visible and r.depth == 0]
        # For a specific parent, order direct children under that parent
        rows = build_rows_from_items(all_items, self.ctx, roots=[parent_key])
        ordered: List[str] = []
        for r in rows:
            if not r.visible:
                continue
            item = self.ctx.items.get(r.key)
            if item and getattr(item, "ui_parent", None) == parent_key:
                ordered.append(r.key)
        return ordered

    def _make_choice_list(
        self, keys: List[str], include_actions: bool, parent_key: Optional[str] = None
    ) -> Tuple[List[Tuple[str, str, bool]], Dict[str, str]]:
        choices: List[Tuple[str, str, bool]] = []
        tag_map: Dict[str, str] = {}
        for key in keys:
            item = self.ctx.items.get(key)
            if not item:
                continue
            current = ValueFormatter.format_config_value(item.label, item.get_value())
            desc = str(current)
            rb = (self.mc.get_value(KEY_CONFIG_ITEM_RUNTIME_BIN) or "").lower()
            tag = installation_item_display_label(key, item.label or key, rb)
            tag_map[tag] = f"KEY:{key}"
            choices.append((tag, desc, False))

            visible_children = [c for c in self._ordered_visible_children(key)]
            if visible_children:
                nav_tag = f" ↳ {item.label} Settings"
                tag_map[nav_tag] = f"GROUP:{key}"
                choices.append((nav_tag, "", False))

        if include_actions:
            sep = " ──────── Actions ────────"
            choices.append((sep, "", False))
            tag_map[sep] = "SEP"
            choices.extend([("Save and Continue", "", False), ("Cancel", "", False)])
            tag_map.update({"Save and Continue": "ACTION:save", "Cancel": "ACTION:exit"})
        return choices, tag_map

    def _navigate(self, parent_key: Optional[str]) -> bool:
        while True:
            keys = self._ordered_visible_children(parent_key)
            include_actions = parent_key is None
            choices, tag_map = self._make_choice_list(keys, include_actions, parent_key)
            if not choices:
                return True
            try:
                label = "Malcolm Installation Options" if parent_key is None else (self.ctx.items.get(parent_key).label or parent_key)
                prompt = f"{label}: choose an item to configure"
                result = InstallerChooseOne(
                    prompt,
                    choices=choices,
                    uiMode=self.ui_mode,
                    extraLabel=(None if parent_key is None else BACK_LABEL),
                )
            except DialogBackException:
                return True
            except DialogCanceledException:
                return False

            mapped = tag_map.get(result, "")
            if mapped == "SEP":
                continue
            if mapped == "ACTION:exit":
                return False
            if mapped == "ACTION:save":
                return True
            if mapped.startswith("GROUP:"):
                grp = mapped.split(":", 1)[1]
                if not self._navigate(grp):
                    return False
                continue
            if mapped.startswith("KEY:"):
                key = mapped.split(":", 1)[1]
                self._edit_item(key)
                continue
            self._edit_item(result)
            continue

    def _edit_item(self, key: str) -> None:
        item = self.ctx.items.get(key)
        if not item:
            return
        val = prompt_config_item_value(
            ui_mode=self.ui_mode,
            config_item=item,
            back_label=BACK_LABEL,
            show_preamble=True,
        )
        if val is None:
            return
        self.ctx.set_item_value(key, val)

        # no special branching; visibility of children handled by dependency rules
