#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2026 Battelle Energy Alliance, LLC.  All rights reserved.

"""Dialog-based configuration menu using python3-dialog."""

from typing import Dict, List, Optional, Tuple, TYPE_CHECKING

from scripts.malcolm_common import (
    InstallerAskForString,
    InstallerChooseOne,
    InstallerDisplayMessage,
    InstallerYesOrNo,
    UserInterfaceMode,
    DialogBackException,
    DialogCanceledException,
)
from scripts.installer.utils.logger_utils import InstallerLogger
from scripts.installer.configs.constants.constants import MAIN_MENU_KEYS
from scripts.installer.ui.shared.menu_builder import ValueFormatter
from scripts.installer.ui.shared.store_view_model import build_rows_from_items, build_child_map
from scripts.installer.ui.shared.search_utils import (
    find_gating_ancestor,
    format_menu_path,
    group_nav_label,
    strip_group_label,
)
from scripts.installer.ui.shared.prompt_utils import prompt_config_item_value
from scripts.installer.utils.exceptions import (
    ConfigValueValidationError,
    ConfigItemNotFoundError,
)

if TYPE_CHECKING:
    from scripts.installer.core.malcolm_config import MalcolmConfig
    from scripts.installer.core.install_context import InstallContext


BACK_LABEL = "Back"


class DialogConfigurationMenu:
    def __init__(
        self,
        malcolm_config: "MalcolmConfig",
        install_context: "InstallContext",
        main_menu_keys: List[str],
        debug_mode: bool = False,
        ui_mode: UserInterfaceMode = UserInterfaceMode.InteractionDialog,
    ) -> None:
        self.mc = malcolm_config
        self.ctx = install_context
        self.main_menu_keys = main_menu_keys or MAIN_MENU_KEYS
        self.debug_mode = debug_mode
        self.ui_mode = ui_mode
        self.child_map: Dict[str, List[str]] = build_child_map(self.mc.get_all_config_items().items())

    def run(self) -> bool:
        try:
            return self._navigate(None)
        except (KeyboardInterrupt, DialogCanceledException):
            return False

    def _ordered_visible_children(self, parent_key: Optional[str]) -> List[str]:
        """Return visible children in a stable, view-model-driven order."""
        all_items = self.mc.get_all_config_items().items()
        if parent_key is None:
            rows = build_rows_from_items(all_items, self.mc, roots=self.main_menu_keys)
            return [r.key for r in rows if r.visible and r.depth == 0]
        # For a specific parent, order direct children under that parent
        rows = build_rows_from_items(all_items, self.mc, roots=[parent_key])
        ordered = []
        for r in rows:
            if not r.visible:
                continue
            item = self.mc.get_item(r.key)
            if item and item.ui_parent == parent_key:
                ordered.append(r.key)
        return ordered

    def _make_choice_list(
        self, keys: List[str], include_actions: bool, parent_key: Optional[str] = None
    ) -> Tuple[List[Tuple[str, str, bool]], Dict[str, str]]:
        choices: List[Tuple[str, str, bool]] = []
        tag_map: Dict[str, str] = {}
        for key in keys:
            item = self.mc.get_item(key)
            if not item:
                continue
            value_display = ValueFormatter.format_config_value(item.label, item.get_value())
            desc = value_display if isinstance(value_display, str) else str(value_display)
            tag = item.label or key
            # map displayed tag back to real key
            tag_map[tag] = f"KEY:{key}"
            choices.append((tag, desc, False))

            # if this item has visible children, offer a separate entry to navigate
            # into its submenu without conflating it with the parent value editor
            visible_children = [c for c in self.child_map.get(key, []) if self.mc.is_item_visible(c)]
            if visible_children:
                # visually indent group navigation entries to indicate dependency
                nav_tag = " ↳ " + group_nav_label(item.label)
                tag_map[nav_tag] = f"GROUP:{key}"
                choices.append((nav_tag, "", False))

        if include_actions:
            # add a non-selectable-looking separator label before actions
            sep_tag = " ──────── Actions ────────"
            choices.append((sep_tag, "", False))
            tag_map[sep_tag] = "SEP"
            action_items = [
                ("Save and Continue", "", False),
                ("Where Is…? (search)", "", False),
                ("Exit Installer", "", False),
            ]
            choices.extend(action_items)
            tag_map.update(
                {
                    "Save and Continue": "ACTION:save",
                    "Where Is…? (search)": "ACTION:search",
                    "Exit Installer": "ACTION:exit",
                }
            )
        return choices, tag_map

    def _navigate(self, parent_key: Optional[str]) -> bool:
        while True:
            keys = self._ordered_visible_children(parent_key)
            include_actions = parent_key is None
            choices, tag_map = self._make_choice_list(keys, include_actions, parent_key)

            if not choices:
                return True if parent_key is None else True

            try:
                label = "Malcolm Configuration" if parent_key is None else self.mc.get_item(parent_key).label
                prompt = strip_group_label(label) + ": select an item to configure"
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
            if mapped == "ACTION:search":
                self._handle_search()
                continue

            # selected a key
            if mapped.startswith("KEY:"):
                key = mapped.split(":", 1)[1]
            elif mapped.startswith("GROUP:"):
                grp_key = mapped.split(":", 1)[1]
                if not self._navigate(grp_key):
                    return False
                continue
            else:
                # fallback – shouldn't happen
                key = result
            # editing a key always prompts for value; navigation occurs via GROUP entries
            self._prompt_for_item_value(key)
            continue

    def _prompt_for_item_value(self, key: str) -> None:
        item = self.mc.get_item(key)
        if not item:
            return

        while True:
            try:
                new_value = prompt_config_item_value(
                    ui_mode=self.ui_mode,
                    config_item=item,
                    back_label=BACK_LABEL,
                    show_preamble=True,
                )
            except (DialogBackException, DialogCanceledException):
                return

            if new_value is None:
                return

            try:
                self.mc.set_value(key, new_value)
            except ConfigValueValidationError as e:
                InstallerDisplayMessage(str(e), uiMode=self.ui_mode)
                # let user try again
                continue
            except ConfigItemNotFoundError as e:
                InstallerLogger.error(str(e))
                return

            return

    def _handle_search(self) -> None:
        """Search for settings and let the user jump straight to one.

        Results are offered as a menu. Each entry shows the path of submenus
        that leads to the item, so the user can also find it by hand. Picking a
        visible item opens its editor; picking a hidden one offers to edit the
        setting that is hiding it first.
        """
        try:
            term = InstallerAskForString("Enter search term:", default="", uiMode=self.ui_mode)
        except (DialogBackException, DialogCanceledException):
            return
        term = (term or "").strip()
        if not term:
            return

        while True:
            # re-run every pass: editing a result can change what is visible
            results = self.mc.search_items(term)
            if not results:
                InstallerDisplayMessage(f"No configuration items found matching '{term}'", uiMode=self.ui_mode)
                return

            choices, tag_map = self._make_search_choice_list(results)
            hidden_count = sum(1 for r in results if not r["visible"])
            prompt = f"Settings matching '{term}'. Select one to go to it."
            if hidden_count:
                prompt += f"\n{hidden_count} hidden until a setting above them is changed."
            try:
                selected = InstallerChooseOne(
                    prompt,
                    choices=choices,
                    uiMode=self.ui_mode,
                    extraLabel=BACK_LABEL,
                )
            except (DialogBackException, DialogCanceledException):
                return

            key = tag_map.get(selected)
            if key:
                self._go_to_search_result(key)

    def _make_search_choice_list(self, results: List[dict]) -> Tuple[List[Tuple[str, str, bool]], Dict[str, str]]:
        """Build radiolist choices for search results, grouped by menu location."""
        entries = []
        for result in results:
            key = result["key"]
            entries.append((not result["visible"], format_menu_path(self.mc, key), result["label"] or key, key))
        # visible first, then cluster by location so siblings sit together
        entries.sort(key=lambda e: (e[0], e[1].lower(), e[2].lower()))

        choices: List[Tuple[str, str, bool]] = []
        tag_map: Dict[str, str] = {}
        for hidden, path, label, key in entries:
            tag = label
            suffix = 2
            while tag in tag_map:
                tag = f"{label} ({suffix})"
                suffix += 1
            tag_map[tag] = key
            choices.append((tag, f"(hidden) {path}" if hidden else path, False))
        return choices, tag_map

    def _go_to_search_result(self, key: str) -> None:
        """Open a search result, revealing it first if it is hidden."""
        target = self.mc.get_item(key)
        if not target:
            return
        target_label = target.label or key

        while not self.mc.is_item_visible(key):
            gate_key = find_gating_ancestor(self.mc, key)
            gate = self.mc.get_item(gate_key) if gate_key else None
            if not gate:
                InstallerDisplayMessage(
                    f"{target_label} can't be shown with the current settings.\n\n"
                    f"Location: {format_menu_path(self.mc, key)}",
                    uiMode=self.ui_mode,
                )
                return

            gate_label = gate.label or gate_key
            gate_value = ValueFormatter.format_config_value(gate_label, gate.get_value())
            try:
                proceed = InstallerYesOrNo(
                    f"{target_label} only appears after {gate_label} is changed "
                    f"(it's set to {gate_value} now).\n\n"
                    f"Location: {format_menu_path(self.mc, key)}\n\n"
                    f"Edit {gate_label} now?",
                    default=True,
                    uiMode=self.ui_mode,
                )
            except (DialogBackException, DialogCanceledException):
                return
            if not proceed:
                return

            before = gate.get_value()
            self._prompt_for_item_value(gate_key)
            if gate.get_value() == before:
                # user backed out or kept the old value; don't nag in a loop
                return

        self._prompt_for_item_value(key)
