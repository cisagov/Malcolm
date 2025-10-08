#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2025 Battelle Energy Alliance, LLC.  All rights reserved.

"""Prompt a ConfigItem value consistently across TUI/DUI."""

from typing import Optional, Any
from scripts.installer.core.config_item import ConfigItem
from scripts.installer.ui.shared.menu_builder import ValueFormatter

from scripts.malcolm_common import (
    InstallerAskForString,
    InstallerAskForPassword,
    InstallerYesOrNo,
    InstallerChooseOne,
    InstallerDisplayMessage,
    UserInterfaceMode,
    DialogBackException,
    DialogCanceledException,
)


def _format_current_value_for_preamble(value: Any, config_item: ConfigItem) -> str:
    if config_item.is_password and value:
        return "********"
    # Reuse shared scalar formatting so TUI/DUI remain consistent
    return ValueFormatter.format_config_value(config_item.label or "", value)


def prompt_config_item_value(
    *,
    ui_mode,
    config_item: ConfigItem,
    back_label: Optional[str] = None,
    show_preamble: bool = True,
) -> Optional[Any]:
    """Prompt the user for a new value for the given ConfigItem.

    The caller is responsible for applying/validating the returned value.

    Args:
        ui_mode: UserInterfaceMode to use with InstallerAsk* wrappers
        config_item: The ConfigItem to prompt
        back_label: Optional extra button label for dialog back navigation
        show_preamble: Whether to include current value and help text in prompt

    Returns:
        The new value or None if cancelled/backed out
    """
    help_text = config_item.question
    current_value = config_item.get_value()
    default_value = config_item.default_value

    # Build question with optional preamble
    if show_preamble and help_text:
        pre_line = f"{config_item.label} (current: {_format_current_value_for_preamble(current_value, config_item)})"
        q_line = str(help_text)
        question = f"{pre_line}\n{q_line}"
    else:
        question = config_item.label

    # 1) Choices (single-select)
    choices = config_item.choices
    if choices:
        display_choices = []
        tag_to_value = {}
        for ch in choices:
            # Preserve original value type in mapping
            orig_value = ch[0] if isinstance(ch, tuple) else ch
            tag = str(orig_value)
            text = ch[1] if isinstance(ch, tuple) and len(ch) > 1 else str(orig_value)
            selected = orig_value == current_value
            # Avoid noisy duplicate like "no        no" in both TUI and DUI
            if str(text).strip() == str(tag).strip():
                item_text = ""
            else:
                item_text = str(text)
            display_choices.append((str(tag), item_text, bool(selected)))
            tag_to_value[str(tag)] = orig_value

        # Build prompt text and optional preamble consistently across UIs
        preamble = (
            f"{config_item.label} (current: "
            f"{_format_current_value_for_preamble(current_value, config_item)})"
        )
        if ui_mode & UserInterfaceMode.InteractionInput:
            if show_preamble:
                print(preamble)
            prompt_text = "Enter choice number"
        else:
            # Dialog mode: prefer concise preamble instead of long question
            prompt_text = (
                preamble if show_preamble else (config_item.label or "Choose one")
            )

        try:
            selected = InstallerChooseOne(
                prompt_text,
                choices=display_choices,
                uiMode=ui_mode,
                extraLabel=back_label,
            )
        except (DialogBackException, DialogCanceledException):
            return None

        # Map string tag back to original type (bool/enum/string)
        return tag_to_value.get(str(selected), selected)

    # 2) Boolean
    if isinstance(default_value, bool):
        try:
            return InstallerYesOrNo(
                question, default=bool(current_value), uiMode=ui_mode
            )
        except (DialogBackException, DialogCanceledException):
            return None

    # 3) Password
    if config_item.is_password:
        try:
            return InstallerAskForPassword(
                question, default=str(current_value or ""), uiMode=ui_mode
            )
        except (DialogBackException, DialogCanceledException):
            return None

    # 4) String/Numeric/List with validation loop for ints
    while True:
        if isinstance(default_value, list) or isinstance(current_value, list):
            default_str = ",".join([str(x) for x in (current_value or [])])
        else:
            default_str = str(current_value or "")

        try:
            entry = InstallerAskForString(
                question, default=default_str, uiMode=ui_mode, extraLabel=back_label
            )
        except (DialogBackException, DialogCanceledException):
            return None

        if entry in (None, ""):
            return None

        if isinstance(default_value, list) or isinstance(current_value, list):
            parts = [p.strip() for p in entry.split(",")] if entry else []
            return [p for p in parts if p]
        # Determine numeric expectation from default/current value or widget hint
        try:
            from scripts.malcolm_constants import WidgetType
            is_number_widget = config_item.widget_type == WidgetType.NUMBER
        except Exception:
            is_number_widget = False

        if isinstance(default_value, int) or isinstance(current_value, int) or is_number_widget:
            try:
                return int(entry)
            except Exception:
                InstallerDisplayMessage(
                    "Invalid integer. Please enter a valid number.", uiMode=ui_mode
                )
                # loop again
                continue

        return entry
