#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2025 Battelle Energy Alliance, LLC.  All rights reserved.

"""Build and format search results consistently across UIs."""

from typing import List, Optional

try:
    from colorama import Fore, Style, init as colorama_init

    colorama_init(strip=False)
    _HAS_COLORAMA = True
except ImportError:  # pragma: no cover - colorama optional in some environments
    Fore = Style = None  # type: ignore
    _HAS_COLORAMA = False


def _dependency_label_string(malcolm_config, keys: List[str]) -> str:
    """Return dependency labels joined with arrows."""

    if not keys:
        return ""

    labels: List[str] = []
    for dep_key in keys:
        dep_item = malcolm_config.get_item(dep_key)
        labels.append(dep_item.label if dep_item else dep_key)
    return " -> ".join(labels)


def _resolve_depends_on(
    malcolm_config, dep_chain: List[str], ui_parent: Optional[str]
) -> str:
    dep_text = _dependency_label_string(malcolm_config, dep_chain)
    if dep_text:
        return dep_text
    if ui_parent:
        parent_item = malcolm_config.get_item(ui_parent)
        return parent_item.label if parent_item else ui_parent
    return "None"


def format_search_results_text(
    malcolm_config,
    search_term: str,
    displayed_keys: List[str],
    debug_mode: bool = False,
    include_numbers: bool = True,
    colorize: bool = True,
) -> str:
    """Build a human-readable search results report matching TUI behavior.

    Args:
        malcolm_config: MalcolmConfig instance
        search_term: term to search keys/labels
        displayed_keys: flattened list of currently visible keys (for numbering)
        debug_mode: include extra details (counts summary)
        include_numbers: when True, prefix visible items with their menu number
        colorize: include ANSI color codes for status values when True

    Returns:
        Multi-line string representing the results
    """
    results = malcolm_config.search_items(search_term)
    if not results:
        return f"No configuration items found matching '{search_term}'"

    lines: List[str] = []
    lines.append(f"--- Search Results for '{search_term}' ---")

    visible_count = hidden_count = 0
    rows: List[str] = []

    names = [result["label"] or result["key"] for result in results]
    name_width = max(len("Name"), *(len(name) for name in names))
    status_values = {"visible", "hidden"}
    status_width = max(len("Status"), *(len(value) for value in status_values))
    item_width = max(len("Item"), 4)

    header = (
        f"{'Item':>{item_width}}  "
        f"{'Name':<{name_width}}  "
        f"{'Status':<{status_width}} "
        "Depends On"
    )
    rows.append(header)

    def format_status_cell(status: str) -> str:
        padded = status.ljust(status_width)
        if not colorize or not _HAS_COLORAMA:
            return padded

        if status == "visible":
            color = Fore.GREEN
        elif status == "hidden":
            color = Fore.RED
        else:
            color = ""

        reset = Style.RESET_ALL if color else ""
        return f"{color}{padded}{reset}"

    for result in results:
        key = result["key"]
        label = result["label"] or key
        visible = result["visible"]
        ui_parent = result["ui_parent"]
        dep_chain = result["dependency_chain"]

        status: str
        if visible:
            visible_count += 1
            status = "visible"
            depends_on = "None"
        else:
            hidden_count += 1
            status = "hidden"
            depends_on = _resolve_depends_on(malcolm_config, dep_chain, ui_parent)

        item_token = "-"
        if visible:
            if include_numbers:
                try:
                    item_number = displayed_keys.index(key) + 1
                    item_token = str(item_number)
                except ValueError:
                    item_token = "?."
            else:
                item_token = "-"
        else:
            item_token = "-."

        status_cell = format_status_cell(status)
        row = (
            f"{item_token:>{item_width}}  "
            f"{label:<{name_width}}  "
            f"{status_cell} "
            f"{depends_on}"
        )
        rows.append(row)

    lines.extend(rows)

    if debug_mode:
        total_count = visible_count + hidden_count
        summary = f"{visible_count} visible"
        if hidden_count:
            summary += f", {hidden_count} hidden"
        lines.append("")
        lines.append(f"Found {total_count} items: {summary}")
    else:
        lines.append("")
        if visible_count:
            lines.append(f"Found {visible_count} items you can configure now.")
        if hidden_count:
            lines.append(
                f"Found {hidden_count} hidden items - enable their dependencies to access them."
            )

    return "\n".join(lines)
