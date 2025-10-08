#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from dataclasses import dataclass
from typing import Any, Iterable, List, Tuple, Dict, Optional

from scripts.installer.core.config_item import ConfigItem


@dataclass
class StoreRow:
    key: str
    label: str
    value_formatted: Any
    choices: list
    visible: bool
    ui_parent: str | None
    editable: bool = True
    depth: int = 0
    prefix: str = ""


def build_rows_from_items(
    items: Iterable[Tuple[str, ConfigItem]],
    store,
    *,
    roots: Optional[List[str]] = None,
) -> List[StoreRow]:
    """Build visible rows from a store for UI rendering with stable grouping/order."""
    rows: List[StoreRow] = []
    try:
        from scripts.installer.core.transform_registry import apply_outbound
    except Exception:
        def apply_outbound(k: str, v: Any) -> Any:  # type: ignore
            return v

    # Materialize input and build quick lookups
    material: List[Tuple[str, ConfigItem]] = list(items)
    item_by_key: Dict[str, ConfigItem] = {k: it for k, it in material}

    # Build parent → children map preserving input order; fall back to label sort within siblings
    children: Dict[str, List[str]] = {}
    top_level: List[str] = []

    for key, item in material:
        parent = item.ui_parent
        if parent and parent in item_by_key:
            children.setdefault(parent, []).append(key)
        else:
            top_level.append(key)

    def _sorted_keys(keys: List[str]) -> List[str]:
        try:
            return sorted(keys, key=lambda k: (item_by_key[k].label or k).lower())
        except Exception:
            return keys

    def walk(k: str, depth: int, ancestors_last: List[bool]) -> None:
        it = item_by_key.get(k)
        if not it:
            return
        vis = bool(store.is_item_visible(k))
        # Build tree prefix using ancestors' lastness
        prefix_parts: List[str] = []
        for is_last in ancestors_last[:-1]:
            prefix_parts.append("    " if is_last else "│   ")
        if ancestors_last:
            prefix_parts.append("└── " if ancestors_last[-1] else "├── ")
        prefix = "".join(prefix_parts)
        rows.append(
            StoreRow(
                key=k,
                label=it.label or k,
                value_formatted=apply_outbound(k, it.get_value()),
                choices=it.choices or [],
                visible=vis,
                ui_parent=it.ui_parent,
                editable=True,
                depth=depth,
                prefix=prefix,
            )
        )
        # Only consider visible children for connector correctness
        vis_children = [ck for ck in children.get(k, []) if store.is_item_visible(ck)]
        ordered = _sorted_keys(vis_children)
        for idx, child_key in enumerate(ordered):
            is_last = idx == (len(ordered) - 1)
            walk(child_key, depth + 1, ancestors_last + [is_last])

    # Determine ordered top-level keys
    if roots:
        ordered_top = [k for k in roots if k in item_by_key]
    else:
        ordered_top = _sorted_keys(top_level)

    # Traverse top-level then their children; only render visible tops
    visible_tops = [kk for kk in ordered_top if store.is_item_visible(kk)]
    for idx, k in enumerate(visible_tops):
        is_last = idx == (len(visible_tops) - 1)
        walk(k, 0, [is_last])

    return rows
