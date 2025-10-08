#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2025 Battelle Energy Alliance, LLC.  All rights reserved.

"""Dump a developer-facing summary of the installer env mapping.

Outputs, per environment variable:
- map key (KEY_ENV_*)
- raw env var name
- owning .env file
- mapped ConfigItems (reverse targets) with explicit authoritative/derived roles
- summary role (authoritative/derived/mixed) from per-item tags

Usage:
- python3 -m scripts.installer.tools.dump_env_mapping --format table
- python3 -m scripts.installer.tools.dump_env_mapping --format json --verbose
"""

from __future__ import annotations

import argparse
import json
from typing import Any, Dict, List, Tuple

import os
import sys

# ensure repository root is on sys.path for direct execution
_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_REPO_ROOT = os.path.normpath(os.path.join(_THIS_DIR, "..", "..", ".."))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from scripts.installer.core import EnvMapper


def _roles_for_env_var(
    mapper, env_map_key: str, item_keys: List[str]
) -> Tuple[str, Dict[str, str]]:
    """Return overall role and per-item roles for an env var based on explicit tags.

    Overall role is authoritative when all mapped items are authoritative,
    derived when all are derived, otherwise mixed. When no mapping exists,
    returns ("n/a", {}).
    """
    ev = mapper.env_var_by_map_key.get(env_map_key)
    if ev is None:
        return "n/a", {}
    per_item: Dict[str, str] = {}
    roles = set()
    for ik in item_keys:
        role = "authoritative" if ev.is_authoritative_for(ik) else "derived"
        per_item[ik] = role
        roles.add(role)
    overall = (
        "authoritative"
        if roles == {"authoritative"}
        else ("derived" if roles == {"derived"} else "mixed")
    )
    return overall, per_item


def _build_summary(mapper, verbose: bool = False) -> List[Dict[str, Any]]:
    items: List[Dict[str, Any]] = []
    for env_map_key, env_var in sorted(
        mapper.env_var_by_map_key.items(), key=lambda kv: kv[0]
    ):
        overall_role, roles_by_item = _roles_for_env_var(
            mapper, env_map_key, env_var.config_items
        )
        entry: Dict[str, Any] = {
            "map_key": env_map_key,
            "env_var": env_var.variable_name,
            "env_file": env_var.file_name,
            "config_items": list(env_var.config_items),
            "role": overall_role,
            "roles_by_item": roles_by_item,
        }
        if getattr(env_var, "reverse_noop", False):
            entry["reverse_noop"] = True
        if verbose:
            # include precedence context per target item when available
            precedence_ctx: Dict[str, List[str]] = {}
            for item_key in env_var.config_items:
                prec = mapper.get_reverse_precedence_for_item(item_key)
                if prec:
                    precedence_ctx[item_key] = prec
            if precedence_ctx:
                entry["reverse_precedence"] = precedence_ctx
        items.append(entry)
    return items


def _print_table(rows: List[Dict[str, Any]]):
    # legend / explanation
    print("Installer Env Mapping – Reverse Import Legend")
    print("- authoritative: wins conflicts for its target setting during env import.")
    print(
        "  Reasoning: represents direct user choice (e.g., container runtime, live capture, explicit NetBox mode)."
    )
    print(
        "- derived: helper flags calculated from authoritative choices during forward generation; do not override them on import."
    )
    print(
        "  Examples: file watcher polling flags, rotated-PCAP flags, NetBox URL implying remote when mode absent."
    )
    print(
        "- reverse no-op: present in env for forward semantics, but intentionally skipped on reverse to avoid conflicts (e.g., syslog listen flags).\n"
    )

    # minimal fixed-width columns for readability
    headers = ["env_var", "map_key", "env_file", "role", "reverse_noop", "targets"]
    col_widths = {h: len(h) for h in headers}
    for r in rows:
        col_widths["env_var"] = max(col_widths["env_var"], len(r["env_var"]))
        col_widths["map_key"] = max(col_widths["map_key"], len(r["map_key"]))
        col_widths["env_file"] = max(col_widths["env_file"], len(r["env_file"]))
        col_widths["role"] = max(col_widths["role"], len(r["role"]))
        col_widths["reverse_noop"] = max(
            col_widths["reverse_noop"],
            len("yes") if r.get("reverse_noop") else len("no"),
        )
        # Build a compact targets string: item(A)/item(D)
        targets_str = ",".join(
            f"{ik}({'A' if r.get('roles_by_item', {}).get(ik) == 'authoritative' else 'D'})"
            for ik in r["config_items"]
        )
        r["_targets_str"] = targets_str
        col_widths["targets"] = max(
            col_widths.get("targets", len("targets")), len(targets_str)
        )

    def fmt(h: str, v: str) -> str:
        return v.ljust(col_widths[h])

    header_line = "  ".join(fmt(h, h) for h in headers)
    print(header_line)
    print("-" * len(header_line))
    for r in rows:
        line = "  ".join(
            [
                fmt("env_var", r["env_var"]),
                fmt("map_key", r["map_key"]),
                fmt("env_file", r["env_file"]),
                fmt("role", r["role"]),
                fmt("reverse_noop", "yes" if r.get("reverse_noop") else "no"),
                fmt("targets", r.get("_targets_str", "")),
            ]
        )
        print(line)


def main():
    parser = argparse.ArgumentParser(description="Dump installer env mapping summary")
    parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Include reverse precedence breakdown per item",
    )
    args = parser.parse_args()

    mapper = EnvMapper()
    rows = _build_summary(mapper, verbose=args.verbose)

    if args.format == "json":
        print(json.dumps(rows, indent=2, sort_keys=False))
    else:
        _print_table(rows)


if __name__ == "__main__":
    main()
