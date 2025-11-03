#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2025 Battelle Energy Alliance, LLC.  All rights reserved.

"""Shared helpers for deciding whether to apply installer tweaks.

Centralizes common logic used by multiple tweak steps to keep code DRY
and avoid repeating simple context checks in each module.
"""

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from scripts.installer.core.install_context import InstallContext


def should_apply_tweak(ctx: "InstallContext", tweak_id: str) -> bool:
    """Return True when a given tweak should be applied.

    Applies when global auto_tweaks is enabled or when the tweak is
    explicitly selected in the install context decisions.
    """
    if ctx.auto_tweaks:
        return True
    try:
        val = ctx.get_item_value(tweak_id)
        return bool(val)
    except Exception:
        return False
