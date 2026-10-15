#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2026 Battelle Energy Alliance, LLC.  All rights reserved.

"""Read-only memory preflight for installations of the full Malcolm stack."""

import sys
from typing import Optional


MINIMUM_MALCOLM_RAM_GIB = 24


def linux_swap_total_kib(meminfo_path: str = '/proc/meminfo') -> Optional[int]:
    """Return configured swap on Linux, or None if it cannot be determined."""
    if not sys.platform.startswith('linux'):
        return None
    try:
        with open(meminfo_path, 'r', encoding='utf-8') as meminfo:
            for line in meminfo:
                if line.startswith('SwapTotal:'):
                    fields = line.split()
                    if len(fields) >= 2:
                        return int(fields[1])
    except (OSError, ValueError):
        pass
    return None


def low_memory_warning(total_ram_gib: object, swap_kib: Optional[int] = None) -> Optional[str]:
    """Describe an unsupported host size without modifying heap settings."""
    try:
        ram_gib = float(total_ram_gib)
    except (TypeError, ValueError):
        return None

    if not (0 < ram_gib < MINIMUM_MALCOLM_RAM_GIB):
        return None

    warning = (
        f'Host has {ram_gib:g} GiB RAM. The full Malcolm stack requires at least '
        f'{MINIMUM_MALCOLM_RAM_GIB} GiB (32 GiB recommended). '
        'This configuration is below the documented minimum and may be unstable '
        'or experience out-of-memory kills.'
    )
    if swap_kib == 0:
        warning += ' No swap was detected, increasing the risk of out-of-memory kills.'
    elif swap_kib is not None and swap_kib > 0:
        warning += ' Swap is configured, but cannot replace the required physical RAM.'

    return (
        warning
        + ' OpenSearch and Logstash heap defaults are unchanged; reducing those '
        'heaps alone will not make the full stack reliable. For evaluation only, '
        'consider disabling optional services such as NetBox or file scanning. '
        'See docs/system-requirements.md before deploying.'
    )
