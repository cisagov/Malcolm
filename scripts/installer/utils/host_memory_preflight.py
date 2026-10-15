#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2026 Battelle Energy Alliance, LLC.  All rights reserved.

"""Read-only host memory check for running the full Malcolm stack locally."""

import sys
from typing import Optional

from scripts.malcolm_constants import (
    DATABASE_MODE_ENUMS,
    PROFILE_MALCOLM,
    DatabaseMode,
    OrchestrationFramework,
)

MINIMUM_MALCOLM_RAM_GIB = 24
RECOMMENDED_MALCOLM_RAM_GIB = 32

# The OS reports somewhat less memory than is installed (Linux's MemTotal excludes memory
#   reserved at boot), so a host with exactly the minimum installed reads as roughly 23 GiB.
#   Only warn when detected memory is clearly below the minimum.
MEMORY_DETECTION_TOLERANCE_GIB = 2


def _opensearch_is_local(os_primary_mode) -> bool:
    """Mirror how the installer resolves the primary document store (unset means local)."""
    if not os_primary_mode:
        return True
    if isinstance(os_primary_mode, DatabaseMode):
        return os_primary_mode == DatabaseMode.OpenSearchLocal
    if isinstance(os_primary_mode, str):
        return DATABASE_MODE_ENUMS.get(os_primary_mode, DatabaseMode.DatabaseUnset) == DatabaseMode.OpenSearchLocal
    return False


def host_memory_check_applies(profile, orchestration_mode, os_primary_mode) -> bool:
    """The minimum describes the full stack with a local OpenSearch on this host.

    It doesn't apply to capture-only Hedgehog, to Kubernetes (where the workload is scheduled
    elsewhere), or when the primary OpenSearch instance is remote.
    """
    return (
        (profile == PROFILE_MALCOLM)
        and (orchestration_mode != OrchestrationFramework.KUBERNETES)
        and _opensearch_is_local(os_primary_mode)
    )


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


def low_memory_warning(total_mem_bytes: object, swap_kib: Optional[int] = None) -> Optional[str]:
    """Return a warning for a host clearly below the minimum, or None (including when memory is unknown)."""
    try:
        total_bytes = int(total_mem_bytes)
    except (TypeError, ValueError):
        return None
    if total_bytes <= 0:
        return None

    total_gib = total_bytes / (1024**3)
    if total_gib >= (MINIMUM_MALCOLM_RAM_GIB - MEMORY_DETECTION_TOLERANCE_GIB):
        return None

    warning = (
        f'This host has about {max(1, round(total_gib))} GiB of RAM. Running the full Malcolm stack on it '
        f'requires at least {MINIMUM_MALCOLM_RAM_GIB} GiB ({RECOMMENDED_MALCOLM_RAM_GIB} GiB or more recommended). '
        'With less, services may be unstable or be stopped for running out of memory.'
    )
    if swap_kib == 0:
        warning += ' No swap space is configured, which makes running out of memory more likely.'
    elif isinstance(swap_kib, int) and swap_kib > 0:
        warning += ' Swap space is configured, but it does not substitute for physical RAM.'

    return f'{warning} See recommended system requirements in the Malcolm documentation'
