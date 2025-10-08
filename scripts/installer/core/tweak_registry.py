#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Tweak Registry

Centralized definitions for system tweaks and grouping used by the installer.
Execution remains in platform utilities; these are data-only.
"""

from typing import List, Dict

from scripts.installer.configs.constants.installation_item_keys import (
    KEY_INSTALLATION_ITEM_AUTO_TWEAKS,
)


def get_linux_tweak_definitions() -> List[Dict]:
    """Return tweak definitions for Linux platforms with grouping.

    Keys are strings consumed by platform tweak utilities and store items.
    """
    defs: List[Dict] = []

    # Coarse group under Auto Tweaks
    defs.append(
        {
            "id": "sysctl",
            "label": "Enable All Sysctl Settings",
            "ui_parent": KEY_INSTALLATION_ITEM_AUTO_TWEAKS,
            # children visible only when auto tweaks is disabled
            "metadata": {"visible_when_parent_disabled": KEY_INSTALLATION_ITEM_AUTO_TWEAKS},
        }
    )

    # Granular sysctl children under 'sysctl'
    sysctl_children = [
        ("fs.file-max", "File descriptor limit"),
        ("fs.inotify.max_user_watches", "Inotify user watches"),
        ("fs.inotify.max_queued_events", "Inotify event queue size"),
        ("fs.inotify.max_user_instances", "Inotify user instances"),
        ("vm.max_map_count", "Virtual memory map count"),
        ("vm.swappiness", "Swappiness"),
        ("vm.dirty_background_ratio", "Dirty background ratio"),
        ("vm.dirty_ratio", "Dirty ratio"),
        ("net.core.somaxconn", "Socket connection limits"),
        ("net.ipv4.tcp_retries2", "TCP retry configuration"),
    ]
    for name, label in sysctl_children:
        tweak_id = f"sysctl_{name.split('.')[-1].replace('-', '_')}"
        defs.append(
            {
                "id": tweak_id,
                "label": f"{label} ({name})",
                "ui_parent": "sysctl",
                # hide when "Enable All Sysctl Settings" is enabled
                "metadata": {"visible_when_parent_disabled": "sysctl"},
            }
        )

    # Other coarse-grained tweaks directly under Auto Tweaks
    for tid, label in [
        ("security_limits", "Security Limits (/etc/security/limits.d)"),
        ("systemd_limits", "Systemd Limits (/etc/systemd/system.conf.d)"),
        ("grub_cgroup", "GRUB Cgroup Parameters"),
        ("network_interface", "Optimize Capture Network Interface"),
    ]:
        defs.append(
            {
                "id": tid,
                "label": label,
                "ui_parent": KEY_INSTALLATION_ITEM_AUTO_TWEAKS,
                "metadata": {"visible_when_parent_disabled": KEY_INSTALLATION_ITEM_AUTO_TWEAKS},
            }
        )

    return defs
