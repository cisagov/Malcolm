#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2025 Battelle Energy Alliance, LLC.  All rights reserved.

"""Shared label helpers for installer UIs.

Provides consistent display label adjustments across TUI/DUI, e.g.,
runtime-specific renaming for podman environments.
"""

from scripts.installer.configs.constants.installation_item_keys import (
    KEY_INSTALLATION_ITEM_DOCKER_COMPOSE_INSTALL_METHOD,
    KEY_INSTALLATION_ITEM_DOCKER_INSTALL_METHOD,
    KEY_INSTALLATION_ITEM_INSTALL_DOCKER_IF_MISSING,
    KEY_INSTALLATION_ITEM_TRY_DOCKER_REPOSITORY,
    KEY_INSTALLATION_ITEM_TRY_DOCKER_CONVENIENCE_SCRIPT,
)


def installation_item_display_label(key: str, base_label: str, runtime_bin: str) -> str:
    """Return a UI label for an installation item adjusted for runtime.

    For podman runtime, some Docker-specific items receive clearer wording.
    Otherwise, return the original label unchanged.
    """
    rb = (runtime_bin or "").lower()
    if not rb.startswith("podman"):
        return base_label

    if key == KEY_INSTALLATION_ITEM_DOCKER_COMPOSE_INSTALL_METHOD:
        return "Podman Compose Installation Method"
    if key == KEY_INSTALLATION_ITEM_DOCKER_INSTALL_METHOD:
        return "Container Runtime Installation Method (Docker only)"
    if key == KEY_INSTALLATION_ITEM_INSTALL_DOCKER_IF_MISSING:
        return "Install Docker if Missing (Docker only)"
    if key == KEY_INSTALLATION_ITEM_TRY_DOCKER_REPOSITORY:
        return "Try Docker Repository Installation (Docker only)"
    if key == KEY_INSTALLATION_ITEM_TRY_DOCKER_CONVENIENCE_SCRIPT:
        return "Try Docker Convenience Script (Docker only)"

    return base_label
