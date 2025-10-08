#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from typing import Callable, Optional


def config_item_is_visible(config, key: str) -> bool:
    """Return visibility for a configuration item using store state."""
    item = config.get_item(key)
    return bool(item and item.is_visible)


def install_item_is_visible(
    ctx,
    key: str,
    item=None,
    *,
    orchestration_mode=None,
    runtime_bin: Optional[str] = None,
    image_archive_path: Optional[str] = None,
    get_value: Optional[Callable[[str], object]] = None,
    docker_installed: Optional[bool] = None,
    compose_available: Optional[bool] = None,
) -> bool:
    """Return True if an installation item should be visible.

    Uses context defaults but allows explicit overrides for tests.
    """
    # Resolve inputs from context when not provided
    orchestration_mode = orchestration_mode or getattr(ctx, "_orchestration_mode", None)
    runtime_bin = (runtime_bin or getattr(ctx, "_runtime_bin", None) or "").lower()
    image_archive_path = image_archive_path or getattr(ctx, "image_archive_path", None)
    if get_value is None:
        get_value = getattr(ctx, "get_item_value", None)
    if docker_installed is None:
        docker_installed = getattr(ctx, "_docker_installed", None)
    if compose_available is None:
        compose_available = getattr(ctx, "_compose_available", None)

    # Acquire item
    item = item or (ctx.items.get(key) if hasattr(ctx, "items") else None)
    if item is None:
        return False
    meta = item.metadata or {}

    # Kubernetes hides docker/podman-gated items
    try:
        from scripts.malcolm_constants import OrchestrationFramework

        if orchestration_mode == OrchestrationFramework.KUBERNETES:
            rt = meta.get("visible_when_runtime")
            if rt in ("docker", "podman"):
                return False
    except Exception:
        pass

    # hide when parent enabled (e.g., auto tweaks)
    vwp = meta.get("visible_when_parent_disabled")
    if vwp and callable(get_value):
        try:
            parent_val = bool(get_value(vwp))
            if parent_val:
                return False
        except Exception:
            pass

    rt = meta.get("visible_when_runtime")
    if not rt:
        base_visible = not (
            key == _lazy_key_load_images() and not image_archive_path
        )
    else:
        base_visible = (rt == "docker" and runtime_bin.startswith("docker")) or (
            rt == "podman" and runtime_bin.startswith("podman")
        )

    if not base_visible:
        return False

    # Additional tool-availability gating
    try:
        (
            KEY_INSTALLATION_ITEM_DOCKER_INSTALL_METHOD,
            KEY_INSTALLATION_ITEM_INSTALL_DOCKER_IF_MISSING,
            KEY_INSTALLATION_ITEM_TRY_DOCKER_REPOSITORY,
            KEY_INSTALLATION_ITEM_TRY_DOCKER_CONVENIENCE_SCRIPT,
            KEY_INSTALLATION_ITEM_DOCKER_COMPOSE_INSTALL_METHOD,
        ) = _lazy_docker_keys()
    except Exception:
        return True

    if runtime_bin.startswith("docker"):
        if docker_installed is True and key in (
            KEY_INSTALLATION_ITEM_DOCKER_INSTALL_METHOD,
            KEY_INSTALLATION_ITEM_INSTALL_DOCKER_IF_MISSING,
            KEY_INSTALLATION_ITEM_TRY_DOCKER_REPOSITORY,
            KEY_INSTALLATION_ITEM_TRY_DOCKER_CONVENIENCE_SCRIPT,
        ):
            return False
        if compose_available is True and key == KEY_INSTALLATION_ITEM_DOCKER_COMPOSE_INSTALL_METHOD:
            return False

    return True


def _lazy_key_load_images():
    from scripts.installer.configs.constants.installation_item_keys import (
        KEY_INSTALLATION_ITEM_LOAD_MALCOLM_IMAGES,
    )

    return KEY_INSTALLATION_ITEM_LOAD_MALCOLM_IMAGES


def _lazy_docker_keys():
    from scripts.installer.configs.constants.installation_item_keys import (
        KEY_INSTALLATION_ITEM_DOCKER_INSTALL_METHOD,
        KEY_INSTALLATION_ITEM_INSTALL_DOCKER_IF_MISSING,
        KEY_INSTALLATION_ITEM_TRY_DOCKER_REPOSITORY,
        KEY_INSTALLATION_ITEM_TRY_DOCKER_CONVENIENCE_SCRIPT,
        KEY_INSTALLATION_ITEM_DOCKER_COMPOSE_INSTALL_METHOD,
    )

    return (
        KEY_INSTALLATION_ITEM_DOCKER_INSTALL_METHOD,
        KEY_INSTALLATION_ITEM_INSTALL_DOCKER_IF_MISSING,
        KEY_INSTALLATION_ITEM_TRY_DOCKER_REPOSITORY,
        KEY_INSTALLATION_ITEM_TRY_DOCKER_CONVENIENCE_SCRIPT,
        KEY_INSTALLATION_ITEM_DOCKER_COMPOSE_INSTALL_METHOD,
    )

