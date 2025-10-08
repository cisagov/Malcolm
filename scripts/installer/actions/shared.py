#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Shared installer actions used by multiple platforms.

These helpers contain cross-platform logic that used to live under the
former steps/ modules. They keep behavior intact while removing the
platform-to-step indirection.
"""

from typing import Tuple, List, Optional

from scripts.installer.configs.constants.enums import InstallerResult
from scripts.installer.configs.constants.constants import (
    COMPOSE_FILE_GLOB,
    COMPOSE_FILENAME,
    COMPOSE_SUBCOMMAND,
    DOCKER_COMPOSE_STANDALONE,
    PODMAN_COMPOSE_STANDALONE,
    COMPOSE_UP_SUBCOMMAND,
    COMPOSE_DETACH_FLAG,
    USERNS_MODE_KEEP_ID,
    PODMAN_LOG_DRIVER,
    DOCKER_LOG_DRIVER,
    LABEL_MALCOLM_RULE,
    LABEL_MALCOLM_ENTRYPOINTS,
    LABEL_MALCOLM_CERTRESOLVER,
    LABEL_MALCOLM_SERVICE,
    LABEL_MALCOLM_SERVICE_PORT,
    LABEL_OS_RULE,
    LABEL_OS_ENTRYPOINTS,
    LABEL_OS_CERTRESOLVER,
    LABEL_OS_SERVICE,
    LABEL_OS_SERVICE_PORT,
    TRAEFIK_ENABLE,
    SERVICE_NAME_MALCOLM,
    SERVICE_NAME_OSMALCOLM,
    SERVICE_PORT_MALCOLM,
    SERVICE_PORT_OSMALCOLM,
    DEFAULT_RESTART_POLICY,
    PCAP_CONTAINER_PATH,
    ZEEK_LOG_CONTAINER_PATH,
    SURICATA_LOG_CONTAINER_PATH,
    OPENSEARCH_DATA_CONTAINER_PATH,
    DEFAULT_PCAP_DIR,
    DEFAULT_ZEEK_LOG_DIR,
    DEFAULT_SURICATA_LOG_DIR,
    DEFAULT_INDEX_DIR,
    DEFAULT_INDEX_SNAPSHOT_DIR,
    SSL_CA_TRUST_DIR,
)


def filesystem_prepare(malcolm_config, config_dir: str, platform, ctx, logger) -> InstallerResult:
    """Ensure configuration directory exists (idempotent, respects dry-run)."""
    import os
    try:
        if not platform.should_write_files():
            logger.info(f"Dry run: would create configuration directory: {config_dir}")
            return InstallerResult.SKIPPED
        if os.path.isdir(config_dir):
            return InstallerResult.SUCCESS
        os.makedirs(config_dir, exist_ok=True)
        logger.info(f"Created configuration directory: {config_dir}")
        return InstallerResult.SUCCESS
    except Exception as e:
        logger.error(f"Filesystem preparation failed: {e}")
        return InstallerResult.FAILURE


def _clear_known_traefik_labels(labels: dict) -> None:
    for key in (
        LABEL_MALCOLM_RULE,
        LABEL_MALCOLM_ENTRYPOINTS,
        LABEL_MALCOLM_CERTRESOLVER,
        LABEL_MALCOLM_SERVICE,
        LABEL_MALCOLM_SERVICE_PORT,
        LABEL_OS_RULE,
        LABEL_OS_ENTRYPOINTS,
        LABEL_OS_CERTRESOLVER,
        LABEL_OS_SERVICE,
        LABEL_OS_SERVICE_PORT,
    ):
        labels.pop(key, None)


def _apply_malcolm_labels(labels: dict, host: str, entrypoint: str, resolver: str) -> None:
    labels[LABEL_MALCOLM_RULE] = f"Host(`{host}`)"
    labels[LABEL_MALCOLM_ENTRYPOINTS] = entrypoint
    labels[LABEL_MALCOLM_CERTRESOLVER] = resolver
    labels[LABEL_MALCOLM_SERVICE] = SERVICE_NAME_MALCOLM
    labels[LABEL_MALCOLM_SERVICE_PORT] = SERVICE_PORT_MALCOLM


def _apply_osmalcolm_labels(labels: dict, host: str, entrypoint: str, resolver: str) -> None:
    labels[LABEL_OS_RULE] = f"Host(`{host}`)"
    labels[LABEL_OS_ENTRYPOINTS] = entrypoint
    labels[LABEL_OS_CERTRESOLVER] = resolver
    labels[LABEL_OS_SERVICE] = SERVICE_NAME_OSMALCOLM
    labels[LABEL_OS_SERVICE_PORT] = SERVICE_PORT_OSMALCOLM


def _is_opensearch_local_and_exposed(os_primary_mode, expose_opensearch: bool) -> bool:
    from scripts.malcolm_constants import DatabaseMode, DATABASE_MODE_ENUMS

    is_local = False
    if isinstance(os_primary_mode, DatabaseMode):
        is_local = os_primary_mode == DatabaseMode.OpenSearchLocal
    elif isinstance(os_primary_mode, str):
        try:
            is_local = (
                DATABASE_MODE_ENUMS.get(os_primary_mode, DatabaseMode.DatabaseUnset)
                == DatabaseMode.OpenSearchLocal
            )
        except Exception:
            is_local = False
    return bool(is_local and expose_opensearch)


def _select_install_path_and_compose_files(config_dir: str):
    import os, glob

    if any(glob.glob(os.path.join(config_dir, COMPOSE_FILE_GLOB))):
        malcolm_install_path = config_dir
    else:
        malcolm_install_path = os.path.dirname(config_dir)
    compose_files = glob.glob(os.path.join(malcolm_install_path, COMPOSE_FILE_GLOB))
    if not compose_files:
        malcolm_install_path = os.path.dirname(malcolm_install_path)
        compose_files = glob.glob(os.path.join(malcolm_install_path, "docker-compose*.yml"))
    return malcolm_install_path, compose_files


def _resolve_restart_policy(malcolm_config):
    from enum import Enum
    from scripts.installer.configs.constants.configuration_item_keys import (
        KEY_CONFIG_ITEM_MALCOLM_RESTART_POLICY,
    )

    restart_policy_value = (
        malcolm_config.get_value(KEY_CONFIG_ITEM_MALCOLM_RESTART_POLICY)
        or DEFAULT_RESTART_POLICY
    )
    return (
        restart_policy_value.value
        if isinstance(restart_policy_value, Enum)
        else str(restart_policy_value)
    )


def _update_services_runtime_settings(data: dict, runtime_bin: str, restart_policy: str, deep_set) -> None:
    services = data.get("services", {})
    for service in services:
        if runtime_bin.startswith("podman"):
            deep_set(data, ["services", service, "userns_mode"], USERNS_MODE_KEEP_ID)
            deep_set(data, ["services", service, "logging", "driver"], PODMAN_LOG_DRIVER)
        else:
            deep_set(data, ["services", service, "userns_mode"], None, deleteIfNone=True)
            deep_set(data, ["services", service, "logging", "driver"], DOCKER_LOG_DRIVER)
        deep_set(data, ["services", service, "restart"], restart_policy)


def _get_traefik_config(malcolm_config):
    from scripts.installer.configs.constants.configuration_item_keys import (
        KEY_CONFIG_ITEM_BEHIND_REVERSE_PROXY,
        KEY_CONFIG_ITEM_TRAEFIK_LABELS,
        KEY_CONFIG_ITEM_TRAEFIK_HOST,
        KEY_CONFIG_ITEM_TRAEFIK_OPENSEARCH_HOST,
        KEY_CONFIG_ITEM_TRAEFIK_ENTRYPOINT,
        KEY_CONFIG_ITEM_TRAEFIK_RESOLVER,
        KEY_CONFIG_ITEM_EXPOSE_OPENSEARCH,
        KEY_CONFIG_ITEM_OPENSEARCH_PRIMARY_MODE,
    )

    try:
        behind_reverse_proxy = bool(malcolm_config.get_value(KEY_CONFIG_ITEM_BEHIND_REVERSE_PROXY))
        traefik_labels_enabled = bool(malcolm_config.get_value(KEY_CONFIG_ITEM_TRAEFIK_LABELS))
        traefik_host = malcolm_config.get_value(KEY_CONFIG_ITEM_TRAEFIK_HOST) or ""
        traefik_os_host = malcolm_config.get_value(KEY_CONFIG_ITEM_TRAEFIK_OPENSEARCH_HOST) or ""
        traefik_entrypoint = malcolm_config.get_value(KEY_CONFIG_ITEM_TRAEFIK_ENTRYPOINT) or ""
        traefik_resolver = malcolm_config.get_value(KEY_CONFIG_ITEM_TRAEFIK_RESOLVER) or ""
        expose_opensearch = bool(malcolm_config.get_value(KEY_CONFIG_ITEM_EXPOSE_OPENSEARCH))
        os_primary_mode = malcolm_config.get_value(KEY_CONFIG_ITEM_OPENSEARCH_PRIMARY_MODE)
    except Exception:
        behind_reverse_proxy = traefik_labels_enabled = False
        traefik_host = traefik_os_host = traefik_entrypoint = traefik_resolver = ""
        expose_opensearch = False
        os_primary_mode = None
    return (
        behind_reverse_proxy,
        traefik_labels_enabled,
        traefik_host,
        traefik_os_host,
        traefik_entrypoint,
        traefik_resolver,
        expose_opensearch,
        os_primary_mode,
    )


def _apply_traefik_labels_if_present(data: dict, traefik_tuple, deep_get, deep_set) -> None:
    (
        behind_reverse_proxy,
        traefik_labels_enabled,
        traefik_host,
        traefik_os_host,
        traefik_entrypoint,
        traefik_resolver,
        expose_opensearch,
        os_primary_mode,
    ) = traefik_tuple

    if "services" in data and "nginx-proxy" in data["services"]:
        labels_path = ["services", "nginx-proxy", "labels"]
        labels_dict = deep_get(data, labels_path, {}) or {}
        _clear_known_traefik_labels(labels_dict)
        labels_dict[TRAEFIK_ENABLE] = bool(behind_reverse_proxy and traefik_labels_enabled)
        if labels_dict[TRAEFIK_ENABLE]:
            if len(traefik_host) > 1 and len(traefik_entrypoint) > 1 and len(traefik_resolver) > 1:
                _apply_malcolm_labels(labels_dict, traefik_host, traefik_entrypoint, traefik_resolver)
            if _is_opensearch_local_and_exposed(os_primary_mode, expose_opensearch):
                if len(traefik_os_host) > 1 and len(traefik_entrypoint) > 1 and len(traefik_resolver) > 1:
                    _apply_osmalcolm_labels(labels_dict, traefik_os_host, traefik_entrypoint, traefik_resolver)
        deep_set(data, labels_path, labels_dict)


def _remap_volumes(data: dict, replacements: List[tuple], deep_get, deep_set) -> None:
    for service_name, container_path, host_path in replacements:
        if service_name in data.get("services", {}):
            volumes = deep_get(data, ["services", service_name, "volumes"], [])
            if not volumes:
                continue
            updated = []
            for volume in volumes:
                if isinstance(volume, str) and container_path in volume:
                    parts = volume.split(":")
                    if len(parts) >= 2 and parts[1] == container_path:
                        parts[0] = host_path
                        updated.append(":".join(parts))
                    else:
                        updated.append(volume)
                else:
                    updated.append(volume)
            deep_set(data, ["services", service_name, "volumes"], updated)


def _apply_network_overrides(data: dict, network_name: Optional[str], deep_get, deep_set) -> None:
    if not network_name:
        return
    networks_config = deep_get(data, ["networks"], {})
    if not networks_config:
        return
    for network in networks_config:
        deep_set(data, ["networks", network, "external"], True)
        deep_set(data, ["networks", network, "name"], network_name)


def _write_or_log_changes(original: dict, data: dict, config_file: str, platform, logger, dump_yaml) -> None:
    changed = data != original
    if platform.should_write_files():
        if changed:
            dump_yaml(data, config_file)
            logger.info(f"Updated compose file: {config_file}")
        else:
            logger.info(f"No changes needed for compose file: {config_file}")
    else:
        if changed:
            logger.info(f"Dry run: would update compose file: {config_file}")
        else:
            logger.info(f"Dry run: no changes for compose file: {config_file}")


def update_ancillary(malcolm_config, config_dir: str, platform, ctx, logger) -> InstallerResult:
    """Update docker-compose files with runtime-specific settings."""
    # Ported from steps/ancillary.py (update_docker_compose_files + run wrapper)
    import os, glob
    from scripts.malcolm_common import DumpYaml, LoadYaml
    from scripts.malcolm_utils import deep_set, deep_get
    from scripts.installer.configs.constants.configuration_item_keys import (
        KEY_CONFIG_ITEM_RUNTIME_BIN,
        KEY_CONFIG_ITEM_PCAP_DIR,
        KEY_CONFIG_ITEM_ZEEK_LOG_DIR,
        KEY_CONFIG_ITEM_SURICATA_LOG_DIR,
        KEY_CONFIG_ITEM_INDEX_DIR,
        KEY_CONFIG_ITEM_INDEX_SNAPSHOT_DIR,
        KEY_CONFIG_ITEM_CONTAINER_NETWORK_NAME,
    )

    try:
        # Prefer the provided directory when it contains compose files; otherwise look at its parent
        malcolm_install_path, compose_files = _select_install_path_and_compose_files(config_dir)
        if not compose_files:
            logger.warning("Could not locate docker-compose files for orchestration updates")
            return InstallerResult.SUCCESS

        if platform.is_dry_run():
            logger.info(
                f"Dry run: would update orchestration (docker-compose) files in {malcolm_install_path}: "
                + ", ".join(sorted(os.path.basename(f) for f in compose_files))
            )
            runtime_bin = malcolm_config.get_value(KEY_CONFIG_ITEM_RUNTIME_BIN) or "docker"
            restart_policy = _resolve_restart_policy(malcolm_config)
            logger.info(
                f"Dry run: would set container runtime adjustments for {runtime_bin} and restart policy {restart_policy}"
            )
            return InstallerResult.SKIPPED

        logger.info(
            f"Updating orchestration (docker-compose) files in {malcolm_install_path}..."
        )
        logger.info(
            f"Found {len(compose_files)} docker-compose files: {[os.path.basename(f) for f in compose_files]}"
        )

        # Load/write per file
        runtime_bin = malcolm_config.get_value(KEY_CONFIG_ITEM_RUNTIME_BIN) or "docker"
        restart_policy = _resolve_restart_policy(malcolm_config)
        pcap_dir = malcolm_config.get_value(KEY_CONFIG_ITEM_PCAP_DIR) or DEFAULT_PCAP_DIR
        zeek_log_dir = malcolm_config.get_value(KEY_CONFIG_ITEM_ZEEK_LOG_DIR) or DEFAULT_ZEEK_LOG_DIR
        suricata_log_dir = (
            malcolm_config.get_value(KEY_CONFIG_ITEM_SURICATA_LOG_DIR) or DEFAULT_SURICATA_LOG_DIR
        )
        index_dir = malcolm_config.get_value(KEY_CONFIG_ITEM_INDEX_DIR) or DEFAULT_INDEX_DIR
        index_snapshot_dir = (
            malcolm_config.get_value(KEY_CONFIG_ITEM_INDEX_SNAPSHOT_DIR) or DEFAULT_INDEX_SNAPSHOT_DIR
        )
        network_name = malcolm_config.get_value(KEY_CONFIG_ITEM_CONTAINER_NETWORK_NAME)

        import copy
        for config_file in compose_files:
            data = LoadYaml(config_file)
            if data is None or "services" not in data:
                continue
            original = copy.deepcopy(data)
            _update_services_runtime_settings(data, runtime_bin, restart_policy, deep_set)

            # Traefik label handling
            traefik_cfg = _get_traefik_config(malcolm_config)
            _apply_traefik_labels_if_present(data, traefik_cfg, deep_get, deep_set)

            # Volume remaps
            volume_replacements = [
                ("arkime", PCAP_CONTAINER_PATH, pcap_dir),
                ("arkime-live", PCAP_CONTAINER_PATH, pcap_dir),
                ("zeek", ZEEK_LOG_CONTAINER_PATH, zeek_log_dir),
                ("zeek-live", ZEEK_LOG_CONTAINER_PATH, zeek_log_dir),
                ("suricata", SURICATA_LOG_CONTAINER_PATH, suricata_log_dir),
                ("suricata-live", SURICATA_LOG_CONTAINER_PATH, suricata_log_dir),
                ("opensearch", OPENSEARCH_DATA_CONTAINER_PATH, index_dir),
                ("opensearch-backup", OPENSEARCH_DATA_CONTAINER_PATH, index_snapshot_dir),
            ]
            _remap_volumes(data, volume_replacements, deep_get, deep_set)

            _apply_network_overrides(data, network_name, deep_get, deep_set)

            _write_or_log_changes(original, data, config_file, platform, logger, DumpYaml)

        return InstallerResult.SUCCESS
    except Exception as e:
        logger.error(f"Error updating docker-compose files: {e}")
        return InstallerResult.FAILURE


def ensure_ssl_env(malcolm_config, config_dir: str, platform, ctx, logger) -> InstallerResult:
    """Ensure ssl.env exists in the configuration directory."""
    import os, shutil
    from scripts.installer.configs.constants.config_env_files import ENV_FILE_SSL
    from scripts.malcolm_utils import get_default_config_dir
    try:
        if not config_dir:
            logger.warning("SSL env step: configuration directory not provided; skipping.")
            return InstallerResult.SKIPPED
        ssl_env_path = os.path.join(config_dir, ENV_FILE_SSL)
        if not os.path.isdir(config_dir):
            if platform.is_dry_run():
                logger.info(f"Dry run: would create configuration directory: {config_dir}")
                logger.info(f"Dry run: would create {ENV_FILE_SSL} in configuration directory.")
                return InstallerResult.SKIPPED
            os.makedirs(config_dir, exist_ok=True)
        if os.path.isfile(ssl_env_path):
            logger.info("ssl.env already present; leaving unchanged.")
            return InstallerResult.SKIPPED
        if platform.is_dry_run():
            logger.info(f"Dry run: would create {ENV_FILE_SSL} in configuration directory.")
            return InstallerResult.SKIPPED
        try:
            templates_dir = get_default_config_dir()
            template_ssl = os.path.join(templates_dir, ENV_FILE_SSL)
            if os.path.isfile(template_ssl):
                shutil.copyfile(template_ssl, ssl_env_path)
                logger.info("Created ssl.env from template.")
                return InstallerResult.SUCCESS
        except Exception:
            pass
        with open(ssl_env_path, "w") as f:
            f.write("# Shared TLS-related environment variables used by multiple services\n")
            f.write("PUSER_CA_TRUST=/var/local/ca-trust\n")
        logger.info("Created ssl.env in configuration directory.")
        return InstallerResult.SUCCESS
    except Exception as e:
        logger.error(f"Failed to ensure ssl.env: {e}")
        return InstallerResult.FAILURE


def _calculate_optimal_resources(total_memory_gigs: float, total_cores: int, orch_mode):
    from scripts.malcolm_constants import OrchestrationFramework

    if orch_mode == OrchestrationFramework.DOCKER_COMPOSE:
        if total_memory_gigs >= 63.0:
            os_memory, ls_memory = "24g", "3g"
        elif total_memory_gigs >= 31.0:
            os_memory, ls_memory = "16g", "2500m"
        elif total_memory_gigs >= 15.0:
            os_memory, ls_memory = "10g", "2500m"
        elif total_memory_gigs >= 11.0:
            os_memory, ls_memory = "6g", "2g"
        elif total_memory_gigs >= 7.0:
            os_memory, ls_memory = "4g", "2g"
        elif total_memory_gigs > 0.0:
            os_memory, ls_memory = "3500m", "2g"
        else:
            os_memory, ls_memory = "8g", "3g"
    else:
        os_memory, ls_memory = "16g", "3g"
    if orch_mode == OrchestrationFramework.DOCKER_COMPOSE:
        ls_workers = 6 if total_cores > 16 else 4 if total_cores >= 12 else 3
    else:
        ls_workers = 6
    return os_memory, ls_memory, ls_workers


def apply_runtime_config(malcolm_config, config_dir: str, platform, ctx, logger) -> Tuple[InstallerResult, str]:
    """Apply Malcolm runtime memory/worker settings based on system resources."""
    # Ported from steps/malcolm_runtime_config.py
    from scripts.installer.configs.constants.configuration_item_keys import (
        KEY_CONFIG_ITEM_MALCOLM_PROFILE,
        KEY_CONFIG_ITEM_OS_MEMORY,
        KEY_CONFIG_ITEM_LS_MEMORY,
        KEY_CONFIG_ITEM_LS_WORKERS,
    )

    try:
        orch_mode = platform.orchestration_mode
        total_memory_gigs = platform.total_memory_gigs or 0.0
        total_cores = platform.total_cores or 0
        if total_cores <= 0:
            total_cores = 1
        os_memory, ls_memory, ls_workers = _calculate_optimal_resources(total_memory_gigs, total_cores, orch_mode)
        if ctx.auto_tweaks or ctx.apply_memory_settings:
            if platform.is_dry_run():
                logger.info("Dry run: would apply optimal memory and worker settings to Malcolm configuration")
                return InstallerResult.SKIPPED, "Runtime configuration skipped (dry run)"
            malcolm_profile = malcolm_config.get_value(KEY_CONFIG_ITEM_MALCOLM_PROFILE) or "malcolm"
            if malcolm_profile == "malcolm" and os_memory:
                malcolm_config.set_value(KEY_CONFIG_ITEM_OS_MEMORY, os_memory)
            if ls_memory:
                malcolm_config.set_value(KEY_CONFIG_ITEM_LS_MEMORY, ls_memory)
            if ls_workers:
                malcolm_config.set_value(KEY_CONFIG_ITEM_LS_WORKERS, ls_workers)
        else:
            logger.info("Keeping existing memory and worker settings")
        if platform.is_dry_run():
            return InstallerResult.SKIPPED, "Runtime configuration skipped (dry run)"
        return InstallerResult.SUCCESS, "Malcolm runtime configuration completed"
    except Exception as e:
        logger.error(f"Malcolm runtime configuration failed: {e}")
        return InstallerResult.FAILURE, "Malcolm runtime configuration failed"


def _resolve_podman_rootless_user(platform):
    import os

    user = os.environ.get("SUDO_USER") or os.environ.get("LOGNAME") or os.environ.get("USER")
    if not user or user == "root":
        return None, None, None
    uid = None
    rc, out = platform.run_process(["id", "-u", user], privileged=False, stderr=False)
    if rc == 0 and out:
        uid = out[0].strip()
    socket_path = f"/run/user/{uid}/podman/podman.sock" if uid else None
    return user, uid, socket_path


def _prepare_podman_rootless_command(base_cmd: List[str], action: str, platform, logger) -> List[str]:
    import os

    user, uid, socket_path = _resolve_podman_rootless_user(platform)
    if os.geteuid() == 0 and user:
        logger.info(f"Podman: {action} as {user} (socket {socket_path})")
        return ["sudo", "-u", user] + base_cmd
    actor = user or os.environ.get("USER") or "current user"
    suffix = f" (socket {socket_path})" if socket_path else ""
    logger.info(f"Podman: {action} as {actor}{suffix}")
    return base_cmd


def perform_docker_operations(malcolm_config, config_dir: str, platform, ctx, logger) -> Tuple[InstallerResult, str]:
    """Validate runtime and compose invocation; provide user guidance/do pulls/loads.

    Ported from steps/docker_ops.py.
    """
    import os
    from typing import Optional
    from scripts.installer.configs.constants.configuration_item_keys import (
        KEY_CONFIG_ITEM_RUNTIME_BIN,
        KEY_CONFIG_ITEM_MALCOLM_PROFILE,
    )

    try:
        runtime_bin: str = malcolm_config.get_value(KEY_CONFIG_ITEM_RUNTIME_BIN) or "docker"
        profile: str = malcolm_config.get_value(KEY_CONFIG_ITEM_MALCOLM_PROFILE)
        runtime_bin = os.path.basename(runtime_bin)

        compose_file = os.path.join(os.path.dirname(config_dir), COMPOSE_FILENAME)
        if not os.path.isfile(compose_file):
            logger.warning(f"No docker-compose.yml found near {config_dir}")
            logger.info("Malcolm container operations will need to be managed manually.")
            return InstallerResult.SUCCESS, "Compose file missing; docker operations skipped"

        logger.info(f"Using compose file: {compose_file}")
        logger.info(f"Container runtime: {runtime_bin}")
        if profile:
            logger.info(f"Malcolm profile: {profile}")

        if platform.is_dry_run():
            logger.info("Dry run: would perform Docker image operations and compose actions")
            if ctx.load_images_from_archive and ctx.image_archive_path:
                logger.info(f"Dry run: would load images from archive {ctx.image_archive_path}")
            else:
                logger.info("Dry run: would pull images using compose")
            logger.info("Dry run: would start Malcolm with 'compose up -d'")
            return InstallerResult.SKIPPED, "Docker operations skipped (dry run)"

        compose_cmd: Optional[List[str]] = None
        if ctx.load_images_from_archive and ctx.image_archive_path and os.path.isfile(ctx.image_archive_path):
            logger.info(f"Loading Malcolm images from {os.path.basename(ctx.image_archive_path)}...")
            load_cmd = [runtime_bin, "load", "-q", "-i", ctx.image_archive_path]
            if runtime_bin.startswith("podman") and os.geteuid() == 0:
                load_cmd = _prepare_podman_rootless_command(load_cmd, "loading images rootless", platform, logger)
                ecode, out = platform.run_process(load_cmd, privileged=False)
            else:
                ecode, out = platform.run_process(load_cmd, privileged=(not runtime_bin.startswith("podman")))
            if ecode == 0:
                logger.info("Malcolm images loaded successfully.")
                return InstallerResult.SUCCESS, "Malcolm images loaded from archive"
            else:
                logger.error(f"Loading Malcolm images failed: {out}")

        elif os.path.isfile(compose_file):
            pull_requested = bool(ctx.pull_malcolm_images)
            if not pull_requested:
                logger.info("Skipping image pull from registry per installer selection.")
            else:
                logger.info("Pulling Malcolm images from registry...")
            compose_cmd = compose_cmd or discover_compose_command(runtime_bin, platform)
            if compose_cmd is None:
                logger.warning("Could not find a working compose command for image pull")
                return InstallerResult.SUCCESS, "Compose command unavailable; manual start required"
            if runtime_bin.startswith("podman"):
                # best-effort socket activation; guidance only on failure
                rc, _ = platform.run_process(["systemctl", "--user", "is-active", "podman.socket"], privileged=False, stderr=False)
                # Not enforcing strict failure, keep behavior pragmatic
            compose_base = compose_cmd + ["-f", compose_file]
            if profile:
                compose_base.extend(["--profile", profile])
            if pull_requested:
                ecode = -1
                if runtime_bin.startswith("podman"):
                    pull_cmd = _prepare_podman_rootless_command(compose_base + ["pull"], "pulling images rootless", platform, logger)
                    ecode = platform.run_process_streaming(pull_cmd, privileged=False)
                else:
                    for priv in (False, True):
                        pull_cmd = compose_base + ["pull"]
                        ecode = platform.run_process_streaming(pull_cmd, privileged=priv)
                        if ecode == 0:
                            break
                if ecode == 0:
                    logger.info("Malcolm images pulled successfully.")
                else:
                    logger.error("Pulling Malcolm images failed")
                    return InstallerResult.FAILURE, "Docker image pull failed"

        # discover compose command & print guidance
        compose_cmd = compose_cmd or discover_compose_command(runtime_bin, platform)
        if compose_cmd is None:
            logger.warning("Could not find a working compose command on PATH.")
            logger.info("Please ensure Docker / Podman is installed and available.")
            return InstallerResult.SUCCESS, "Compose command unavailable; manual start required"
        compose_base = compose_cmd + ["-f", compose_file]
        if profile:
            compose_base.extend(["--profile", profile])
        printable_cmd = " ".join(compose_base + [COMPOSE_UP_SUBCOMMAND, COMPOSE_DETACH_FLAG])
        logger.info("Docker compose validated successfully.")
        logger.info("To start Malcolm run:")
        logger.info(f"  {printable_cmd}")
        return InstallerResult.SUCCESS, "Docker operations completed"
    except Exception as exc:
        logger.error(f"Docker operations failed: {exc}")
        return InstallerResult.FAILURE, "Docker operations failed"


# Expose compose discovery as a tiny shared helper for unit tests
def discover_compose_command(runtime_bin: str, platform) -> list | None:
    """Return a working compose invocation list for the given runtime.

    Mirrors the discovery behavior used by perform_docker_operations.
    """
    from typing import List
    if runtime_bin == "docker":
        candidates: List[List[str]] = [[runtime_bin, "compose"], ["docker-compose"]]
    elif runtime_bin == "podman":
        candidates = [[runtime_bin, "compose"], ["podman-compose"]]
    else:
        candidates = [[runtime_bin, "compose"]]
    for cmd in candidates:
        rc, _ = platform.run_process(cmd + ["--version"], stderr=False)
        if rc == 0:
            return cmd
    return None
