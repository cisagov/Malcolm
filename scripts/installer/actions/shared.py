#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Shared installer actions used by multiple platforms.
"""

import copy
import glob
import os
from enum import Enum
from typing import Tuple, List, Optional

from scripts.malcolm_constants import (
    COMPOSE_MALCOLM_EXTENSION,
    COMPOSE_MALCOLM_EXTENSION_AUX_FW,
    COMPOSE_MALCOLM_EXTENSION_AUX_FW_AIDE,
    COMPOSE_MALCOLM_EXTENSION_AUX_FW_AUDITLOG,
    COMPOSE_MALCOLM_EXTENSION_AUX_FW_CPU,
    COMPOSE_MALCOLM_EXTENSION_AUX_FW_DF,
    COMPOSE_MALCOLM_EXTENSION_AUX_FW_DISK,
    COMPOSE_MALCOLM_EXTENSION_AUX_FW_KMSG,
    COMPOSE_MALCOLM_EXTENSION_AUX_FW_MEM,
    COMPOSE_MALCOLM_EXTENSION_AUX_FW_NETWORK,
    COMPOSE_MALCOLM_EXTENSION_AUX_FW_SYSTEMD,
    COMPOSE_MALCOLM_EXTENSION_AUX_FW_THERMAL,
    COMPOSE_MALCOLM_EXTENSION_HEDGEHOG,
    COMPOSE_MALCOLM_EXTENSION_HEDGEHOG_REACHBACK_REQUEST_ACL,
    COMPOSE_MALCOLM_EXTENSION_PRUNE,
    COMPOSE_MALCOLM_EXTENSION_PRUNE_LOGS,
    COMPOSE_MALCOLM_EXTENSION_PRUNE_PCAP,
    DATABASE_MODE_ENUMS,
    DatabaseMode,
    DEFAULT_INDEX_DIR,
    DEFAULT_INDEX_SNAPSHOT_DIR,
    DEFAULT_PCAP_DIR,
    DEFAULT_SURICATA_LOG_DIR,
    DEFAULT_ZEEK_LOG_DIR,
    ImageArchitecture,
    PROFILE_HEDGEHOG,
    PROFILE_MALCOLM,
    SERVICE_PORT_HEDGEHOG_PROFILE_ARKIME_VIEWER,
    SERVICE_PORT_HEDGEHOG_PROFILE_EXTRACTED_FILES,
)
from scripts.malcolm_common import (
    BuildBoundPathReplacers,
    DumpYaml,
    LoadYaml,
    RemapBoundPaths,
)
from scripts.malcolm_utils import deep_get, deep_set, get_main_script_dir

from scripts.installer.configs.constants.configuration_item_keys import (
    KEY_CONFIG_ITEM_AUX_FW_AIDE,
    KEY_CONFIG_ITEM_AUX_FW_AUDITLOG,
    KEY_CONFIG_ITEM_AUX_FW_CPU,
    KEY_CONFIG_ITEM_AUX_FW_DF,
    KEY_CONFIG_ITEM_AUX_FW_DISK,
    KEY_CONFIG_ITEM_AUX_FW_KMSG,
    KEY_CONFIG_ITEM_AUX_FW_MEM,
    KEY_CONFIG_ITEM_AUX_FW_NETWORK,
    KEY_CONFIG_ITEM_AUX_FW_SYSTEMD,
    KEY_CONFIG_ITEM_AUX_FW_THERMAL,
    KEY_CONFIG_ITEM_CONTAINER_NETWORK_NAME,
    KEY_CONFIG_ITEM_EXPOSE_FILEBEAT_TCP,
    KEY_CONFIG_ITEM_EXPOSE_LOGSTASH,
    KEY_CONFIG_ITEM_EXPOSE_OPENSEARCH,
    KEY_CONFIG_ITEM_EXPOSE_SFTP,
    KEY_CONFIG_ITEM_IMAGE_ARCH,
    KEY_CONFIG_ITEM_INDEX_DIR,
    KEY_CONFIG_ITEM_INDEX_SNAPSHOT_DIR,
    KEY_CONFIG_ITEM_LIVE_ARKIME,
    KEY_CONFIG_ITEM_MALCOLM_PROFILE,
    KEY_CONFIG_ITEM_MALCOLM_RESTART_POLICY,
    KEY_CONFIG_ITEM_NGINX_SSL,
    KEY_CONFIG_ITEM_OPEN_PORTS,
    KEY_CONFIG_ITEM_OPENSEARCH_PRIMARY_MODE,
    KEY_CONFIG_ITEM_PCAP_DIR,
    KEY_CONFIG_ITEM_PCAP_NETSNIFF,
    KEY_CONFIG_ITEM_PCAP_TCPDUMP,
    KEY_CONFIG_ITEM_PRUNE_LOGS,
    KEY_CONFIG_ITEM_PRUNE_PCAP,
    KEY_CONFIG_ITEM_REACHBACK_REQUEST_ACL,
    KEY_CONFIG_ITEM_RUNTIME_BIN,
    KEY_CONFIG_ITEM_SURICATA_LOG_DIR,
    KEY_CONFIG_ITEM_SYSLOG_TCP_PORT,
    KEY_CONFIG_ITEM_SYSLOG_UDP_PORT,
    KEY_CONFIG_ITEM_TRAEFIK_ENTRYPOINT,
    KEY_CONFIG_ITEM_TRAEFIK_HOST,
    KEY_CONFIG_ITEM_TRAEFIK_LABELS,
    KEY_CONFIG_ITEM_TRAEFIK_OPENSEARCH_HOST,
    KEY_CONFIG_ITEM_TRAEFIK_RESOLVER,
    KEY_CONFIG_ITEM_USE_DEFAULT_STORAGE_LOCATIONS,
    KEY_CONFIG_ITEM_ZEEK_LOG_DIR,
)
from scripts.installer.configs.constants.constants import (
    COMPOSE_DETACH_FLAG,
    COMPOSE_FILE_GLOB,
    COMPOSE_FILENAME,
    COMPOSE_UP_SUBCOMMAND,
    DEFAULT_RESTART_POLICY,
    DOCKER_LOG_DRIVER,
    LABEL_MALCOLM_CERTRESOLVER,
    LABEL_MALCOLM_ENTRYPOINTS,
    LABEL_MALCOLM_RULE,
    LABEL_MALCOLM_SERVICE,
    LABEL_MALCOLM_SERVICE_PORT,
    LABEL_OS_CERTRESOLVER,
    LABEL_OS_ENTRYPOINTS,
    LABEL_OS_RULE,
    LABEL_OS_SERVICE,
    LABEL_OS_SERVICE_PORT,
    PODMAN_LOG_DRIVER,
    SERVICE_IP_EXPOSED,
    SERVICE_IP_LOCAL,
    SERVICE_NAME_MALCOLM,
    SERVICE_NAME_OSMALCOLM,
    SERVICE_PORT_LOGSTASH,
    SERVICE_PORT_MALCOLM,
    SERVICE_PORT_MALCOLM_NO_SSL,
    SERVICE_PORT_OSMALCOLM,
    SERVICE_PORT_OSMALCOLM_NO_SSL,
    SERVICE_PORT_SFTP_EXTERNAL,
    SERVICE_PORT_SFTP_INTERNAL,
    SERVICE_PORT_TCP_JSON,
    TRAEFIK_ENABLE,
    USERNS_MODE_KEEP_ID,
)
from scripts.installer.configs.constants.enums import InstallerResult, OpenPortsChoices
from scripts.installer.utils import InstallerLogger


def filesystem_prepare(malcolm_config, config_dir: str, platform, ctx) -> InstallerResult:
    """Ensure configuration directory exists (idempotent, respects dry-run)."""

    try:
        if not platform.should_write_files():
            InstallerLogger.info(f"Dry run: would create configuration directory: {config_dir}")
            return InstallerResult.SKIPPED
        if os.path.isdir(config_dir):
            return InstallerResult.SUCCESS
        os.makedirs(config_dir, exist_ok=True)
        InstallerLogger.info(f"Created configuration directory: {config_dir}")
        return InstallerResult.SUCCESS
    except Exception as e:
        InstallerLogger.error(f"Filesystem preparation failed: {e}")
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
    is_local = False
    if isinstance(os_primary_mode, DatabaseMode):
        is_local = os_primary_mode == DatabaseMode.OpenSearchLocal
    elif isinstance(os_primary_mode, str):
        try:
            is_local = (
                DATABASE_MODE_ENUMS.get(os_primary_mode, DatabaseMode.DatabaseUnset) == DatabaseMode.OpenSearchLocal
            )
        except Exception:
            is_local = False
    return bool(is_local and expose_opensearch)


def _select_install_path_and_compose_files(config_dir: str):
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
    restart_policy_value = malcolm_config.get_value(KEY_CONFIG_ITEM_MALCOLM_RESTART_POLICY) or DEFAULT_RESTART_POLICY
    return restart_policy_value.value if isinstance(restart_policy_value, Enum) else str(restart_policy_value)


def _update_services_runtime_settings(data: dict, runtime_bin: str, restart_policy: str, image_arch: str) -> None:
    for service in data.get("services", {}):
        if runtime_bin.startswith("podman"):
            deep_set(data, ["services", service, "userns_mode"], USERNS_MODE_KEEP_ID)
            deep_set(data, ["services", service, "logging", "driver"], PODMAN_LOG_DRIVER)
        else:
            deep_set(data, ["services", service, "userns_mode"], None, deleteIfNone=True)
            deep_set(data, ["services", service, "logging", "driver"], DOCKER_LOG_DRIVER)
        deep_set(data, ["services", service, "restart"], restart_policy)
        if image := deep_get(
            data,
            ['services', service, 'image'],
        ):
            image_parts = image.rstrip().split(":")
            image_parts[-1] = image_parts[-1].split("-", 1)[0] + (
                "" if image_arch == ImageArchitecture.AMD64.value else '-' + str(image_arch)
            )
            deep_set(data, ['services', service, 'image'], ":".join(image_parts))


def _get_traefik_config(malcolm_config):
    try:
        traefik_labels_enabled = bool(malcolm_config.get_value(KEY_CONFIG_ITEM_TRAEFIK_LABELS))
        traefik_host = malcolm_config.get_value(KEY_CONFIG_ITEM_TRAEFIK_HOST) or ""
        traefik_os_host = malcolm_config.get_value(KEY_CONFIG_ITEM_TRAEFIK_OPENSEARCH_HOST) or ""
        traefik_entrypoint = malcolm_config.get_value(KEY_CONFIG_ITEM_TRAEFIK_ENTRYPOINT) or ""
        traefik_resolver = malcolm_config.get_value(KEY_CONFIG_ITEM_TRAEFIK_RESOLVER) or ""
        expose_opensearch = (
            malcolm_config.get_value(KEY_CONFIG_ITEM_OPEN_PORTS) != OpenPortsChoices.NO.value
        ) and bool(malcolm_config.get_value(KEY_CONFIG_ITEM_EXPOSE_OPENSEARCH))
        os_primary_mode = (
            malcolm_config.get_value(KEY_CONFIG_ITEM_OPENSEARCH_PRIMARY_MODE) or DatabaseMode.OpenSearchLocal
        )
    except Exception as e:
        InstallerLogger.error(f"_get_traefik_config: {e}")
        traefik_labels_enabled = False
        traefik_host = traefik_os_host = traefik_entrypoint = traefik_resolver = ""
        expose_opensearch = False
        os_primary_mode = DatabaseMode.OpenSearchLocal
    return (
        traefik_labels_enabled,
        traefik_host,
        traefik_os_host,
        traefik_entrypoint,
        traefik_resolver,
        expose_opensearch,
        os_primary_mode,
    )


def _apply_traefik_labels_if_present(data: dict, traefik_tuple) -> None:
    (
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

        # Always write a boolean traefik.enable label
        labels_dict[TRAEFIK_ENABLE] = bool(traefik_labels_enabled)
        if labels_dict[TRAEFIK_ENABLE]:
            if len(traefik_host) > 1 and len(traefik_entrypoint) > 1 and len(traefik_resolver) > 1:
                _apply_malcolm_labels(labels_dict, traefik_host, traefik_entrypoint, traefik_resolver)
            if _is_opensearch_local_and_exposed(os_primary_mode, expose_opensearch):
                if len(traefik_os_host) > 1 and len(traefik_entrypoint) > 1 and len(traefik_resolver) > 1:
                    _apply_osmalcolm_labels(labels_dict, traefik_os_host, traefik_entrypoint, traefik_resolver)

        deep_set(data, labels_path, labels_dict)


def _apply_network_overrides(data: dict, network_name: Optional[str]) -> None:
    if network_name:
        for network in deep_get(data, ["networks"], {}):
            deep_set(data, ["networks", network, "external"], True)
            deep_set(data, ["networks", network, "name"], network_name)


def _get_exposed_services_config(malcolm_config):
    try:
        traefik_labels_enabled = bool(malcolm_config.get_value(KEY_CONFIG_ITEM_TRAEFIK_LABELS) or False)
        open_ports = malcolm_config.get_value(KEY_CONFIG_ITEM_OPEN_PORTS) != OpenPortsChoices.NO.value
        profile = malcolm_config.get_value(KEY_CONFIG_ITEM_MALCOLM_PROFILE) or PROFILE_MALCOLM
        os_primary_mode = (
            malcolm_config.get_value(KEY_CONFIG_ITEM_OPENSEARCH_PRIMARY_MODE) or DatabaseMode.OpenSearchLocal
        )
        nginx_ssl = malcolm_config.get_value(KEY_CONFIG_ITEM_NGINX_SSL) or True
        expose_filebeat_tcp = open_ports and bool(
            malcolm_config.get_value(KEY_CONFIG_ITEM_EXPOSE_FILEBEAT_TCP) or False
        )
        expose_logstash = open_ports and bool(malcolm_config.get_value(KEY_CONFIG_ITEM_EXPOSE_LOGSTASH) or False)
        expose_opensearch = open_ports and bool(malcolm_config.get_value(KEY_CONFIG_ITEM_EXPOSE_OPENSEARCH) or False)
        expose_sftp = open_ports and bool(malcolm_config.get_value(KEY_CONFIG_ITEM_EXPOSE_SFTP) or False)
        syslog_tcp_port = (malcolm_config.get_value(KEY_CONFIG_ITEM_SYSLOG_TCP_PORT) or 0) if open_ports else 0
        syslog_udp_port = (malcolm_config.get_value(KEY_CONFIG_ITEM_SYSLOG_UDP_PORT) or 0) if open_ports else 0
        reachback_request_acl = (
            (malcolm_config.get_value(KEY_CONFIG_ITEM_REACHBACK_REQUEST_ACL) or [])
            if (profile == PROFILE_HEDGEHOG)
            else []
        )
        # these aren't directly for exposed ports, but do determine whether arkime or arkime-live
        #   has the arkime reachback service port exposed
        pcap_cap_tcpdump = malcolm_config.get_value(KEY_CONFIG_ITEM_PCAP_TCPDUMP) or False
        pcap_cap_netsniff = malcolm_config.get_value(KEY_CONFIG_ITEM_PCAP_NETSNIFF) or False
        pcap_cap_arkime_live = malcolm_config.get_value(KEY_CONFIG_ITEM_LIVE_ARKIME) or False

    except Exception as e:
        InstallerLogger.error(f"_get_exposed_services_config: {e}")
        traefik_labels_enabled = False
        open_ports = False
        profile = malcolm_config.get_value(KEY_CONFIG_ITEM_MALCOLM_PROFILE) or PROFILE_MALCOLM
        nginx_ssl = True
        os_primary_mode = DatabaseMode.OpenSearchLocal
        expose_filebeat_tcp = False
        expose_logstash = False
        expose_opensearch = False
        expose_sftp = False
        syslog_tcp_port = 0
        syslog_udp_port = 0
        reachback_request_acl = []
        pcap_cap_tcpdump = False
        pcap_cap_netsniff = False
        pcap_cap_arkime_live = False

    return (
        traefik_labels_enabled,
        open_ports,
        profile,
        nginx_ssl,
        os_primary_mode,
        expose_filebeat_tcp,
        expose_logstash,
        expose_opensearch,
        expose_sftp,
        syslog_tcp_port,
        syslog_udp_port,
        reachback_request_acl,
        pcap_cap_tcpdump,
        pcap_cap_netsniff,
        pcap_cap_arkime_live,
    )


def _apply_exposed_services(data: dict, exposed_services_tuple, platform) -> None:
    (
        traefik_labels_enabled,
        open_ports,
        profile,
        nginx_ssl,
        os_primary_mode,
        expose_filebeat_tcp,
        expose_logstash,
        expose_opensearch,
        expose_sftp,
        syslog_tcp_port,
        syslog_udp_port,
        reachback_request_acl,
        pcap_cap_tcpdump,
        pcap_cap_netsniff,
        pcap_cap_arkime_live,
    ) = exposed_services_tuple

    ###################################
    # set bind IPs based on whether services should be externally exposed or not

    for service, port_infos in {
        'filebeat': [
            [expose_filebeat_tcp, int(SERVICE_PORT_TCP_JSON), int(SERVICE_PORT_TCP_JSON), 'tcp'],
            [syslog_tcp_port > 0, syslog_tcp_port, syslog_tcp_port, 'tcp'],
            [syslog_udp_port > 0, syslog_udp_port, syslog_udp_port, 'udp'],
        ],
        'logstash': [
            [expose_logstash, int(SERVICE_PORT_LOGSTASH), int(SERVICE_PORT_LOGSTASH), 'tcp'],
        ],
        'upload': [
            [expose_sftp, int(SERVICE_PORT_SFTP_EXTERNAL), int(SERVICE_PORT_SFTP_INTERNAL), 'tcp'],
        ],
    }.items():
        if service in data['services']:
            if profile == PROFILE_HEDGEHOG:
                data['services'][service].pop('ports', None)
            else:
                data['services'][service]['ports'] = []
                for port_info in port_infos:
                    if all(x for x in port_info):
                        data['services'][service]['ports'].append(
                            f"{SERVICE_IP_EXPOSED}:{port_info[1]}:{port_info[2]}/{port_info[3]}"
                        )
                if not data['services'][service]['ports']:
                    data['services'][service].pop('ports', None)
    ###################################

    ###################################
    # reachback request ACL for hedgehog Linux run profile

    # remove previously exposed ports from compose
    for hh_profile_service in ('file-monitor', 'arkime', 'arkime-live'):
        if hh_profile_service in data['services']:
            data['services'][hh_profile_service].pop('ports', None)

    # remove HH ACL section from extension
    if deep_get(data, [COMPOSE_MALCOLM_EXTENSION, COMPOSE_MALCOLM_EXTENSION_HEDGEHOG], []):
        data[COMPOSE_MALCOLM_EXTENSION][COMPOSE_MALCOLM_EXTENSION_HEDGEHOG].pop(
            COMPOSE_MALCOLM_EXTENSION_HEDGEHOG_REACHBACK_REQUEST_ACL, None
        )

    # if we're hedgehog mode and have an ACL...
    if (profile == PROFILE_HEDGEHOG) and reachback_request_acl:
        # set the ACL into the malcolm extension
        deep_set(
            data,
            [
                COMPOSE_MALCOLM_EXTENSION,
                COMPOSE_MALCOLM_EXTENSION_HEDGEHOG,
                COMPOSE_MALCOLM_EXTENSION_HEDGEHOG_REACHBACK_REQUEST_ACL,
            ],
            reachback_request_acl,
        )
        aclPorts = {'file-monitor': SERVICE_PORT_HEDGEHOG_PROFILE_EXTRACTED_FILES}
        if any((pcap_cap_arkime_live, pcap_cap_netsniff, pcap_cap_tcpdump)):
            # expose 8005 for arkime-live or arkime depending on where Arkime viewer will be running
            aclPorts['arkime-live' if pcap_cap_arkime_live else 'arkime'] = SERVICE_PORT_HEDGEHOG_PROFILE_ARKIME_VIEWER
        for service, port in aclPorts.items():
            data['services'][service]['ports'] = [f"{SERVICE_IP_EXPOSED}:{port}:{port}/tcp"]
    ###################################

    ###################################
    # nginx-proxy has got a lot going on
    if 'nginx-proxy' in data['services']:

        # set bind IPs and ports based on whether it should be externally exposed or not
        if (profile == PROFILE_HEDGEHOG) or traefik_labels_enabled:
            data['services']['nginx-proxy'].pop('ports', None)
        else:
            data['services']['nginx-proxy']['ports'] = [
                f"{(SERVICE_IP_EXPOSED if nginx_ssl else SERVICE_IP_LOCAL)}:"
                f"{(SERVICE_PORT_MALCOLM if nginx_ssl else SERVICE_PORT_MALCOLM_NO_SSL)}:"
                f"{SERVICE_PORT_MALCOLM}/tcp",
            ]
            if _is_opensearch_local_and_exposed(os_primary_mode, expose_opensearch):
                data['services']['nginx-proxy']['ports'].append(
                    f"{SERVICE_IP_EXPOSED}:{SERVICE_PORT_OSMALCOLM if nginx_ssl else SERVICE_PORT_OSMALCOLM_NO_SSL}:{SERVICE_PORT_OSMALCOLM}/tcp"
                )


def _apply_malcolm_extensions(data: dict, malcolm_config):
    ext_map = {
        # forwarders
        COMPOSE_MALCOLM_EXTENSION_AUX_FW: {
            KEY_CONFIG_ITEM_AUX_FW_AIDE: COMPOSE_MALCOLM_EXTENSION_AUX_FW_AIDE,
            KEY_CONFIG_ITEM_AUX_FW_AUDITLOG: COMPOSE_MALCOLM_EXTENSION_AUX_FW_AUDITLOG,
            KEY_CONFIG_ITEM_AUX_FW_CPU: COMPOSE_MALCOLM_EXTENSION_AUX_FW_CPU,
            KEY_CONFIG_ITEM_AUX_FW_DF: COMPOSE_MALCOLM_EXTENSION_AUX_FW_DF,
            KEY_CONFIG_ITEM_AUX_FW_DISK: COMPOSE_MALCOLM_EXTENSION_AUX_FW_DISK,
            KEY_CONFIG_ITEM_AUX_FW_KMSG: COMPOSE_MALCOLM_EXTENSION_AUX_FW_KMSG,
            KEY_CONFIG_ITEM_AUX_FW_MEM: COMPOSE_MALCOLM_EXTENSION_AUX_FW_MEM,
            KEY_CONFIG_ITEM_AUX_FW_NETWORK: COMPOSE_MALCOLM_EXTENSION_AUX_FW_NETWORK,
            KEY_CONFIG_ITEM_AUX_FW_SYSTEMD: COMPOSE_MALCOLM_EXTENSION_AUX_FW_SYSTEMD,
            KEY_CONFIG_ITEM_AUX_FW_THERMAL: COMPOSE_MALCOLM_EXTENSION_AUX_FW_THERMAL,
        },
        # prune operations external to containers
        COMPOSE_MALCOLM_EXTENSION_PRUNE: {
            KEY_CONFIG_ITEM_PRUNE_PCAP: COMPOSE_MALCOLM_EXTENSION_PRUNE_PCAP,
            KEY_CONFIG_ITEM_PRUNE_LOGS: COMPOSE_MALCOLM_EXTENSION_PRUNE_LOGS,
        },
    }
    for ext_key, ext_key_map in ext_map.items():
        ext_values = {}
        for key in ext_key_map.keys():
            ext_values[key] = bool(malcolm_config.get_value(key) or False)

        if deep_get(data, [COMPOSE_MALCOLM_EXTENSION], []):
            data[COMPOSE_MALCOLM_EXTENSION].pop(ext_key, None)

        for key, value in ext_values.items():
            deep_set(
                data,
                [
                    COMPOSE_MALCOLM_EXTENSION,
                    ext_key,
                    ext_key_map[key],
                ],
                value,
            )


def _write_or_log_changes(original: dict, data: dict, config_file: str, platform, dump_yaml) -> bool:
    changed = data != original
    if platform.should_write_files():
        if changed:
            dump_yaml(data, config_file)
            InstallerLogger.info(f"Updated compose file: {config_file}")
        else:
            InstallerLogger.info(f"No changes needed for compose file: {config_file}")
    else:
        if changed:
            InstallerLogger.info(f"Dry run: would update compose file: {config_file}")
        else:
            InstallerLogger.info(f"Dry run: no changes for compose file: {config_file}")

    return platform.should_write_files() and changed


def update_compose_files(
    malcolm_config, config_dir: str, orchestration_file: Optional[str], platform, ctx
) -> InstallerResult:
    """Update docker-compose files with runtime-specific settings."""
    try:
        if orchestration_file and os.path.isfile(orchestration_file):
            compose_files = [orchestration_file]
        else:
            _, compose_files = _select_install_path_and_compose_files(config_dir)

        if not compose_files:
            InstallerLogger.warning("Could not locate compose files for orchestration updates")
            return InstallerResult.SUCCESS

        if platform.is_dry_run():
            InstallerLogger.info(
                f"Dry run: would update compose files for orchestration: {', '.join(sorted(os.path.basename(f) for f in compose_files))}"
            )
            runtime_bin = malcolm_config.get_value(KEY_CONFIG_ITEM_RUNTIME_BIN) or "docker"
            restart_policy = _resolve_restart_policy(malcolm_config)
            InstallerLogger.info(
                f"Dry run: would set container runtime adjustments for {runtime_bin} and restart policy {restart_policy}"
            )
            return InstallerResult.SKIPPED

        InstallerLogger.info(
            f"Updating {len(compose_files)} compose file(s) for orchestration ({', '.join(sorted(os.path.basename(f) for f in compose_files))})..."
        )

        runtime_bin = malcolm_config.get_value(KEY_CONFIG_ITEM_RUNTIME_BIN) or "docker"
        restart_policy = _resolve_restart_policy(malcolm_config)
        network_name = malcolm_config.get_value(KEY_CONFIG_ITEM_CONTAINER_NETWORK_NAME)
        image_arch = malcolm_config.get_value(KEY_CONFIG_ITEM_IMAGE_ARCH)

        def get_or_default(config, key, default, use_default):
            return default if use_default else config.get_value(key) or default

        use_default = malcolm_config.get_value(KEY_CONFIG_ITEM_USE_DEFAULT_STORAGE_LOCATIONS)
        pcap_dir = get_or_default(malcolm_config, KEY_CONFIG_ITEM_PCAP_DIR, DEFAULT_PCAP_DIR, use_default)
        zeek_log_dir = get_or_default(malcolm_config, KEY_CONFIG_ITEM_ZEEK_LOG_DIR, DEFAULT_ZEEK_LOG_DIR, use_default)
        suricata_log_dir = get_or_default(
            malcolm_config, KEY_CONFIG_ITEM_SURICATA_LOG_DIR, DEFAULT_SURICATA_LOG_DIR, use_default
        )
        index_dir = get_or_default(malcolm_config, KEY_CONFIG_ITEM_INDEX_DIR, DEFAULT_INDEX_DIR, use_default)
        index_snapshot_dir = get_or_default(
            malcolm_config, KEY_CONFIG_ITEM_INDEX_SNAPSHOT_DIR, DEFAULT_INDEX_SNAPSHOT_DIR, use_default
        )

        result = InstallerResult.SUCCESS

        for config_file in compose_files:
            try:
                data = LoadYaml(config_file)
                if not data or "services" not in data:
                    continue

                original = copy.deepcopy(data)

                # logging, userns_mode, restart policy, and image architecture
                _update_services_runtime_settings(data, runtime_bin, restart_policy, image_arch)

                # for "large' storage locations (pcap, logs, opensearch, etc.) replace
                #   bind mount sources with user-specified locations
                RemapBoundPaths(
                    data,
                    BuildBoundPathReplacers(
                        pcap_dir,
                        suricata_log_dir,
                        zeek_log_dir,
                        index_dir,
                        index_snapshot_dir,
                    ),
                )

                # open ports for exposed services
                _apply_exposed_services(data, _get_exposed_services_config(malcolm_config), platform)

                # Malcolm x- extensions in compose file (except for reachback ACL which is done in _apply_exposed_services)
                _apply_malcolm_extensions(data, malcolm_config)

                # Traefik label handling
                _apply_traefik_labels_if_present(data, _get_traefik_config(malcolm_config))

                # custom container networking
                _apply_network_overrides(data, network_name)

                written = False
                config_file_stat = os.stat(config_file)
                orig_uid, orig_gid = config_file_stat[4], config_file_stat[5]
                try:
                    written = _write_or_log_changes(original, data, config_file, platform, DumpYaml)
                finally:
                    # restore ownership
                    if written:
                        os.chown(config_file, orig_uid, orig_gid)

            except Exception as e:
                InstallerLogger.error(f"Error updating docker-compose files: {e}")
                result = InstallerResult.FAILURE

        return result

    except Exception as e:
        InstallerLogger.error(f"Error updating docker-compose files: {e}")
        return InstallerResult.FAILURE


def perform_docker_operations(malcolm_config, config_dir: str, platform, ctx) -> Tuple[InstallerResult, str]:
    """Validate runtime and compose invocation; provide user guidance/do pulls/loads."""

    try:
        runtime_bin: str = malcolm_config.get_value(KEY_CONFIG_ITEM_RUNTIME_BIN) or "docker"
        profile: str = malcolm_config.get_value(KEY_CONFIG_ITEM_MALCOLM_PROFILE)
        runtime_bin = os.path.basename(runtime_bin)

        compose_file = os.path.join(os.path.dirname(config_dir), COMPOSE_FILENAME)
        if not os.path.isfile(compose_file):
            InstallerLogger.warning(f"No docker-compose.yml found near {config_dir}")
            InstallerLogger.info("Malcolm container operations will need to be managed manually.")
            return InstallerResult.SUCCESS, "Compose file missing; docker operations skipped"

        InstallerLogger.info(f"Using compose file: {compose_file}")
        InstallerLogger.info(f"Container runtime: {runtime_bin}")
        if profile:
            InstallerLogger.info(f"Malcolm profile: {profile}")

        if platform.is_dry_run():
            InstallerLogger.info("Dry run: would perform Docker image operations and compose actions")
            InstallerLogger.info("Dry run: would pull images using compose")
            InstallerLogger.info("Dry run: would start Malcolm with 'compose up -d'")
            return InstallerResult.SKIPPED, "Docker operations skipped (dry run)"

        compose_cmd: Optional[List[str]] = None
        if os.path.isfile(compose_file):
            pull_requested = bool(ctx.pull_malcolm_images)
            if not pull_requested:
                InstallerLogger.info("Skipping image pull from registry per installer selection.")
            else:
                InstallerLogger.info("Pulling Malcolm images from registry...")
            compose_cmd = compose_cmd or discover_compose_command(runtime_bin, platform)
            if compose_cmd is None:
                InstallerLogger.warning("Could not find a working compose command for image pull")
                return InstallerResult.SUCCESS, "Compose command unavailable; manual image pull required"
            if runtime_bin.startswith("podman"):
                InstallerLogger.warning("Podman (rootless) runtime requested; manual image pull required")
                return InstallerResult.SUCCESS, "Podman (rootless) runtime requested; manual image pull required"

            compose_base = compose_cmd + ["-f", compose_file]
            if profile:
                compose_base.extend(["--profile", profile])
            if pull_requested:
                ecode = -1
                for priv in (False, True):
                    pull_cmd = compose_base + ["pull"]
                    ecode = platform.run_process_streaming(pull_cmd)
                    if ecode == 0:
                        break
                if ecode == 0:
                    InstallerLogger.info("Malcolm images pulled successfully.")
                else:
                    InstallerLogger.error("Pulling Malcolm images failed")
                    return InstallerResult.FAILURE, "Docker image pull failed"

        # discover compose command & print guidance
        compose_cmd = compose_cmd or discover_compose_command(runtime_bin, platform)
        if compose_cmd is None:
            InstallerLogger.warning("Could not find a working compose command on PATH.")
            InstallerLogger.info("Please ensure Docker / Podman is installed and available.")
            return InstallerResult.SUCCESS, "Compose command unavailable; manual start required"
        compose_base = compose_cmd + ["-f", compose_file]
        if profile:
            compose_base.extend(["--profile", profile])
        printable_cmd = " ".join(compose_base + [COMPOSE_UP_SUBCOMMAND, COMPOSE_DETACH_FLAG])
        start_script = os.path.join(get_main_script_dir(), 'start')
        InstallerLogger.info("Docker compose validated successfully.")
        InstallerLogger.info("To start Malcolm run:")
        InstallerLogger.info(f"  {start_script if os.path.isfile(start_script) else printable_cmd}")
        return InstallerResult.SUCCESS, "Docker operations completed"
    except Exception as exc:
        InstallerLogger.error(f"Docker operations failed: {exc}")
        return InstallerResult.FAILURE, "Docker operations failed"


# Expose compose discovery as a tiny shared helper for unit tests
def discover_compose_command(runtime_bin: str, platform) -> Optional[List]:
    """
    Return a working compose invocation list for the given runtime.
    """
    candidates = [[runtime_bin, "compose"]]
    if runtime_bin in {"docker", "podman"}:
        candidates.append([f"{runtime_bin}-compose"])
    for cmd in candidates:
        rc, _ = platform.run_process(cmd + ["version"], stderr=False)
        if rc == 0:
            return cmd
    return None
