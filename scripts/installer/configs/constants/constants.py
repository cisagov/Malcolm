#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Centralized constants for installer shared actions and compose updates.

These constants replace magic strings/numbers embedded in helper code to
improve readability and keep behavior DRY and consistent across modules.
"""

# Main configuration menu top-level keys used by TUI/DUI
# This list should include the primary items users configure first.
from scripts.installer.configs.constants.configuration_item_keys import (
    KEY_CONFIG_ITEM_AUTO_ARKIME,
    KEY_CONFIG_ITEM_AUTO_FREQ,
    KEY_CONFIG_ITEM_AUTO_OUI,
    KEY_CONFIG_ITEM_AUTO_SURICATA,
    KEY_CONFIG_ITEM_AUTO_ZEEK,
    KEY_CONFIG_ITEM_TRAEFIK_LABELS,
    KEY_CONFIG_ITEM_CAPTURE_LIVE_NETWORK_TRAFFIC,
    KEY_CONFIG_ITEM_CLEAN_UP_OLD_ARTIFACTS,
    KEY_CONFIG_ITEM_INDEX_MANAGEMENT_POLICY,
    KEY_CONFIG_ITEM_MALCOLM_PROFILE,
    KEY_CONFIG_ITEM_NETBOX_MODE,
    KEY_CONFIG_ITEM_NGINX_RESOLVER_IPV4,
    KEY_CONFIG_ITEM_NGINX_RESOLVER_IPV6,
    KEY_CONFIG_ITEM_NGINX_SSL,
    KEY_CONFIG_ITEM_OPEN_PORTS,
    KEY_CONFIG_ITEM_PCAP_NODE_NAME,
    KEY_CONFIG_ITEM_REVERSE_DNS,
    KEY_CONFIG_ITEM_RUNTIME_BIN,
    KEY_CONFIG_ITEM_USE_DEFAULT_STORAGE_LOCATIONS,
)

# Compose file discovery
COMPOSE_FILE_GLOB = "docker-compose*.yml"
COMPOSE_FILENAME = "docker-compose.yml"

# Compose command discovery
COMPOSE_SUBCOMMAND = "compose"
DOCKER_COMPOSE_STANDALONE = "docker-compose"
PODMAN_COMPOSE_STANDALONE = "podman-compose"

# Compose up guidance
COMPOSE_UP_SUBCOMMAND = "up"
COMPOSE_DETACH_FLAG = "-d"

# Podman specific
USERNS_MODE_KEEP_ID = "keep-id"
PODMAN_LOG_DRIVER = "json-file"

# Docker specific
DOCKER_LOG_DRIVER = "local"


# Traefik label keys for nginx-proxy service (Malcolm UI)
LABEL_MALCOLM_RULE = "traefik.http.routers.malcolm.rule"
LABEL_MALCOLM_ENTRYPOINTS = "traefik.http.routers.malcolm.entrypoints"
LABEL_MALCOLM_CERTRESOLVER = "traefik.http.routers.malcolm.tls.certresolver"
LABEL_MALCOLM_SERVICE = "traefik.http.routers.malcolm.service"
LABEL_MALCOLM_SERVICE_PORT = "traefik.http.services.malcolm.loadbalancer.server.port"

# Traefik label keys for osmalcolm (OpenSearch when exposed)
LABEL_OS_RULE = "traefik.http.routers.osmalcolm.rule"
LABEL_OS_ENTRYPOINTS = "traefik.http.routers.osmalcolm.entrypoints"
LABEL_OS_CERTRESOLVER = "traefik.http.routers.osmalcolm.tls.certresolver"
LABEL_OS_SERVICE = "traefik.http.routers.osmalcolm.service"
LABEL_OS_SERVICE_PORT = "traefik.http.services.osmalcolm.loadbalancer.server.port"

# Traefik and service exposure static values
SERVICE_IP_EXPOSED = "0.0.0.0"
SERVICE_IP_LOCAL = "127.0.0.1"
SERVICE_NAME_MALCOLM = "malcolm"
SERVICE_NAME_OSMALCOLM = "osmalcolm"
SERVICE_PORT_LOGSTASH = "5044"
SERVICE_PORT_MALCOLM = "443"
SERVICE_PORT_MALCOLM_NO_SSL = "80"
SERVICE_PORT_OSMALCOLM = "9200"
SERVICE_PORT_OSMALCOLM_NO_SSL = "9201"
SERVICE_PORT_SFTP_EXTERNAL = "8022"
SERVICE_PORT_SFTP_INTERNAL = "22"
SERVICE_PORT_TCP_JSON = "5045"
SERVICE_PORT_ARKIME_WISE = "8081"
TRAEFIK_ENABLE = "traefik.enable"

LOCAL_LOGSTASH_HOST = f"logstash:{SERVICE_PORT_LOGSTASH}"
LOCAL_DASHBOARDS_URL = "http://dashboards:5601/dashboards"
LOCAL_OPENSEARCH_URL = f"https://opensearch:{SERVICE_PORT_OSMALCOLM}"
LOCAL_ARKIME_WISE_URL = f"http://arkime:{SERVICE_PORT_ARKIME_WISE}"

# Default restart policy string (used for display/logging fallbacks)
DEFAULT_RESTART_POLICY = "unless-stopped"

# ---------------------------------------------------------------------------
# Pre-existing installer constants referenced across core/ui
# ---------------------------------------------------------------------------

# Default syslog listen port used by dependencies and validations
SYSLOG_DEFAULT_PORT = 514

# Default resource settings specific for Docker vs. Kubernetes (where we can't auto-detect)
LOGSTASH_WORKERS_DOCKER_COMPOSE = 3
LOGSTASH_WORKERS_KUBERNETES = 6
OPENSEARCH_MEMORY_KUBERNETES = "31g"
LOGSTASH_MEMORY_KUBERNETES = "4g"

MAIN_MENU_KEYS = [
    KEY_CONFIG_ITEM_RUNTIME_BIN,
    KEY_CONFIG_ITEM_MALCOLM_PROFILE,
    KEY_CONFIG_ITEM_NGINX_SSL,
    KEY_CONFIG_ITEM_NGINX_RESOLVER_IPV4,
    KEY_CONFIG_ITEM_NGINX_RESOLVER_IPV6,
    KEY_CONFIG_ITEM_TRAEFIK_LABELS,
    KEY_CONFIG_ITEM_USE_DEFAULT_STORAGE_LOCATIONS,
    KEY_CONFIG_ITEM_CLEAN_UP_OLD_ARTIFACTS,
    KEY_CONFIG_ITEM_INDEX_MANAGEMENT_POLICY,
    KEY_CONFIG_ITEM_AUTO_ARKIME,
    KEY_CONFIG_ITEM_AUTO_SURICATA,
    KEY_CONFIG_ITEM_AUTO_ZEEK,
    KEY_CONFIG_ITEM_REVERSE_DNS,
    KEY_CONFIG_ITEM_AUTO_OUI,
    KEY_CONFIG_ITEM_AUTO_FREQ,
    KEY_CONFIG_ITEM_NETBOX_MODE,
    KEY_CONFIG_ITEM_OPEN_PORTS,
    KEY_CONFIG_ITEM_PCAP_NODE_NAME,
    KEY_CONFIG_ITEM_CAPTURE_LIVE_NETWORK_TRAFFIC,
]

# Choice lists for config items
# Keep UI-friendly strings centralized to ensure consistent display across UIs
ORCHESTRATION_MODE_CHOICES = [
    ("DOCKER_COMPOSE", "Docker Compose"),
    ("KUBERNETES", "Kubernetes"),
]
