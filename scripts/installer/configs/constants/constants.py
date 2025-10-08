#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Centralized constants for installer shared actions and compose updates.

These constants replace magic strings/numbers embedded in helper code to
improve readability and keep behavior DRY and consistent across modules.
"""

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

# Traefik static values
TRAEFIK_ENABLE = "traefik.enable"
SERVICE_NAME_MALCOLM = "malcolm"
SERVICE_NAME_OSMALCOLM = "osmalcolm"
SERVICE_PORT_MALCOLM = "443"
SERVICE_PORT_OSMALCOLM = "9200"

# Default restart policy string (used for display/logging fallbacks)
DEFAULT_RESTART_POLICY = "unless-stopped"

# Container paths (inside containers) used for volume mappings
PCAP_CONTAINER_PATH = "/data/pcap"
ZEEK_LOG_CONTAINER_PATH = "/opt/zeek/logs"
SURICATA_LOG_CONTAINER_PATH = "/opt/suricata/logs"
OPENSEARCH_DATA_CONTAINER_PATH = "/usr/share/opensearch/data"

# Default host directories when config values are not set
DEFAULT_PCAP_DIR = "./pcap"
DEFAULT_ZEEK_LOG_DIR = "./zeek-logs"
DEFAULT_SURICATA_LOG_DIR = "./suricata-logs"
DEFAULT_INDEX_DIR = "./opensearch"
DEFAULT_INDEX_SNAPSHOT_DIR = "./opensearch-backup"

# SSL env defaults
SSL_CA_TRUST_DIR = "/var/local/ca-trust"

# ---------------------------------------------------------------------------
# Pre-existing installer constants referenced across core/ui
# ---------------------------------------------------------------------------

# Default syslog listen port used by dependencies and validations
SYSLOG_DEFAULT_PORT = 514

# Default Logstash workers by orchestration mode (parity with legacy logic)
LOGSTASH_WORKERS_DOCKER_COMPOSE = 3
LOGSTASH_WORKERS_KUBERNETES = 6

# Main configuration menu top-level keys used by TUI/DUI
# This list should include the primary items users configure first.
from scripts.installer.configs.constants.configuration_item_keys import (
    KEY_CONFIG_ITEM_RUNTIME_BIN,
    KEY_CONFIG_ITEM_PROCESS_USER_ID,
    KEY_CONFIG_ITEM_PROCESS_GROUP_ID,
    KEY_CONFIG_ITEM_PCAP_NODE_NAME,
    KEY_CONFIG_ITEM_MALCOLM_PROFILE,
    KEY_CONFIG_ITEM_LOGSTASH_HOST,
    KEY_CONFIG_ITEM_MALCOLM_AUTO_RESTART,
    KEY_CONFIG_ITEM_NGINX_SSL,
    KEY_CONFIG_ITEM_BEHIND_REVERSE_PROXY,
    KEY_CONFIG_ITEM_CONTAINER_NETWORK_NAME,
    KEY_CONFIG_ITEM_USE_DEFAULT_STORAGE_LOCATIONS,
    KEY_CONFIG_ITEM_INDEX_MANAGEMENT_POLICY,
    KEY_CONFIG_ITEM_CLEAN_UP_OLD_INDICES,
    KEY_CONFIG_ITEM_AUTO_ARKIME,
    KEY_CONFIG_ITEM_AUTO_SURICATA,
    KEY_CONFIG_ITEM_AUTO_ZEEK,
    KEY_CONFIG_ITEM_MALCOLM_ICS,
    KEY_CONFIG_ITEM_REVERSE_DNS,
    KEY_CONFIG_ITEM_AUTO_OUI,
    KEY_CONFIG_ITEM_AUTO_FREQ,
    KEY_CONFIG_ITEM_OPEN_PORTS,
    KEY_CONFIG_ITEM_FILE_CARVE_ENABLED,
    KEY_CONFIG_ITEM_ZEEK_PULL_INTELLIGENCE_FEEDS,
    KEY_CONFIG_ITEM_NETBOX_MODE,
    KEY_CONFIG_ITEM_CAPTURE_LIVE_NETWORK_TRAFFIC,
    KEY_CONFIG_ITEM_DASHBOARDS_DARK_MODE,
)

MAIN_MENU_KEYS = [
    KEY_CONFIG_ITEM_RUNTIME_BIN,
    KEY_CONFIG_ITEM_PROCESS_USER_ID,
    KEY_CONFIG_ITEM_PROCESS_GROUP_ID,
    KEY_CONFIG_ITEM_PCAP_NODE_NAME,
    KEY_CONFIG_ITEM_MALCOLM_PROFILE,
    KEY_CONFIG_ITEM_LOGSTASH_HOST,
    KEY_CONFIG_ITEM_MALCOLM_AUTO_RESTART,
    KEY_CONFIG_ITEM_NGINX_SSL,
    KEY_CONFIG_ITEM_BEHIND_REVERSE_PROXY,
    KEY_CONFIG_ITEM_CONTAINER_NETWORK_NAME,
    KEY_CONFIG_ITEM_USE_DEFAULT_STORAGE_LOCATIONS,
    KEY_CONFIG_ITEM_INDEX_MANAGEMENT_POLICY,
    KEY_CONFIG_ITEM_CLEAN_UP_OLD_INDICES,
    KEY_CONFIG_ITEM_AUTO_ARKIME,
    KEY_CONFIG_ITEM_AUTO_SURICATA,
    KEY_CONFIG_ITEM_AUTO_ZEEK,
    KEY_CONFIG_ITEM_MALCOLM_ICS,
    KEY_CONFIG_ITEM_REVERSE_DNS,
    KEY_CONFIG_ITEM_AUTO_OUI,
    KEY_CONFIG_ITEM_AUTO_FREQ,
    KEY_CONFIG_ITEM_OPEN_PORTS,
    KEY_CONFIG_ITEM_FILE_CARVE_ENABLED,
    KEY_CONFIG_ITEM_ZEEK_PULL_INTELLIGENCE_FEEDS,
    KEY_CONFIG_ITEM_NETBOX_MODE,
    KEY_CONFIG_ITEM_CAPTURE_LIVE_NETWORK_TRAFFIC,
    KEY_CONFIG_ITEM_DASHBOARDS_DARK_MODE,
]

# Choice lists for config items
# Keep UI-friendly strings centralized to ensure consistent display across UIs
ORCHESTRATION_MODE_CHOICES = [
    ("DOCKER_COMPOSE", "Docker Compose"),
    ("KUBERNETES", "Kubernetes"),
]
