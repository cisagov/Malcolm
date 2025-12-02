#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2025 Battelle Energy Alliance, LLC.  All rights reserved.

import enum
from collections import defaultdict
from enum import Enum, Flag, auto


###################################################################################################
PROFILE_KEY = "MALCOLM_PROFILE"
PROFILE_MALCOLM = "malcolm"
PROFILE_HEDGEHOG = "hedgehog"
CONTAINER_RUNTIME_KEY = "MALCOLM_CONTAINER_RUNTIME"

###################################################################################################
PLATFORM_WINDOWS = "Windows"
PLATFORM_MAC = "Darwin"
PLATFORM_LINUX = "Linux"
PLATFORM_LINUX_ALMA = "almalinux"
PLATFORM_LINUX_AMAZON = "amzn"
PLATFORM_LINUX_CENTOS = "centos"
PLATFORM_LINUX_DEBIAN = "debian"
PLATFORM_LINUX_ELEMENTARY = "elementary"
PLATFORM_LINUX_FEDORA = "fedora"
PLATFORM_LINUX_MINT = "linuxmint"
PLATFORM_LINUX_POP = "pop"
PLATFORM_LINUX_RHEL = "rhel"
PLATFORM_LINUX_ROCKY = "rocky"
PLATFORM_LINUX_UBUNTU = "ubuntu"
PLATFORM_LINUX_ZORIN = "zorin"

###################################################################################################
# Default values for process user ID and group ID
PUID_DEFAULT = 1000
PGID_DEFAULT = 1000

###################################################################################################
YAML_VERSION = (1, 1)

###################################################################################################
LOGSTASH_JAVA_OPTS_DEFAULT = "-server -Xmx2500m -Xms2500m -Xss2048k -XX:-HeapDumpOnOutOfMemoryError -Djava.security.egd=file:/dev/./urandom -Dlog4j.formatMsgNoLookups=true"
OPENSEARCH_JAVA_OPTS_DEFAULT = "-server -Xmx10g -Xms10g -Xss256k -XX:-HeapDumpOnOutOfMemoryError -Djava.security.egd=file:/dev/./urandom -Dlog4j.formatMsgNoLookups=true"


###################################################################################################
# Constants for run modes
class PresentationMode(Enum):
    MODE_TUI = auto()  # Text-based User Interface
    MODE_DUI = auto()  # Dialogs
    MODE_GUI = auto()  # Graphical
    MODE_SILENT = auto()  # Silent mode


###################################################################################################
# Constants for Malcolm image prefix and dotfile secret key
MALCOLM_IMAGE_PREFIX = "ghcr.io/idaholab/malcolm/"
MALCOLM_VERSION = "25.12.0"

###################################################################################################
# Constants for Malcolm configmap directory replacer
MALCOLM_DOTFILE_SECRET_KEY = "K8S_SECRET"
MALCOLM_CONFIGMAP_DIR_REPLACER = "_MALDIR_"

###################################################################################################
# Directory path constants
HEDGEHOG_PCAP_DIR = "pcap"
HEDGEHOG_ZEEK_DIR = "zeek"
MALCOLM_DB_DIR = "datastore"
MALCOLM_PCAP_DIR = "pcap"
MALCOLM_LOGS_DIR = "logs"

###################################################################################################
SERVICE_PORT_HEDGEHOG_PROFILE_ARKIME_VIEWER = "8005"
SERVICE_PORT_HEDGEHOG_PROFILE_EXTRACTED_FILES = "8006"

# Malcolm extension fields for docker-compose
COMPOSE_MALCOLM_EXTENSION = "x-malcolm"
COMPOSE_MALCOLM_EXTENSION_HEDGEHOG = "hedgehog"
COMPOSE_MALCOLM_EXTENSION_HEDGEHOG_REACHBACK_REQUEST_ACL = "request_acl"
COMPOSE_MALCOLM_EXTENSION_AUX_FW = "aux-forwarders"
COMPOSE_MALCOLM_EXTENSION_AUX_FW_AIDE = "aide"
COMPOSE_MALCOLM_EXTENSION_AUX_FW_AUDITLOG = "auditlog"
COMPOSE_MALCOLM_EXTENSION_AUX_FW_CPU = "cpu"
COMPOSE_MALCOLM_EXTENSION_AUX_FW_DF = "df"
COMPOSE_MALCOLM_EXTENSION_AUX_FW_DISK = "disk"
COMPOSE_MALCOLM_EXTENSION_AUX_FW_KMSG = "kmsg"
COMPOSE_MALCOLM_EXTENSION_AUX_FW_MEM = "mem"
COMPOSE_MALCOLM_EXTENSION_AUX_FW_NETWORK = "network"
COMPOSE_MALCOLM_EXTENSION_AUX_FW_SYSTEMD = "systemd"
COMPOSE_MALCOLM_EXTENSION_AUX_FW_THERMAL = "thermal"
COMPOSE_MALCOLM_EXTENSION_PRUNE = "prune"
COMPOSE_MALCOLM_EXTENSION_PRUNE_PCAP = "pcap"
COMPOSE_MALCOLM_EXTENSION_PRUNE_LOGS = "logs"

###################################################################################################
# Directory path constants for volume mapping

# Container paths (inside containers) used for volume mappings
FILE_MONITOR_ZEEK_LOGS_CONTAINER_PATH = "/zeek/logs"
FILEBEAT_SURICATA_LOG_CONTAINER_PATH = "/suricata"
FILEBEAT_ZEEK_LOG_CONTAINER_PATH = "/zeek"
OPENSEARCH_BACKUP_CONTAINER_PATH = "/opt/opensearch/backup"
OPENSEARCH_DATA_CONTAINER_PATH = "/usr/share/opensearch/data"
PCAP_CAPTURE_CONTAINER_PATH = "/pcap"
PCAP_DATA_CONTAINER_PATH = "/data/pcap"
SURICATA_LOG_CONTAINER_PATH = "/var/log/suricata"
UPLOAD_ARTIFACT_CONTAINER_PATH = "/var/www/upload/server/php/chroot/files"
ZEEK_EXTRACT_FILES_CONTAINER_PATH = "/zeek/extract_files"
ZEEK_LIVE_LOG_CONTAINER_PATH = "/zeek/live"
ZEEK_LOG_UPLOAD_CONTAINER_PATH = "/zeek/upload"

# Default host directories when config values are not set
DEFAULT_PCAP_DIR = "./pcap"
DEFAULT_ZEEK_LOG_DIR = "./zeek-logs"
DEFAULT_SURICATA_LOG_DIR = "./suricata-logs"
DEFAULT_INDEX_DIR = "./opensearch"
DEFAULT_INDEX_SNAPSHOT_DIR = "./opensearch-backup"


###################################################################################################
# methods for Malcolm's connection to a data store
class DatabaseMode(enum.IntFlag):
    OpenSearchLocal = enum.auto()
    OpenSearchRemote = enum.auto()
    ElasticsearchRemote = enum.auto()
    DatabaseUnset = enum.auto()


DATABASE_MODE_LABELS = defaultdict(lambda: "")
DATABASE_MODE_ENUMS = defaultdict(lambda: DatabaseMode.DatabaseUnset)
DATABASE_MODE_LABELS[DatabaseMode.OpenSearchLocal] = "opensearch-local"
DATABASE_MODE_LABELS[DatabaseMode.OpenSearchRemote] = "opensearch-remote"
DATABASE_MODE_LABELS[DatabaseMode.ElasticsearchRemote] = "elasticsearch-remote"
DATABASE_MODE_ENUMS["opensearch-local"] = DatabaseMode.OpenSearchLocal
DATABASE_MODE_ENUMS["opensearch-remote"] = DatabaseMode.OpenSearchRemote
DATABASE_MODE_ENUMS["elasticsearch-remote"] = DatabaseMode.ElasticsearchRemote


# Image architecture constants
class ImageArchitecture(Enum):
    AMD64 = "amd64"
    ARM64 = "arm64"


class OrchestrationFramework(Flag):
    UNKNOWN = auto()
    DOCKER_COMPOSE = auto()
    KUBERNETES = auto()


OrchestrationFrameworksSupported = OrchestrationFramework.DOCKER_COMPOSE | OrchestrationFramework.KUBERNETES


class WidgetType(Enum):
    TEXT = auto()
    PASSWORD = auto()
    CHECKBOX = auto()
    RADIO = auto()
    SELECT = auto()
    MULTISELECT = auto()
    DATE = auto()
    TIME = auto()
    DATETIME = auto()
    NUMBER = auto()
    DIRECTORY = auto()


class SettingsFileFormat(Enum):
    JSON = "JSON"
    YAML = "YAML"
    UNKNOWN = "UNKNOWN"
