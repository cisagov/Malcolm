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
PLATFORM_LINUX_CENTOS = "centos"
PLATFORM_LINUX_DEBIAN = "debian"
PLATFORM_LINUX_FEDORA = "fedora"
PLATFORM_LINUX_UBUNTU = "ubuntu"
PLATFORM_LINUX_ROCKY = "rocky"
PLATFORM_LINUX_ALMA = "almalinux"
PLATFORM_LINUX_AMAZON = "amazon"

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

###################################################################################################
# Constants for Malcolm configmap directory replacer
MALCOLM_DOTFILE_SECRET_KEY = "K8S_SECRET"
MALCOLM_CONFIGMAP_DIR_REPLACER = "_MALDIR_"

###################################################################################################
# Operating system mode constants
OS_MODE_HEDGEHOG = "hedgehog"
OS_MODE_MALCOLM = "malcolm"

###################################################################################################
# Directory path constants
HEDGEHOG_PCAP_DIR = "pcap"
HEDGEHOG_ZEEK_DIR = "zeek"
MALCOLM_DB_DIR = "datastore"
MALCOLM_PCAP_DIR = "pcap"
MALCOLM_LOGS_DIR = "logs"


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


OrchestrationFrameworksSupported = (
    OrchestrationFramework.DOCKER_COMPOSE | OrchestrationFramework.KUBERNETES
)


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
