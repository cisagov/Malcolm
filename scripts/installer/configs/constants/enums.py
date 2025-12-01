#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2025 Battelle Energy Alliance, LLC.  All rights reserved.


from enum import Enum, auto


# Used primarily for getting status from discrete steps during the installer and subsequently logging
class InstallerResult(Enum):
    """Return status for an installation step."""

    SUCCESS = auto()
    FAILURE = auto()
    SKIPPED = auto()


# top-level control flow for the installer
class ControlFlow(Enum):
    """High-level control over what the installer should do.

    - DRYRUN: log intended actions; make no changes (no file writes, no installs)
    - INSTALL: write configuration and perform installation steps
    - CONFIG: write configuration and ancillary files only; no installation steps
    """

    DRYRUN = auto()
    INSTALL = auto()
    CONFIG = auto()

    # query helpers
    def is_dry_run(self) -> bool:
        return self is ControlFlow.DRYRUN

    def is_config_only(self) -> bool:
        return self is ControlFlow.CONFIG

    def should_write_files(self) -> bool:
        """returns True only when file writes are allowed"""
        return self is not ControlFlow.DRYRUN

    def should_run_install_steps(self) -> bool:
        """returns True only when installation (system-changing) steps should run"""
        return self is ControlFlow.INSTALL

    # logging helpers
    def log_prefix(self) -> str:
        """prefix to use for 'would do' messages in dry-run"""
        return "Dry run: " if self is ControlFlow.DRYRUN else ""

    def would(self, action: str) -> str:
        """formats an action string appropriately for the current mode"""
        return ("Dry run: would " + action) if self is ControlFlow.DRYRUN else action


#####################################################
# ConfigItem Enums
#####################################################


# Docker restart policy constants
class DockerRestartPolicy(Enum):
    UNLESS_STOPPED = "unless-stopped"
    ALWAYS = "always"
    NO = "no"
    ON_FAILURE = "on-failure"


# Filebeat log format constants
class FilebeatLogFormat(Enum):
    JSON = "json"
    RAW = "raw"


# Filebeat field name constants
class FilebeatFieldNames(Enum):
    MESSAGE = "message"
    MISCBEAT = "miscbeat"


# OpenSearch/Elasticsearch mode constants
class SearchEngineMode(Enum):
    OPENSEARCH_LOCAL = "opensearch-local"
    OPENSEARCH_REMOTE = "opensearch-remote"
    ELASTICSEARCH_REMOTE = "elasticsearch-remote"


# NetBox mode constants
class NetboxMode(Enum):
    DISABLED = "disabled"
    LOCAL = "local"
    REMOTE = "remote"


# Open ports selection constants
class OpenPortsChoices(Enum):
    NO = "no"
    YES = "yes"
    CUSTOMIZE = "customize"


# Docker installation method constants
class DockerInstallMethod(Enum):
    REPOSITORY = "repository"
    CONVENIENCE_SCRIPT = "convenience_script"
    SKIP = "skip"


# Docker Compose installation method constants
class DockerComposeInstallMethod(Enum):
    GITHUB = "github"
    SKIP = "skip"


# Image/Runtime handling constants
class ImageHandlingMethod(Enum):
    LOAD = "load"
    PULL = "pull"
    SKIP = "skip"


# Container runtime constants
class ContainerRuntime(Enum):
    DOCKER = "docker"
    PODMAN = "podman"
    KUBERNETES = "kubernetes"


# File extraction mode constants
class FileExtractionMode(Enum):
    NONE = "none"
    KNOWN = "known"
    MAPPED = "mapped"
    ALL = "all"
    INTERESTING = "interesting"
    NOTCOMMTXT = "notcommtxt"


# File preservation mode constants
class FilePreservationMode(Enum):
    QUARANTINED = "quarantined"
    ALL = "all"
    NONE = "none"


# Arkime compression types
class ArkimePCAPCompression(Enum):
    NONE = "none"
    GZIP = "gzip"
    ZSTD = "zstd"
