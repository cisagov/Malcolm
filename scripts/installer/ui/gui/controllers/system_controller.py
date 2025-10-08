#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2025 Battelle Energy Alliance, LLC.  All rights reserved.

"""
System Controller for Malcolm GUI Installer
=========================================

This module provides the controller for system settings in the Malcolm GUI installer.
"""

import os
import sys
from pathlib import Path
from typing import Optional, Tuple, Any

from .base_controller import BaseController
from scripts.malcolm_common import GetMalcolmDir

from configs import MalcolmConfig


class SystemController(BaseController):
    """
    Controller for managing Malcolm system settings.

    This controller handles all operations related to system configuration,
    including initial setup, database configuration, resource settings,
    system behavior, and system management.
    """

    def __init__(self, model: MalcolmConfig):
        """
        Initialize with a reference to the model.

        Args:
            model: The central Malcolm configuration model
        """
        super().__init__(model)
        self.config_model = model
        self.view = None

    def set_view(self, view):
        """
        Set the view this controller will manage

        Args:
            view: The view instance
        """
        self.view = view
        self.refresh_view()

    def refresh_view(self):
        """
        Update the view with current model data.
        """
        if not self.view:
            return

        # Initial Setup
        self.view.update_puid(self.model.puid)
        self.view.update_pgid(self.model.pgid)
        self.view.update_node_name(self.model.node_name)

        # Profile
        self.view.update_profile(self.model.profile)

        # Database Configuration
        self.view.update_use_local_opensearch(self.model.use_local_opensearch)
        self.view.update_remote_store_type(self.model.remote_store_type)
        self.view.update_connection_url(self.model.connection_url)
        self.view.update_require_ssl_validation(self.model.require_ssl_validation)
        self.view.update_kibana_url(self.model.kibana_url)
        self.view.update_forward_logs_to_remote(self.model.forward_logs_to_remote)
        self.view.update_secondary_store_type(self.model.secondary_store_type)
        self.view.update_secondary_url(self.model.secondary_url)
        self.view.update_secondary_ssl_validation(self.model.secondary_ssl_validation)
        self.view.update_logstash_host_port(self.model.logstash_host_port)

        # Resource Settings
        self.view.update_opensearch_memory(self.model.opensearch_memory)
        self.view.update_logstash_memory(self.model.logstash_memory)
        self.view.update_logstash_workers(self.model.logstash_workers)

        # System Behavior
        self.view.update_auto_restart(self.model.auto_restart)
        self.view.update_restart_behavior(self.model.restart_behavior)

        # System Locations
        self.view.update_use_default_paths(self.model.use_default_paths)
        if not self.model.use_default_paths:
            self.view.update_opensearch_path(self.model.opensearch_path)
            self.view.update_zeek_path(self.model.zeek_path)
            self.view.update_pcap_path(self.model.pcap_path)
            self.view.update_suricata_path(self.model.suricata_path)
            self.view.update_index_path(self.model.index_path)
            self.view.update_snapshot_path(self.model.snapshot_path)

        # Index Management
        self.view.update_enable_index_management(self.model.enable_index_management)
        self.view.update_use_hot_warm(self.model.use_hot_warm)
        self.view.update_hot_duration(self.model.hot_duration)
        self.view.update_spi_retention(self.model.spi_retention)
        self.view.update_segments_to_optimize(self.model.segments_to_optimize)
        self.view.update_replica_count(self.model.replica_count)
        self.view.update_history_weeks(self.model.history_weeks)

        # System Management
        self.view.update_auto_delete_indices(self.model.auto_delete_indices)
        self.view.update_index_size_threshold(self.model.index_size_threshold)
        self.view.update_use_name_for_deletion(self.model.use_name_for_deletion)
        self.view.update_auto_delete_pcaps(self.model.auto_delete_pcaps)
        self.view.update_pcap_size_threshold(self.model.pcap_size_threshold)

    def set_opensearch_path(self, path: str) -> Tuple[bool, str]:
        """
        Set the OpenSearch data path

        Args:
            path: The directory path for OpenSearch data

        Returns:
            tuple: (success, error_message)
        """
        if not path:
            return False, "OpenSearch path cannot be empty"

        # Try to set the path in the model
        if not self.model.config.set("opensearch_path", path):
            return False, "Failed to set OpenSearch path"

        return True, ""

    def set_zeek_path(self, path: str) -> Tuple[bool, str]:
        """
        Set the Zeek logs path

        Args:
            path: The directory path for Zeek logs

        Returns:
            tuple: (success, error_message)
        """
        if not path:
            return False, "Zeek logs path cannot be empty"

        # Try to set the path in the model
        if not self.model.config.set("zeek_path", path):
            return False, "Failed to set Zeek logs path"

        return True, ""

    def set_pcap_path(self, path: str) -> Tuple[bool, str]:
        """
        Set the PCAP storage path

        Args:
            path: The directory path for PCAP files

        Returns:
            tuple: (success, error_message)
        """
        if not path:
            return False, "PCAP path cannot be empty"

        # Try to set the path in the model
        if not self.model.config.set("pcap_path", path):
            return False, "Failed to set PCAP path"

        return True, ""

    def set_opensearch_memory(self, memory: int) -> Tuple[bool, str]:
        """
        Set the OpenSearch memory allocation

        Args:
            memory: Memory allocation in MB

        Returns:
            tuple: (success, error_message)
        """
        try:
            memory_value = int(memory)
            if memory_value < 1024:
                return False, "OpenSearch memory should be at least 1024 MB"

            # Try to set the memory in the model
            if not self.model.config.set("opensearch_memory", memory_value):
                return False, "Failed to set OpenSearch memory"

            return True, ""
        except ValueError:
            return False, "Memory value must be a number"

    def set_use_local_opensearch(self, value):
        """
        Set whether to use local OpenSearch.

        Args:
            value: Boolean value

        Returns:
            tuple: (success, error_message)
        """
        # Update the model
        if not self.model.set("use_local_opensearch", value):
            return False, "Failed to set use_local_opensearch in model"

        return True, ""

    def set_compress_opensearch_snapshots(self, value):
        """
        Set whether to compress OpenSearch snapshots.

        Args:
            value: Boolean value

        Returns:
            tuple: (success, error_message)
        """
        # Update the model
        if not self.model.set("compress_opensearch_snapshots", value):
            return False, "Failed to set compress_opensearch_snapshots in model"

        return True, ""

    def set_forward_logs_to_remote(self, value):
        """
        Set whether to forward logs to a remote store.

        Args:
            value: Boolean value

        Returns:
            tuple: (success, error_message)
        """
        # Update the model
        if not self.model.set("forward_logs_to_remote", value):
            return False, "Failed to set forward_logs_to_remote in model"

        return True, ""

    def set_remote_store_type(self, store_type: str) -> Tuple[bool, str]:
        """
        Set the type of remote document store to forward logs to

        Args:
            store_type: The store type ('opensearch-remote' or 'elasticsearch-remote')

        Returns:
            tuple: (success, error_message)
        """
        if not store_type:
            return False, "Remote store type cannot be empty"

        if store_type not in self.model.REMOTE_STORE_TYPES:
            return (
                False,
                f"Invalid remote store type. Must be one of: {', '.join(self.model.REMOTE_STORE_TYPES.keys())}",
            )

        # Try to set the store type in the model
        if not self.model.remote_store_type == store_type:
            # Set the store type
            self.model.remote_store_type = store_type
            if self.model.remote_store_type != store_type:
                return False, "Failed to set remote store type"

        return True, ""

    def set_connection_url(self, url: str) -> Tuple[bool, str]:
        """
        Set the connection URL for the remote document store

        Args:
            url: The connection URL (e.g., https://192.168.1.123:9200)

        Returns:
            tuple: (success, error_message)
        """
        # No validation needed here, just store the URL
        # Real validation will happen on save when forward_logs_to_remote is enabled
        self.model.connection_url = url
        return True, ""

    def set_kibana_url(self, url: str) -> Tuple[bool, str]:
        """
        Set the Kibana URL for the remote document store

        Args:
            url: The Kibana URL (e.g., https://192.168.1.123:5601)

        Returns:
            tuple: (success, error_message)
        """
        # No validation needed here, just store the URL
        # Real validation will happen on save when use_local_opensearch is disabled
        self.model.kibana_url = url
        self.refresh_view()
        return True, ""

    def set_secondary_store_type(self, store_type: str) -> Tuple[bool, str]:
        """
        Set the type of secondary document store to forward logs to

        Args:
            store_type: The store type ('opensearch-remote' or 'elasticsearch-remote')

        Returns:
            tuple: (success, error_message)
        """
        if not store_type:
            return False, "Secondary store type cannot be empty"

        if store_type not in self.model.REMOTE_STORE_TYPES:
            return (
                False,
                f"Invalid secondary store type. Must be one of: {', '.join(self.model.REMOTE_STORE_TYPES.keys())}",
            )

        # Set the store type
        self.model.secondary_store_type = store_type
        self.refresh_view()
        return True, ""

    def set_secondary_url(self, url: str) -> Tuple[bool, str]:
        """
        Set the connection URL for the secondary document store

        Args:
            url: The secondary URL (e.g., https://192.168.1.124:9200)

        Returns:
            tuple: (success, error_message)
        """
        # No validation needed here, just store the URL
        # Real validation will happen on save when forward_logs_to_remote is enabled
        self.model.secondary_url = url
        self.refresh_view()
        return True, ""

    def set_secondary_ssl_validation(self, require_ssl_validation: bool) -> None:
        """
        Set whether to require SSL validation for the secondary store

        Args:
            require_ssl_validation: Whether to require SSL validation
        """
        self.model.secondary_ssl_validation = require_ssl_validation
        self.refresh_view()

    def set_logstash_host_port(self, host_port: str) -> Tuple[bool, str]:
        """
        Set the Logstash host:port for forwarding logs

        Args:
            host_port: The host:port string (e.g., 192.168.1.124:5044)

        Returns:
            tuple: (success, error_message)
        """
        # Basic format validation
        if not host_port:
            return False, "Logstash host:port cannot be empty"

        if ":" not in host_port:
            return False, "Logstash host:port must be in format host:port"

        host, port = host_port.split(":", 1)
        try:
            port_num = int(port)
            if port_num < 1 or port_num > 65535:
                return False, "Port must be between 1 and 65535"
        except ValueError:
            return False, "Port must be a number"

        # Store the value
        self.model.logstash_host_port = host_port
        self.refresh_view()
        return True, ""

    def validate_settings(self) -> Tuple[bool, str]:
        """
        Validate all system settings

        Returns:
            tuple: (is_valid, error_message)
        """
        return self.model.validate()

    def save_settings(self) -> Tuple[bool, str]:
        """
        Validate and save all system settings

        Returns:
            tuple: (success, message)
        """
        # First validate all settings
        valid, message = self.validate_settings()
        if not valid:
            return False, message

        # All validation passed
        return True, "System settings saved successfully"

    # Initial Setup Methods
    def set_puid(self, value: int) -> Tuple[bool, str]:
        """Set the process user ID"""
        try:
            puid = int(value)
            if puid < 0:
                return False, "User ID must be a positive number"
            self.model.puid = puid
            return True, ""
        except ValueError:
            return False, "User ID must be a number"

    def set_pgid(self, value: int) -> Tuple[bool, str]:
        """Set the process group ID"""
        try:
            pgid = int(value)
            if pgid < 0:
                return False, "Group ID must be a positive number"
            self.model.pgid = pgid
            return True, ""
        except ValueError:
            return False, "Group ID must be a number"

    def set_node_name(self, value: str) -> Tuple[bool, str]:
        """Set the node name"""
        if not value:
            return False, "Node name cannot be empty"
        self.model.node_name = value
        self.refresh_view()
        return True, ""

    def set_require_ssl_validation(self, require_ssl_validation: bool) -> None:
        """Set whether to require SSL validation"""
        self.model.require_ssl_validation = require_ssl_validation
        self.refresh_view()

    # Profile Methods
    def set_profile(self, value: str) -> Tuple[bool, str]:
        """Set the running profile"""
        if value not in self.model.PROFILES:
            return (
                False,
                f"Invalid profile. Must be one of: {', '.join(self.model.PROFILES.keys())}",
            )
        self.model.profile = value
        self.refresh_view()
        return True, ""

    # Resource Settings Methods
    def set_logstash_memory(self, memory: int) -> Tuple[bool, str]:
        """
        Set the Logstash memory allocation

        Args:
            memory: Memory allocation in MB

        Returns:
            tuple: (success, error_message)
        """
        try:
            memory_value = int(memory)
            if memory_value < 1024:
                return False, "Logstash memory should be at least 1024 MB"

            # Try to set the memory in the model
            if not self.model.config.set("logstash_memory", memory_value):
                return False, "Failed to set Logstash memory"

            return True, ""
        except ValueError:
            return False, "Memory value must be a number"

    def set_logstash_workers(self, workers: int) -> Tuple[bool, str]:
        """
        Set the number of Logstash workers

        Args:
            workers: Number of worker threads

        Returns:
            tuple: (success, error_message)
        """
        try:
            workers_value = int(workers)
            if workers_value < 1:
                return False, "Must have at least 1 Logstash worker"

            # Try to set the workers in the model
            if not self.model.config.set("logstash_workers", workers_value):
                return False, "Failed to set Logstash workers"

            return True, ""
        except ValueError:
            return False, "Workers value must be a number"

    # System Behavior Methods
    def set_auto_restart(self, value: bool) -> Tuple[bool, str]:
        """Set whether to automatically restart containers"""
        if not self.model.config.set("auto_restart", value):
            return False, "Failed to set auto restart"
        return True, ""

    def set_restart_behavior(self, value: str) -> Tuple[bool, str]:
        """Set the container restart behavior"""
        if value not in self.model.RESTART_BEHAVIORS:
            return (
                False,
                f"Invalid restart behavior. Must be one of: {', '.join(self.model.RESTART_BEHAVIORS.keys())}",
            )
        if not self.model.config.set("restart_behavior", value):
            return False, "Failed to set restart behavior"
        return True, ""

    # System Locations Methods
    def set_use_default_paths(self, value: bool) -> Tuple[bool, str]:
        """Set whether to use default paths"""
        if not self.model.config.set("use_default_paths", value):
            return False, "Failed to set use default paths"
        return True, ""

    def set_suricata_path(self, path: str) -> Tuple[bool, str]:
        """Set the Suricata logs path"""
        if not path:
            return False, "Suricata logs path cannot be empty"
        if not self.model.config.set("suricata_path", path):
            return False, "Failed to set Suricata logs path"
        return True, ""

    def set_index_path(self, path: str) -> Tuple[bool, str]:
        """Set the OpenSearch indices path"""
        if not path:
            return False, "Index path cannot be empty"
        if not self.model.config.set("index_path", path):
            return False, "Failed to set index path"
        return True, ""

    def set_snapshot_path(self, path: str) -> Tuple[bool, str]:
        """Set the OpenSearch snapshots path"""
        if not path:
            return False, "Snapshot path cannot be empty"
        if not self.model.config.set("snapshot_path", path):
            return False, "Failed to set snapshot path"
        return True, ""

    # Index Management Methods
    def set_enable_index_management(self, value: bool) -> Tuple[bool, str]:
        """Set whether to enable index management"""
        if not self.model.config.set("enable_index_management", value):
            return False, "Failed to set enable index management"
        return True, ""

    def set_use_hot_warm(self, value: bool) -> Tuple[bool, str]:
        """Set whether to use hot/warm architecture"""
        if not self.model.config.set("use_hot_warm", value):
            return False, "Failed to set use hot/warm"
        return True, ""

    def set_hot_duration(self, value: str) -> Tuple[bool, str]:
        """Set the hot duration"""
        if not value:
            return False, "Hot duration cannot be empty"
        if not self.model.config.set("hot_duration", value):
            return False, "Failed to set hot duration"
        return True, ""

    def set_spi_retention(self, value: str) -> Tuple[bool, str]:
        """Set the SPI retention period"""
        if not value:
            return False, "SPI retention cannot be empty"
        if not self.model.config.set("spi_retention", value):
            return False, "Failed to set SPI retention"
        return True, ""

    def set_segments_to_optimize(self, value: int) -> Tuple[bool, str]:
        """Set the number of segments to optimize"""
        try:
            segments = int(value)
            if segments < 1:
                return False, "Must optimize at least 1 segment"
            if not self.model.config.set("segments_to_optimize", segments):
                return False, "Failed to set segments to optimize"
            return True, ""
        except ValueError:
            return False, "Segments value must be a number"

    def set_replica_count(self, value: int) -> Tuple[bool, str]:
        """Set the replica count"""
        try:
            replicas = int(value)
            if replicas < 0:
                return False, "Replica count cannot be negative"
            if not self.model.config.set("replica_count", replicas):
                return False, "Failed to set replica count"
            return True, ""
        except ValueError:
            return False, "Replica count must be a number"

    def set_history_weeks(self, value: int) -> Tuple[bool, str]:
        """Set the number of weeks to keep history"""
        try:
            weeks = int(value)
            if weeks < 1:
                return False, "Must keep at least 1 week of history"
            if not self.model.config.set("history_weeks", weeks):
                return False, "Failed to set history weeks"
            return True, ""
        except ValueError:
            return False, "History weeks must be a number"

    # System Management Methods
    def set_auto_delete_indices(self, value: bool) -> Tuple[bool, str]:
        """Set whether to automatically delete indices"""
        if not self.model.config.set("auto_delete_indices", value):
            return False, "Failed to set auto delete indices"
        return True, ""

    def set_index_size_threshold(self, value: str) -> Tuple[bool, str]:
        """Set the index size threshold"""
        if not value:
            return False, "Index size threshold cannot be empty"
        if not self.model.config.set("index_size_threshold", value):
            return False, "Failed to set index size threshold"
        return True, ""

    def set_use_name_for_deletion(self, value: bool) -> Tuple[bool, str]:
        """Set whether to use name for deletion"""
        if not self.model.config.set("use_name_for_deletion", value):
            return False, "Failed to set use name for deletion"
        return True, ""

    def set_auto_delete_pcaps(self, value: bool) -> Tuple[bool, str]:
        """Set whether to automatically delete PCAPs"""
        if not self.model.config.set("auto_delete_pcaps", value):
            return False, "Failed to set auto delete PCAPs"
        return True, ""

    def set_pcap_size_threshold(self, value: str) -> Tuple[bool, str]:
        """Set the PCAP size threshold"""
        if not value:
            return False, "PCAP size threshold cannot be empty"
        if not self.model.config.set("pcap_size_threshold", value):
            return False, "Failed to set PCAP size threshold"
        return True, ""
