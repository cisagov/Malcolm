#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2025 Battelle Energy Alliance, LLC.  All rights reserved.

"""
Welcome Controller
================

Controls the welcome view of the Malcolm installer.
"""

import os
import platform
import psutil


class WelcomeController:
    """Controller for the Malcolm welcome screen."""

    def __init__(self, model):
        """
        Initialize with a reference to the model.

        Args:
            model: The central Malcolm configuration model
        """
        self.model = model
        self.view = None

    def set_view(self, view):
        """
        Set the view this controller will manage.

        Args:
            view: The welcome view instance
        """
        self.view = view
        self.refresh_view()

    def refresh_view(self):
        """Refresh the view with current model data and system information."""
        if not self.view:
            return

        # Get system information
        system_info = self.get_system_info()
        self.view.update_system_info(system_info)

    def get_system_info(self):
        """
        Get system information for requirements check.

        Returns:
            dict: System information and requirements status
        """
        # Get basic system info
        system = platform.system()
        release = platform.release()
        version = platform.version()

        # Get CPU info
        cpu_count = os.cpu_count()

        # Get memory info
        memory_gb = round(psutil.virtual_memory().total / (1024**3), 1)

        # Get disk info
        disk_total_gb = round(psutil.disk_usage("/").total / (1024**3), 1)
        disk_free_gb = round(psutil.disk_usage("/").free / (1024**3), 1)

        # Check if Docker/Podman is installed
        docker_installed = self._check_docker_installed()

        # Check requirements
        meets_cpu_req = cpu_count >= 2
        meets_memory_req = memory_gb >= 8
        meets_disk_req = disk_free_gb >= 50
        meets_container_req = docker_installed

        # Aggregate all info
        info = {
            "system": system,
            "release": release,
            "version": version,
            "cpu_count": cpu_count,
            "memory_gb": memory_gb,
            "disk_total_gb": disk_total_gb,
            "disk_free_gb": disk_free_gb,
            "docker_installed": docker_installed,
            "meets_cpu_req": meets_cpu_req,
            "meets_memory_req": meets_memory_req,
            "meets_disk_req": meets_disk_req,
            "meets_container_req": meets_container_req,
            "meets_all_req": all(
                [meets_cpu_req, meets_memory_req, meets_disk_req, meets_container_req]
            ),
        }

        return info

    def _check_docker_installed(self):
        """
        Check if Docker or Podman is installed.

        Returns:
            bool: True if Docker or Podman is installed
        """
        # Simple check using path
        docker_paths = ["/usr/bin/docker", "/usr/local/bin/docker", "/bin/docker"]
        podman_paths = ["/usr/bin/podman", "/usr/local/bin/podman", "/bin/podman"]

        docker_exists = any(os.path.exists(path) for path in docker_paths)
        podman_exists = any(os.path.exists(path) for path in podman_paths)

        return docker_exists or podman_exists

    def mark_introduction_read(self):
        """Mark the introduction as read in the model."""
        self.model.set("welcome_completed", True)
        return True, "Welcome screen completed"
