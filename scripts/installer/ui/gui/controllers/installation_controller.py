#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2025 Battelle Energy Alliance, LLC.  All rights reserved.

"""
Installation Controller for Malcolm GUI Installer
=============================================

This module provides the controller for handling the installation process in the Malcolm GUI installer.
"""

import os
import sys
import subprocess
import threading
import time

from .base_controller import BaseController
from scripts.malcolm_common import GetMalcolmDir


class InstallationController(BaseController):
    """
    Controller for managing Malcolm installation process.

    This controller handles the actual installation of Malcolm,
    including generating configuration files and starting services.
    """

    def __init__(self, model):
        """
        Initialize the installation controller.

        Args:
            model: The MalcolmConfig model instance
        """
        super().__init__(model)

        # Set default values
        self.installation_in_progress = False
        self.installation_complete = False
        self.installation_success = False
        self.installation_message = ""
        self.installation_thread = None
        self.installation_output = []

    def refresh_view(self):
        """
        Update the view with current installation status.
        """
        if not self.view:
            return

        # Update view with current status if the view has these methods
        if hasattr(self.view, "update_installation_status"):
            status = "Not Started"
            if self.installation_in_progress:
                status = "In Progress"
            elif self.installation_complete:
                status = "Complete" if self.installation_success else "Failed"

            self.view.update_installation_status(status, self.installation_message)

        if hasattr(self.view, "update_installation_output"):
            self.view.update_installation_output("\n".join(self.installation_output))

    def start_installation(self):
        """
        Start the Malcolm installation process.

        Returns:
            tuple: (success, error_message)
        """
        if self.installation_in_progress:
            return False, "Installation is already in progress"

        # Reset installation state
        self.installation_in_progress = True
        self.installation_complete = False
        self.installation_success = False
        self.installation_message = "Starting installation..."
        self.installation_output = []

        # Update the view
        self.refresh_view()

        # Start installation in a separate thread
        self.installation_thread = threading.Thread(target=self._run_installation)
        self.installation_thread.daemon = True
        self.installation_thread.start()

        return True, "Installation started"

    def _run_installation(self):
        """
        Run the actual installation process in a background thread.
        """
        try:
            # First save the configuration to a file
            config_file = os.path.join(
                self.model.get("malcolm_install_path", ""), "malcolmgui.json"
            )
            if not self.model.save_to_file(config_file):
                self.installation_message = "Failed to save configuration file"
                self.installation_success = False
                self.installation_complete = True
                self.installation_in_progress = False
                self.refresh_view()
                return

            # Add to output
            self.installation_output.append(f"Saved configuration to {config_file}")

            # Build command for the install.py script
            malcolm_dir = self.model.get("malcolm_install_path", GetMalcolmDir())
            install_script = os.path.join(malcolm_dir, "scripts", "install.py")

            cmd = [sys.executable, install_script, "--configfile", config_file]

            # Add other arguments
            if self.model.get("config_only", False):
                cmd.append("--config-only")

            if self.model.get("debug", False):
                cmd.append("--debug")

            container_runtime = self.model.get("container_runtime")
            if container_runtime:
                cmd.extend(["--container-runtime", container_runtime])

            malcolm_file = self.model.get("malcolm_file")
            if malcolm_file:
                cmd.extend(["--malcolm", malcolm_file])

            images_file = self.model.get("images_file")
            if images_file:
                cmd.extend(["--images", images_file])

            # Run the installation command
            self.installation_output.append(f"Running command: {' '.join(cmd)}")
            self.refresh_view()

            # Execute the command and capture output
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                universal_newlines=True,
                bufsize=1,
            )

            # Process output in real-time
            for line in process.stdout:
                line = line.strip()
                if line:
                    self.installation_output.append(line)
                    self.refresh_view()

            # Wait for process to complete
            process.wait()

            # Set final status
            if process.returncode == 0:
                self.installation_success = True
                self.installation_message = "Installation completed successfully"
            else:
                self.installation_success = False
                self.installation_message = (
                    f"Installation failed with return code {process.returncode}"
                )

        except Exception as e:
            self.installation_success = False
            self.installation_message = f"Installation failed: {str(e)}"
            self.installation_output.append(f"Error: {str(e)}")

        finally:
            self.installation_complete = True
            self.installation_in_progress = False
            self.refresh_view()

    def get_installation_status(self):
        """
        Get the current installation status.

        Returns:
            tuple: (in_progress, complete, success, message)
        """
        return (
            self.installation_in_progress,
            self.installation_complete,
            self.installation_success,
            self.installation_message,
        )

    def get_installation_output(self):
        """
        Get the installation output.

        Returns:
            list: Installation output lines
        """
        return self.installation_output.copy()

    def cancel_installation(self):
        """
        Attempt to cancel the installation process.

        Returns:
            tuple: (success, error_message)
        """
        if not self.installation_in_progress:
            return False, "No installation in progress"

        self.installation_message = "Installation cancelled by user"
        self.installation_success = False
        self.installation_complete = True
        self.installation_in_progress = False

        # Update the view
        self.refresh_view()

        return True, "Installation cancelled"
