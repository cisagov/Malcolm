#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2025 Battelle Energy Alliance, LLC.  All rights reserved.

"""
Network Controller for Malcolm GUI Installer
=========================================

This module provides the controller for network settings in the Malcolm GUI installer.
"""

import logging
from typing import Optional, Tuple, Any
from tkinter import messagebox

from .base_controller import BaseController
from configs import MalcolmConfig


class NetworkController(BaseController):
    """
    Controller for managing Malcolm network settings.

    This controller handles all operations related to network configuration,
    including exposed ports, interfaces, and external connectivity settings.
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
        Set the view this controller will manage.

        Args:
            view: The network view instance
        """
        self.view = view
        self.refresh_view()

    def refresh_view(self):
        """
        Update the view with the current model state
        """
        # Update network mode
        self.view.update_network_mode(self.network_model.network_mode)

        # Update host network settings
        self.view.update_custom_ports_enabled(self.network_model.custom_ports_enabled)
        self.view.update_web_port(self.network_model.web_port)
        self.view.update_opensearch_port(self.network_model.opensearch_port)
        self.view.update_logstash_port(self.network_model.logstash_port)

        # Update exposure settings
        self.view.update_expose_opensearch(self.network_model.expose_opensearch)
        self.view.update_expose_logstash(self.network_model.expose_logstash)

        # Update remote access settings
        self.view.update_remote_access_enabled(self.network_model.remote_access_enabled)
        self.view.update_domain_name(self.network_model.domain_name)
        self.view.update_behind_reverse_proxy(self.network_model.behind_reverse_proxy)
        self.view.update_configure_traefik_labels(
            self.network_model.configure_traefik_labels
        )
        self.view.update_traefik_domain(self.network_model.traefik_domain)

    def set_web_port(self, port):
        """
        Set the web interface port.

        Args:
            port: Port number

        Returns:
            tuple: (success, error_message)
        """
        try:
            port_num = int(port)
            if port_num < 1 or port_num > 65535:
                return False, "Port must be between 1 and 65535"

            # Update the model
            if not self.network_model.web_port == port_num:
                self.network_model.web_port = port_num
                if self.network_model.web_port != port_num:
                    return False, "Failed to set web port in model"

            return True, ""
        except ValueError:
            return False, "Port must be a number"

    def set_opensearch_port(self, port):
        """
        Set the OpenSearch port.

        Args:
            port: Port number

        Returns:
            tuple: (success, error_message)
        """
        try:
            port_num = int(port)
            if port_num < 1 or port_num > 65535:
                return False, "Port must be between 1 and 65535"

            # Update the model
            if not self.network_model.opensearch_port == port_num:
                self.network_model.opensearch_port = port_num
                if self.network_model.opensearch_port != port_num:
                    return False, "Failed to set OpenSearch port in model"

            return True, ""
        except ValueError:
            return False, "Port must be a number"

    def set_logstash_port(self, port):
        """
        Set the Logstash port.

        Args:
            port: Port number

        Returns:
            tuple: (success, error_message)
        """
        try:
            port_num = int(port)
            if port_num < 1 or port_num > 65535:
                return False, "Port must be between 1 and 65535"

            # Update the model
            if not self.network_model.logstash_port == port_num:
                self.network_model.logstash_port = port_num
                if self.network_model.logstash_port != port_num:
                    return False, "Failed to set Logstash port in model"

            return True, ""
        except ValueError:
            return False, "Port must be a number"

    def set_expose_opensearch(self, value):
        """
        Set whether to expose OpenSearch externally.

        Args:
            value: Boolean value

        Returns:
            tuple: (success, error_message)
        """
        # Update the model
        if not self.network_model.expose_opensearch == value:
            self.network_model.expose_opensearch = value
            if self.network_model.expose_opensearch != value:
                return False, "Failed to set expose_opensearch in model"

        return True, ""

    def set_expose_logstash(self, value):
        """
        Set whether to expose Logstash externally.

        Args:
            value: Boolean value

        Returns:
            tuple: (success, error_message)
        """
        # Update the model
        if not self.network_model.expose_logstash == value:
            self.network_model.expose_logstash = value
            if self.network_model.expose_logstash != value:
                return False, "Failed to set expose_logstash in model"

        return True, ""

    def set_network_mode(self, mode: str) -> Tuple[bool, str]:
        """
        Set the network mode in the model.

        Args:
            mode: The network mode to set ('bridge', 'host', or 'external')

        Returns:
            tuple: (success, error_message)
        """
        # Validate the mode
        if mode not in ["bridge", "host", "external"]:
            return (
                False,
                "Invalid network mode. Must be 'bridge', 'host', or 'external'.",
            )

        # Update the model
        if not self.network_model.network_mode == mode:
            self.network_model.network_mode = mode
            if self.network_model.network_mode != mode:
                return False, "Failed to set network mode in model"

        return True, ""

    def set_external_network(self, network_name: str) -> Tuple[bool, str]:
        """
        Set the external container network name in the model.

        Args:
            network_name: The network name to set

        Returns:
            tuple: (success, error_message)
        """
        # Update the model
        if not self.network_model.external_network == network_name:
            self.network_model.external_network = network_name
            if self.network_model.external_network != network_name:
                return False, "Failed to set external network name in model"

        return True, ""

    def set_remote_access_enabled(self, value):
        """
        Enable or disable remote access feature

        Args:
            value (bool): True to enable remote access, False to disable

        Returns:
            tuple: (success, error_message)
        """
        try:
            self.network_model.remote_access_enabled = bool(value)
            self.refresh_view()
            return True, ""
        except Exception as e:
            logging.error(f"Error setting remote access enabled: {str(e)}")
            return False, str(e)

    def set_domain_name(self, domain_name):
        """
        Set the domain name for remote access

        Args:
            domain_name (str): Domain name to use

        Returns:
            tuple: (success, error_message)
        """
        try:
            self.network_model.domain_name = domain_name
            self.refresh_view()
            return True, ""
        except ValueError as e:
            # Show validation error to user
            messagebox.showerror("Invalid Domain Name", str(e))
            # Revert to previous valid value in the view
            self.refresh_view()
            return False, str(e)
        except Exception as e:
            logging.error(f"Error setting domain name: {str(e)}")
            return False, str(e)

    def set_behind_reverse_proxy(self, value):
        """
        Set whether Malcolm is behind a reverse proxy

        Args:
            value (bool): True if behind reverse proxy, False otherwise

        Returns:
            tuple: (success, error_message)
        """
        try:
            self.network_model.behind_reverse_proxy = bool(value)
            # If disabling reverse proxy, also disable its dependent settings
            if not value:
                self.network_model.configure_traefik_labels = False
            self.refresh_view()
            return True, ""
        except Exception as e:
            logging.error(f"Error setting behind reverse proxy: {str(e)}")
            return False, str(e)

    def set_configure_traefik_labels(self, value):
        """
        Set whether to configure Traefik labels

        Args:
            value (bool): True to configure Traefik labels, False otherwise

        Returns:
            tuple: (success, error_message)
        """
        try:
            # Can only be enabled if behind_reverse_proxy is True
            if value and not self.network_model.behind_reverse_proxy:
                error_msg = "Traefik labels can only be configured when 'Behind Reverse Proxy' is enabled."
                messagebox.showerror("Configuration Error", error_msg)
                return False, error_msg

            self.network_model.configure_traefik_labels = bool(value)
            self.refresh_view()
            return True, ""
        except Exception as e:
            logging.error(f"Error setting configure Traefik labels: {str(e)}")
            return False, str(e)

    def set_traefik_domain(self, domain):
        """
        Set the domain name for Traefik router

        Args:
            domain (str): Domain for Traefik router

        Returns:
            tuple: (success, error_message)
        """
        try:
            self.network_model.traefik_domain = domain
            self.refresh_view()
            return True, ""
        except ValueError as e:
            # Show validation error to user
            messagebox.showerror("Invalid Traefik Domain", str(e))
            # Revert to previous valid value in the view
            self.refresh_view()
            return False, str(e)
        except Exception as e:
            logging.error(f"Error setting Traefik domain: {str(e)}")
            return False, str(e)

    def get_domain_name(self) -> str:
        """
        Get the domain name from the model.

        Returns:
            str: The current domain name
        """
        return self.network_model.domain_name

    def set_custom_ports_enabled(self, enabled: bool) -> Tuple[bool, str]:
        """
        Set whether custom port mappings are enabled in the model.

        Args:
            enabled: Whether custom port mappings are enabled

        Returns:
            tuple: (success, error_message)
        """
        # Update the model
        if not self.network_model.custom_ports_enabled == enabled:
            self.network_model.custom_ports_enabled = enabled
            if self.network_model.custom_ports_enabled != enabled:
                return False, "Failed to set custom ports enabled in model"

        return True, ""

    def validate_settings(self) -> Tuple[bool, str]:
        """
        Validate all network settings

        Returns:
            tuple: (is_valid, error_message)
        """
        return self.network_model.validate()

    def save_settings(self) -> Tuple[bool, str]:
        """
        Validate and save all network settings

        Returns:
            tuple: (success, message)
        """
        # First validate settings
        valid, message = self.validate_settings()
        if not valid:
            return False, message

        # All validations passed
        return True, "Network settings saved successfully"
