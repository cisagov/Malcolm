#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2025 Battelle Energy Alliance, LLC.  All rights reserved.

"""
Analysis Controller for Malcolm GUI Installer
==========================================

This module provides the controller for analysis settings in the Malcolm GUI installer.
"""

import os
import sys
from typing import Optional, Tuple, Any

from .base_controller import BaseController
from scripts.malcolm_common import GetMalcolmDir

from configs import MalcolmConfig


class AnalysisController(BaseController):
    """
    Controller for managing Malcolm analysis settings.

    This controller handles all operations related to analysis configuration,
    including Zeek, Suricata, and other analysis tools.
    """

    def __init__(self, config: MalcolmConfig):
        """
        Initialize with a reference to the central config model

        Args:
            config: The central MalcolmConfig instance
        """
        super().__init__(config)
        self.model = AnalysisModel(config)
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

        # Update view with current model values
        self.view.update_analyze_with_arkime(self.model.analyze_with_arkime)
        self.view.update_analyze_with_suricata(self.model.analyze_with_suricata)
        self.view.update_update_suricata_signatures(
            self.model.update_suricata_signatures
        )
        self.view.update_analyze_with_zeek(self.model.analyze_with_zeek)
        self.view.update_is_ot_ics_network(self.model.is_ot_ics_network)
        self.view.update_perform_local_dns_lookups(self.model.perform_local_dns_lookups)
        self.view.update_perform_hardware_vendor_lookups(
            self.model.perform_hardware_vendor_lookups
        )
        self.view.update_perform_string_randomness_scoring(
            self.model.perform_string_randomness_scoring
        )
        self.view.update_accept_logs_from_sensors(self.model.accept_logs_from_sensors)

    def set_analyze_with_arkime(self, value: bool) -> Tuple[bool, str]:
        """
        Set whether to automatically analyze PCAP files with Arkime

        Args:
            value: True to analyze PCAP with Arkime, False otherwise

        Returns:
            tuple: (success, error_message)
        """
        self.model.analyze_with_arkime = value
        if self.model.analyze_with_arkime != value:
            return False, "Failed to set Arkime analysis preference"

        return True, ""

    def set_analyze_with_suricata(self, value: bool) -> Tuple[bool, str]:
        """
        Set whether to automatically analyze PCAP files with Suricata

        Args:
            value: True to analyze PCAP with Suricata, False otherwise

        Returns:
            tuple: (success, error_message)
        """
        self.model.analyze_with_suricata = value
        if self.model.analyze_with_suricata != value:
            return False, "Failed to set Suricata analysis preference"

        return True, ""

    def set_update_suricata_signatures(self, value: bool) -> Tuple[bool, str]:
        """
        Set whether to download updated Suricata signatures periodically

        Args:
            value: True to update signatures, False otherwise

        Returns:
            tuple: (success, error_message)
        """
        self.model.update_suricata_signatures = value
        if self.model.update_suricata_signatures != value:
            return False, "Failed to set Suricata signature update preference"

        return True, ""

    def set_analyze_with_zeek(self, value: bool) -> Tuple[bool, str]:
        """
        Set whether to automatically analyze PCAP files with Zeek

        Args:
            value: True to analyze PCAP with Zeek, False otherwise

        Returns:
            tuple: (success, error_message)
        """
        self.model.analyze_with_zeek = value
        if self.model.analyze_with_zeek != value:
            return False, "Failed to set Zeek analysis preference"

        return True, ""

    def set_is_ot_ics_network(self, value: bool) -> Tuple[bool, str]:
        """
        Set whether Malcolm is used to monitor an OT/ICS network

        Args:
            value: True if monitoring OT/ICS network, False otherwise

        Returns:
            tuple: (success, error_message)
        """
        self.model.is_ot_ics_network = value
        if self.model.is_ot_ics_network != value:
            return False, "Failed to set OT/ICS network monitoring preference"

        return True, ""

    def set_perform_local_dns_lookups(self, value: bool) -> Tuple[bool, str]:
        """
        Set whether to perform reverse DNS lookup locally for IP addresses

        Args:
            value: True to perform DNS lookups, False otherwise

        Returns:
            tuple: (success, error_message)
        """
        self.model.perform_local_dns_lookups = value
        if self.model.perform_local_dns_lookups != value:
            return False, "Failed to set local DNS lookup preference"

        return True, ""

    def set_perform_hardware_vendor_lookups(self, value: bool) -> Tuple[bool, str]:
        """
        Set whether to perform hardware vendor OUI lookups for MAC addresses

        Args:
            value: True to perform MAC lookups, False otherwise

        Returns:
            tuple: (success, error_message)
        """
        self.model.perform_hardware_vendor_lookups = value
        if self.model.perform_hardware_vendor_lookups != value:
            return False, "Failed to set hardware vendor lookup preference"

        return True, ""

    def set_perform_string_randomness_scoring(self, value: bool) -> Tuple[bool, str]:
        """
        Set whether to perform string randomness scoring on some fields

        Args:
            value: True to perform randomness scoring, False otherwise

        Returns:
            tuple: (success, error_message)
        """
        self.model.perform_string_randomness_scoring = value
        if self.model.perform_string_randomness_scoring != value:
            return False, "Failed to set string randomness scoring preference"

        return True, ""

    def set_accept_logs_from_sensors(self, value: str) -> Tuple[bool, str]:
        """
        Set whether Malcolm should accept logs and metrics from sensors

        Args:
            value: "no", "yes", or "customize"

        Returns:
            tuple: (success, error_message)
        """
        if value not in ["no", "yes", "customize"]:
            return (
                False,
                "Invalid setting for accepting logs from sensors. Must be 'no', 'yes', or 'customize'.",
            )

        self.model.accept_logs_from_sensors = value
        if self.model.accept_logs_from_sensors != value:
            return False, "Failed to set logs from sensors preference"

        return True, ""

    def validate(self) -> Tuple[bool, str]:
        """
        Validate all analysis settings

        Returns:
            tuple: (success, error_message)
        """
        return self.model.validate()

    def save_settings(self) -> Tuple[bool, str]:
        """
        Validate and save all settings to the model.

        Returns:
            tuple: (success, error_message)
        """
        # Validate settings first
        valid, error_message = self.validate()
        if not valid:
            return False, error_message

        # All settings are already in the model through properties
        return True, "Analysis settings saved successfully"
