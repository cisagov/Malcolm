import os
import customtkinter
from typing import Callable, Optional, Dict

from controllers.analysis_controller import AnalysisController
from views.base_view import BaseView


class AnalysisView(BaseView):
    """View for Malcolm analysis settings"""

    def __init__(self, parent, controller: AnalysisController):
        """
        Initialize with parent frame and controller

        Args:
            parent: The parent tkinter widget
            controller: The analysis controller
        """
        super().__init__(parent, controller)

        # Create the main frame
        self.frame = customtkinter.CTkFrame(parent)
        self.frame.pack(fill="both", expand=True, padx=10, pady=10)

        # Set up the layout
        self._create_ui()

        # Status message at the bottom of the screen
        self.status_label = customtkinter.CTkLabel(self.frame, text="")
        self.status_label.grid(
            row=100, column=0, columnspan=3, padx=10, pady=(20, 10), sticky="w"
        )

        # Register with controller AFTER UI elements are created
        self.controller.set_view(self)

    def _create_ui(self):
        """Create all UI elements"""
        # Title
        title = customtkinter.CTkLabel(
            self.frame,
            text="Analysis Configuration",
            font=customtkinter.CTkFont(size=20, weight="bold"),
        )
        title.grid(row=0, column=0, columnspan=3, padx=20, pady=(20, 10), sticky="w")

        # Description
        description = customtkinter.CTkLabel(
            self.frame,
            text="Configure analysis settings for Malcolm",
            font=customtkinter.CTkFont(size=12),
        )
        description.grid(
            row=1, column=0, columnspan=3, padx=20, pady=(0, 20), sticky="w"
        )

        # Create sections
        current_row = self._create_analyzer_section(row=2)
        current_row = self._create_network_section(row=current_row)
        current_row = self._create_additional_section(row=current_row)

        # Save button
        self.save_button = customtkinter.CTkButton(
            self.frame, text="Save Settings", command=self._on_save
        )
        self.save_button.grid(row=current_row, column=2, padx=10, pady=20, sticky="e")

    def _create_analyzer_section(self, row: int) -> int:
        """
        Create the analyzer settings section

        Args:
            row: The starting row

        Returns:
            int: The next available row
        """
        # Section header
        section_label = customtkinter.CTkLabel(
            self.frame,
            text="PCAP Analysis Tools",
            font=customtkinter.CTkFont(size=16, weight="bold"),
        )
        section_label.grid(
            row=row, column=0, columnspan=3, padx=20, pady=(20, 5), sticky="w"
        )
        row += 1

        # Description
        description = customtkinter.CTkLabel(
            self.frame,
            text="Configure which tools Malcolm will use for PCAP analysis",
            font=customtkinter.CTkFont(size=12),
        )
        description.grid(
            row=row, column=0, columnspan=3, padx=20, pady=(0, 10), sticky="w"
        )
        row += 1

        # Arkime checkbox
        self.analyze_with_arkime_var = customtkinter.BooleanVar(value=True)
        self.analyze_with_arkime_checkbox = customtkinter.CTkCheckBox(
            self.frame,
            text="Automatically analyze all PCAP files with Arkime",
            variable=self.analyze_with_arkime_var,
            command=self._on_analyze_with_arkime_change,
            onvalue=True,
            offvalue=False,
        )
        self.analyze_with_arkime_checkbox.grid(
            row=row, column=0, columnspan=2, padx=(20, 5), pady=5, sticky="w"
        )
        row += 1

        # Suricata checkbox
        self.analyze_with_suricata_var = customtkinter.BooleanVar(value=True)
        self.analyze_with_suricata_checkbox = customtkinter.CTkCheckBox(
            self.frame,
            text="Automatically analyze all PCAP files with Suricata",
            variable=self.analyze_with_suricata_var,
            command=self._on_analyze_with_suricata_change,
            onvalue=True,
            offvalue=False,
        )
        self.analyze_with_suricata_checkbox.grid(
            row=row, column=0, columnspan=2, padx=(20, 5), pady=5, sticky="w"
        )
        row += 1

        # Suricata signatures checkbox
        self.update_suricata_signatures_var = customtkinter.BooleanVar(value=False)
        self.update_suricata_signatures_checkbox = customtkinter.CTkCheckBox(
            self.frame,
            text="Download updated Suricata signatures periodically",
            variable=self.update_suricata_signatures_var,
            command=self._on_update_suricata_signatures_change,
            onvalue=True,
            offvalue=False,
        )
        self.update_suricata_signatures_checkbox.grid(
            row=row, column=0, columnspan=2, padx=(40, 5), pady=5, sticky="w"
        )
        row += 1

        # Zeek checkbox
        self.analyze_with_zeek_var = customtkinter.BooleanVar(value=True)
        self.analyze_with_zeek_checkbox = customtkinter.CTkCheckBox(
            self.frame,
            text="Automatically analyze all PCAP files with Zeek",
            variable=self.analyze_with_zeek_var,
            command=self._on_analyze_with_zeek_change,
            onvalue=True,
            offvalue=False,
        )
        self.analyze_with_zeek_checkbox.grid(
            row=row, column=0, columnspan=2, padx=(20, 5), pady=5, sticky="w"
        )
        row += 1

        return row

    def _create_network_section(self, row: int) -> int:
        """
        Create the network settings section

        Args:
            row: The starting row

        Returns:
            int: The next available row
        """
        # Section header
        section_label = customtkinter.CTkLabel(
            self.frame,
            text="Network Settings",
            font=customtkinter.CTkFont(size=16, weight="bold"),
        )
        section_label.grid(
            row=row, column=0, columnspan=3, padx=20, pady=(20, 5), sticky="w"
        )
        row += 1

        # Description
        description = customtkinter.CTkLabel(
            self.frame,
            text="Configure network monitoring settings",
            font=customtkinter.CTkFont(size=12),
        )
        description.grid(
            row=row, column=0, columnspan=3, padx=20, pady=(0, 10), sticky="w"
        )
        row += 1

        # OT/ICS checkbox
        self.is_ot_ics_network_var = customtkinter.BooleanVar(value=False)
        self.is_ot_ics_network_checkbox = customtkinter.CTkCheckBox(
            self.frame,
            text="Malcolm is monitoring an Operational Technology/Industrial Control Systems (OT/ICS) network",
            variable=self.is_ot_ics_network_var,
            command=self._on_is_ot_ics_network_change,
            onvalue=True,
            offvalue=False,
        )
        self.is_ot_ics_network_checkbox.grid(
            row=row, column=0, columnspan=3, padx=(20, 5), pady=5, sticky="w"
        )
        row += 1

        # Accept logs checkbox options
        logs_frame = customtkinter.CTkFrame(self.frame, fg_color="transparent")
        logs_frame.grid(
            row=row, column=0, columnspan=3, padx=(20, 5), pady=5, sticky="w"
        )

        logs_label = customtkinter.CTkLabel(
            logs_frame,
            text="Should Malcolm accept logs and metrics from a Hedgehog Linux sensor or other forwarder?",
            font=customtkinter.CTkFont(size=12),
        )
        logs_label.grid(row=0, column=0, columnspan=3, padx=0, pady=(5, 5), sticky="w")

        # Radio buttons for accept logs
        self.accept_logs_from_sensors_var = customtkinter.StringVar(value="no")

        self.accept_logs_no_radio = customtkinter.CTkRadioButton(
            logs_frame,
            text="No",
            variable=self.accept_logs_from_sensors_var,
            value="no",
            command=self._on_accept_logs_from_sensors_change,
        )
        self.accept_logs_no_radio.grid(
            row=1, column=0, padx=(0, 10), pady=5, sticky="w"
        )

        self.accept_logs_yes_radio = customtkinter.CTkRadioButton(
            logs_frame,
            text="Yes",
            variable=self.accept_logs_from_sensors_var,
            value="yes",
            command=self._on_accept_logs_from_sensors_change,
        )
        self.accept_logs_yes_radio.grid(
            row=1, column=1, padx=(0, 10), pady=5, sticky="w"
        )

        self.accept_logs_customize_radio = customtkinter.CTkRadioButton(
            logs_frame,
            text="Customize",
            variable=self.accept_logs_from_sensors_var,
            value="customize",
            command=self._on_accept_logs_from_sensors_change,
        )
        self.accept_logs_customize_radio.grid(
            row=1, column=2, padx=0, pady=5, sticky="w"
        )

        row += 1

        return row

    def _create_additional_section(self, row: int) -> int:
        """
        Create the additional settings section

        Args:
            row: The starting row

        Returns:
            int: The next available row
        """
        # Section header
        section_label = customtkinter.CTkLabel(
            self.frame,
            text="Additional Analysis Features",
            font=customtkinter.CTkFont(size=16, weight="bold"),
        )
        section_label.grid(
            row=row, column=0, columnspan=3, padx=20, pady=(20, 5), sticky="w"
        )
        row += 1

        # Description
        description = customtkinter.CTkLabel(
            self.frame,
            text="Configure additional analysis features",
            font=customtkinter.CTkFont(size=12),
        )
        description.grid(
            row=row, column=0, columnspan=3, padx=20, pady=(0, 10), sticky="w"
        )
        row += 1

        # DNS lookups checkbox
        self.perform_local_dns_lookups_var = customtkinter.BooleanVar(value=False)
        self.perform_local_dns_lookups_checkbox = customtkinter.CTkCheckBox(
            self.frame,
            text="Perform reverse DNS lookup locally for source and destination IP addresses in logs",
            variable=self.perform_local_dns_lookups_var,
            command=self._on_perform_local_dns_lookups_change,
            onvalue=True,
            offvalue=False,
        )
        self.perform_local_dns_lookups_checkbox.grid(
            row=row, column=0, columnspan=3, padx=(20, 5), pady=5, sticky="w"
        )
        row += 1

        # Hardware vendor lookup checkbox
        self.perform_hardware_vendor_lookups_var = customtkinter.BooleanVar(value=True)
        self.perform_hardware_vendor_lookups_checkbox = customtkinter.CTkCheckBox(
            self.frame,
            text="Perform hardware vendor OUI lookups for MAC addresses",
            variable=self.perform_hardware_vendor_lookups_var,
            command=self._on_perform_hardware_vendor_lookups_change,
            onvalue=True,
            offvalue=False,
        )
        self.perform_hardware_vendor_lookups_checkbox.grid(
            row=row, column=0, columnspan=3, padx=(20, 5), pady=5, sticky="w"
        )
        row += 1

        # String randomness scoring checkbox
        self.perform_string_randomness_scoring_var = customtkinter.BooleanVar(
            value=True
        )
        self.perform_string_randomness_scoring_checkbox = customtkinter.CTkCheckBox(
            self.frame,
            text="Perform string randomness scoring on some fields",
            variable=self.perform_string_randomness_scoring_var,
            command=self._on_perform_string_randomness_scoring_change,
            onvalue=True,
            offvalue=False,
        )
        self.perform_string_randomness_scoring_checkbox.grid(
            row=row, column=0, columnspan=3, padx=(20, 5), pady=5, sticky="w"
        )
        row += 1

        return row

    def _on_analyze_with_arkime_change(self):
        """Handle Arkime checkbox change"""
        value = self.analyze_with_arkime_var.get()
        success, message = self.controller.set_analyze_with_arkime(value)
        if not success:
            self.status_label.configure(text=f"Error: {message}")
        else:
            self.status_label.configure(text="")

    def _on_analyze_with_suricata_change(self):
        """Handle Suricata checkbox change"""
        value = self.analyze_with_suricata_var.get()
        success, message = self.controller.set_analyze_with_suricata(value)
        if not success:
            self.status_label.configure(text=f"Error: {message}")
        else:
            self.status_label.configure(text="")

        # Update the Suricata signatures checkbox state
        self._update_suricata_signatures_state()

    def _on_update_suricata_signatures_change(self):
        """Handle Suricata signatures checkbox change"""
        value = self.update_suricata_signatures_var.get()
        success, message = self.controller.set_update_suricata_signatures(value)
        if not success:
            self.status_label.configure(text=f"Error: {message}")
        else:
            self.status_label.configure(text="")

    def _on_analyze_with_zeek_change(self):
        """Handle Zeek checkbox change"""
        value = self.analyze_with_zeek_var.get()
        success, message = self.controller.set_analyze_with_zeek(value)
        if not success:
            self.status_label.configure(text=f"Error: {message}")
        else:
            self.status_label.configure(text="")

    def _on_is_ot_ics_network_change(self):
        """Handle OT/ICS checkbox change"""
        value = self.is_ot_ics_network_var.get()
        success, message = self.controller.set_is_ot_ics_network(value)
        if not success:
            self.status_label.configure(text=f"Error: {message}")
        else:
            self.status_label.configure(text="")

    def _on_accept_logs_from_sensors_change(self):
        """Handle accept logs radio button change"""
        value = self.accept_logs_from_sensors_var.get()
        success, message = self.controller.set_accept_logs_from_sensors(value)
        if not success:
            self.status_label.configure(text=f"Error: {message}")
        else:
            self.status_label.configure(text="")

    def _on_perform_local_dns_lookups_change(self):
        """Handle DNS lookups checkbox change"""
        value = self.perform_local_dns_lookups_var.get()
        success, message = self.controller.set_perform_local_dns_lookups(value)
        if not success:
            self.status_label.configure(text=f"Error: {message}")
        else:
            self.status_label.configure(text="")

    def _on_perform_hardware_vendor_lookups_change(self):
        """Handle hardware vendor lookups checkbox change"""
        value = self.perform_hardware_vendor_lookups_var.get()
        success, message = self.controller.set_perform_hardware_vendor_lookups(value)
        if not success:
            self.status_label.configure(text=f"Error: {message}")
        else:
            self.status_label.configure(text="")

    def _on_perform_string_randomness_scoring_change(self):
        """Handle string randomness scoring checkbox change"""
        value = self.perform_string_randomness_scoring_var.get()
        success, message = self.controller.set_perform_string_randomness_scoring(value)
        if not success:
            self.status_label.configure(text=f"Error: {message}")
        else:
            self.status_label.configure(text="")

    def _on_save(self):
        """Handle save button click"""
        success, message = self.controller.save_settings()
        if success:
            self.status_label.configure(text=f"Success: {message}")
        else:
            self.status_label.configure(text=f"Error: {message}")

    def _update_suricata_signatures_state(self):
        """Update the state of the Suricata signatures checkbox"""
        if self.analyze_with_suricata_var.get():
            self.update_suricata_signatures_checkbox.configure(state="normal")
        else:
            # Disable the signatures checkbox if Suricata is not enabled
            self.update_suricata_signatures_checkbox.configure(state="disabled")
            # Reset the value
            self.update_suricata_signatures_var.set(False)
            # Update the model
            self.controller.set_update_suricata_signatures(False)

    def update_analyze_with_arkime(self, value: bool):
        """Update the Arkime checkbox with the model value"""
        self.analyze_with_arkime_var.set(value)

    def update_analyze_with_suricata(self, value: bool):
        """Update the Suricata checkbox with the model value"""
        self.analyze_with_suricata_var.set(value)
        # Update dependent controls
        self._update_suricata_signatures_state()

    def update_update_suricata_signatures(self, value: bool):
        """Update the Suricata signatures checkbox with the model value"""
        self.update_suricata_signatures_var.set(value)

    def update_analyze_with_zeek(self, value: bool):
        """Update the Zeek checkbox with the model value"""
        self.analyze_with_zeek_var.set(value)

    def update_is_ot_ics_network(self, value: bool):
        """Update the OT/ICS checkbox with the model value"""
        self.is_ot_ics_network_var.set(value)

    def update_perform_local_dns_lookups(self, value: bool):
        """Update the DNS lookups checkbox with the model value"""
        self.perform_local_dns_lookups_var.set(value)

    def update_perform_hardware_vendor_lookups(self, value: bool):
        """Update the hardware vendor lookups checkbox with the model value"""
        self.perform_hardware_vendor_lookups_var.set(value)

    def update_perform_string_randomness_scoring(self, value: bool):
        """Update the string randomness scoring checkbox with the model value"""
        self.perform_string_randomness_scoring_var.set(value)

    def update_accept_logs_from_sensors(self, value: str):
        """Update the accept logs radio buttons with the model value"""
        self.accept_logs_from_sensors_var.set(value)
