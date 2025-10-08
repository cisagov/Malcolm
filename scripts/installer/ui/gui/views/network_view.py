#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Network View
==========

Network view for the Malcolm installer, providing network configuration options.
"""

import customtkinter

from components.styles import *
from components.frame import Frame
from components.label import Label
from components.disableable_panel import DisableablePanel
from controllers.network_controller import NetworkController
from views.base_view import BaseView


class NetworkView(BaseView):
    """View for Malcolm network settings"""

    def __init__(self, parent, controller: NetworkController):
        """
        Initialize with parent frame and controller

        Args:
            parent: The parent tkinter widget
            controller: The network controller
        """
        # Call parent init which will create self.frame and call setup_ui
        super().__init__(parent, controller)
        self.controller = controller
        self.error_label = None

        # Initialize variables that will be used across methods
        self.network_mode_var = customtkinter.StringVar(value="bridge")
        self.external_network_widgets = []
        self.ports_widgets = []
        self.remote_access_widgets = []
        self.reverse_proxy_widgets = []
        self.traefik_widgets = []

        # Setup UI elements
        self.setup_ui()

        # Register with controller AFTER UI elements are created
        self.controller.set_view(self)

    def setup_ui(self):
        """Set up UI components."""
        row = 0

        # Title
        Label.title(self.frame, "Network Configuration", row)
        row += 1

        # Description
        Label.description(self.frame, "Configure network settings for Malcolm", row)
        row += 1

        # Network Mode Section
        row = self._create_network_mode_section(row)

        # Custom Service Ports Section
        row = self._create_port_configuration_section(row)

        # Expose Services Section
        row = self._create_expose_services_section(row)

        # Remote Access Section
        row = self._create_remote_access_section(row)

        # Add spacer before save button for clear separation
        spacer = customtkinter.CTkFrame(self.frame, fg_color="transparent", height=10)
        spacer.grid(row=row, column=0, padx=0, pady=5, sticky="ew")
        row += 1

        # Add Save Button - ensure it's well-spaced from previous sections
        save_container = customtkinter.CTkFrame(self.frame, fg_color="transparent")
        save_container.grid(
            row=row,
            column=0,
            padx=PADDING_LARGE,
            pady=(PADDING_LARGE, PADDING_LARGE * 2),
            sticky="ew",
        )

        self.save_button = customtkinter.CTkButton(
            save_container,
            text="Save Network Settings",
            command=self._on_save,
            width=200,
        )
        self.save_button.grid(row=0, column=0, padx=0, pady=0)

        self.status_label = customtkinter.CTkLabel(
            save_container, text="", text_color=("green", "green")
        )
        self.status_label.grid(row=0, column=1, padx=PADDING_MEDIUM, pady=0, sticky="w")

        self.save_button_frame = save_container
        row += 1

    def _create_network_mode_section(self, row: int) -> int:
        """
        Create the network mode selection section

        Args:
            row: The starting row

        Returns:
            int: The next available row
        """
        # Section header
        Label.section_header(self.frame, "Network Mode", row)
        row += 1

        # Description
        Label.section_description(
            self.frame,
            "Select how Malcolm's containers will connect to the network.",
            row,
        )
        row += 1

        # Create a frame for the network mode options
        mode_frame = customtkinter.CTkFrame(self.frame)
        mode_frame.grid(
            row=row, column=0, padx=PADDING_LARGE, pady=PADDING_SMALL, sticky="ew"
        )

        # Create radio buttons for each network mode
        self.bridge_radio = customtkinter.CTkRadioButton(
            mode_frame,
            text="Bridge (Default)",
            variable=self.network_mode_var,
            value="bridge",
            command=self._on_network_mode_change,
        )
        self.bridge_radio.grid(row=0, column=0, padx=(20, 0), pady=(10, 5), sticky="w")

        self.host_radio = customtkinter.CTkRadioButton(
            mode_frame,
            text="Host",
            variable=self.network_mode_var,
            value="host",
            command=self._on_network_mode_change,
        )
        self.host_radio.grid(row=1, column=0, padx=(20, 0), pady=5, sticky="w")

        self.external_radio = customtkinter.CTkRadioButton(
            mode_frame,
            text="External",
            variable=self.network_mode_var,
            value="external",
            command=self._on_network_mode_change,
        )
        self.external_radio.grid(row=2, column=0, padx=(20, 0), pady=5, sticky="w")

        # Create a nested panel for the external network name
        # Use DisableablePanel to create a dependent panel that's only enabled when "external" is selected
        self.external_network_panel, self.external_network_widgets = (
            DisableablePanel.create_radiobutton_panel(
                parent=mode_frame,
                radio_value="external",
                radio_variable=self.network_mode_var,
                row=3,
                column=0,
                indent=40,
            )
        )

        # Create network name input within the panel
        name_label = customtkinter.CTkLabel(
            self.external_network_panel, text="External Network Name:"
        )
        name_label.grid(row=0, column=0, padx=(0, 10), pady=5, sticky="w")
        self.external_network_widgets.append(name_label)

        self.network_name_entry = customtkinter.CTkEntry(
            self.external_network_panel,
            placeholder_text="Enter external network name",
            width=300,
        )
        self.network_name_entry.grid(row=0, column=1, padx=5, pady=5, sticky="ew")
        self.external_network_widgets.append(self.network_name_entry)

        # Add event bindings
        self.network_name_entry.bind("<FocusOut>", self._on_network_name_change)

        row += 1
        return row

    def _create_port_configuration_section(self, row: int) -> int:
        """
        Create the port configuration section

        Args:
            row: The starting row

        Returns:
            int: The next available row
        """
        # Section header
        Label.section_header(self.frame, "Custom Service Ports", row)
        row += 1

        # Description
        Label.section_description(
            self.frame, "Configure custom port mappings for Malcolm services.", row
        )
        row += 1

        # Use DisableablePanel for custom ports
        checkbox, ports_panel, ports_widgets = DisableablePanel.create_checkbox_panel(
            self.frame,
            "Use Custom Port Mappings",
            self.controller.set_custom_ports_enabled,
            lambda: self.controller.config_model.get("custom_ports_enabled", False),
            row=row,
        )
        # Adjust the checkbox position to match section headers
        checkbox.grid_configure(padx=20)
        self.custom_ports_checkbox = checkbox
        self.ports_panel = ports_panel
        self.ports_widgets = ports_widgets
        row += 2  # Skip a row for the panel

        # Create the port inputs within the panel
        self._create_port_inputs(ports_panel, ports_widgets)

        return row

    def _create_port_inputs(self, panel, widgets_list):
        """Create port input fields inside the panel"""
        port_section = customtkinter.CTkFrame(panel, fg_color="transparent")
        port_section.grid(row=0, column=0, padx=10, pady=10, sticky="ew")
        widgets_list.append(port_section)

        # Web interface port
        web_frame = customtkinter.CTkFrame(port_section, fg_color="transparent")
        web_frame.grid(row=0, column=0, padx=10, pady=5, sticky="w")
        widgets_list.append(web_frame)

        web_label = customtkinter.CTkLabel(
            web_frame, text="Web Interface Port:", font=("", 12, "bold")
        )
        web_label.grid(row=0, column=0, padx=0, pady=5, sticky="w")

        self.web_port_entry = customtkinter.CTkEntry(
            web_frame, placeholder_text="443", width=100
        )
        self.web_port_entry.grid(row=0, column=1, padx=(10, 0), pady=5, sticky="w")
        self.web_port_entry.bind("<FocusOut>", self._on_web_port_change)
        widgets_list.append(self.web_port_entry)

        # OpenSearch port
        opensearch_frame = customtkinter.CTkFrame(port_section, fg_color="transparent")
        opensearch_frame.grid(row=1, column=0, padx=10, pady=5, sticky="w")
        widgets_list.append(opensearch_frame)

        opensearch_label = customtkinter.CTkLabel(
            opensearch_frame, text="OpenSearch Port:", font=("", 12, "bold")
        )
        opensearch_label.grid(row=0, column=0, padx=0, pady=5, sticky="w")

        self.opensearch_port_entry = customtkinter.CTkEntry(
            opensearch_frame, placeholder_text="9200", width=100
        )
        self.opensearch_port_entry.grid(
            row=0, column=1, padx=(10, 0), pady=5, sticky="w"
        )
        self.opensearch_port_entry.bind("<FocusOut>", self._on_opensearch_port_change)
        widgets_list.append(self.opensearch_port_entry)

        # Logstash port
        logstash_frame = customtkinter.CTkFrame(port_section, fg_color="transparent")
        logstash_frame.grid(row=2, column=0, padx=10, pady=5, sticky="w")
        widgets_list.append(logstash_frame)

        logstash_label = customtkinter.CTkLabel(
            logstash_frame, text="Logstash Port:", font=("", 12, "bold")
        )
        logstash_label.grid(row=0, column=0, padx=0, pady=5, sticky="w")

        self.logstash_port_entry = customtkinter.CTkEntry(
            logstash_frame, placeholder_text="5044", width=100
        )
        self.logstash_port_entry.grid(row=0, column=1, padx=(10, 0), pady=5, sticky="w")
        self.logstash_port_entry.bind("<FocusOut>", self._on_logstash_port_change)
        widgets_list.append(self.logstash_port_entry)

    def _create_expose_services_section(self, row: int) -> int:
        """
        Create the expose services section

        Args:
            row: The starting row

        Returns:
            int: The next available row
        """
        # Section header
        Label.section_header(self.frame, "Expose Services Externally", row)
        row += 1

        # Description
        Label.section_description(
            self.frame, "Configure which services to expose externally.", row
        )
        row += 1

        # Create a frame for the checkboxes
        services_frame = customtkinter.CTkFrame(self.frame)
        services_frame.grid(
            row=row, column=0, padx=PADDING_LARGE, pady=PADDING_SMALL, sticky="ew"
        )

        # Expose OpenSearch checkbox
        self.expose_opensearch_var = customtkinter.BooleanVar(value=False)
        self.expose_opensearch_checkbox = customtkinter.CTkCheckBox(
            services_frame,
            text="Expose OpenSearch",
            variable=self.expose_opensearch_var,
            command=self._on_expose_opensearch_change,
        )
        self.expose_opensearch_checkbox.grid(
            row=0, column=0, padx=20, pady=10, sticky="w"
        )

        # Expose Logstash checkbox
        self.expose_logstash_var = customtkinter.BooleanVar(value=False)
        self.expose_logstash_checkbox = customtkinter.CTkCheckBox(
            services_frame,
            text="Expose Logstash",
            variable=self.expose_logstash_var,
            command=self._on_expose_logstash_change,
        )
        self.expose_logstash_checkbox.grid(
            row=1, column=0, padx=20, pady=10, sticky="w"
        )

        row += 1
        return row

    def _create_remote_access_section(self, row: int) -> int:
        """
        Create the remote access section

        Args:
            row: The starting row

        Returns:
            int: The next available row
        """
        # Section header
        Label.section_header(self.frame, "Remote Access", row)
        row += 1

        # Description
        Label.section_description(
            self.frame, "Configure remote access settings for Malcolm.", row
        )
        row += 1

        # Create main checkbox panel for remote access
        self.enable_remote_access_var = customtkinter.BooleanVar(value=False)
        remote_access_checkbox, remote_access_panel, remote_access_widgets = (
            DisableablePanel.create_checkbox_panel(
                self.frame,
                "Enable Remote Access",
                self.controller.set_remote_access_enabled,
                lambda: self.controller.config_model.get(
                    "remote_access_enabled", False
                ),
                row=row,
                column=0,
                indent=0,
            )
        )
        # Adjust the checkbox position to match section headers
        remote_access_checkbox.grid_configure(padx=20, pady=10)
        self.enable_remote_access_checkbox = remote_access_checkbox
        self.remote_access_panel = remote_access_panel
        self.remote_access_widgets = remote_access_widgets

        # Account for the checkbox and panel in row count
        row += 2

        # Domain Name Label and Entry - Make it clearly part of "Enable Remote Access"
        domain_frame = customtkinter.CTkFrame(
            remote_access_panel, fg_color="transparent"
        )
        domain_frame.grid(row=0, column=0, sticky="w", pady=10, padx=20)
        remote_access_widgets.append(domain_frame)

        domain_label = customtkinter.CTkLabel(
            domain_frame, text="Domain Name:", font=("", 12, "bold")
        )
        domain_label.grid(row=0, column=0, sticky="w", padx=(0, 10))
        remote_access_widgets.append(domain_label)

        self.domain_name_entry = customtkinter.CTkEntry(domain_frame, width=280)
        self.domain_name_entry.grid(row=0, column=1, sticky="w")
        self.domain_name_entry.bind("<FocusOut>", self._on_domain_name_change)
        remote_access_widgets.append(self.domain_name_entry)

        # Create a nested panel for reverse proxy options - Clearly indented under Remote Access
        self.behind_reverse_proxy_var = customtkinter.BooleanVar(value=False)
        reverse_proxy_checkbox, reverse_proxy_panel, reverse_proxy_widgets = (
            DisableablePanel.create_checkbox_panel(
                remote_access_panel,
                "Behind Reverse Proxy",
                self.controller.set_behind_reverse_proxy,
                lambda: self.controller.config_model.get("behind_reverse_proxy", False),
                row=1,
                column=0,
                indent=20,
            )
        )
        # Adjust checkbox padding to appear indented
        reverse_proxy_checkbox.grid_configure(padx=(40, 0), pady=10)

        self.behind_reverse_proxy_checkbox = reverse_proxy_checkbox
        self.reverse_proxy_panel = reverse_proxy_panel
        self.reverse_proxy_widgets = reverse_proxy_widgets
        remote_access_widgets.append(reverse_proxy_checkbox)
        remote_access_widgets.append(reverse_proxy_panel)

        # Register reverse proxy panel as a child of remote access panel
        DisableablePanel.register_child_panel(remote_access_panel, reverse_proxy_panel)

        # Create another nested panel for Traefik labels options - Clearly indented under Reverse Proxy
        self.configure_traefik_labels_var = customtkinter.BooleanVar(value=False)
        traefik_checkbox, traefik_panel, traefik_widgets = (
            DisableablePanel.create_checkbox_panel(
                reverse_proxy_panel,
                "Configure Traefik Labels",
                self.controller.set_configure_traefik_labels,
                lambda: self.controller.config_model.get(
                    "configure_traefik_labels", False
                ),
                row=0,
                column=0,
                indent=20,
            )
        )
        # Adjust checkbox padding to appear further indented
        traefik_checkbox.grid_configure(padx=(40, 0), pady=10)

        self.configure_traefik_labels_checkbox = traefik_checkbox
        self.traefik_panel = traefik_panel
        self.traefik_widgets = traefik_widgets
        reverse_proxy_widgets.append(traefik_checkbox)
        reverse_proxy_widgets.append(traefik_panel)

        # Register traefik panel as a child of reverse proxy panel
        DisableablePanel.register_child_panel(reverse_proxy_panel, traefik_panel)

        # Traefik Domain Label and Entry - Clearly indented under Configure Traefik Labels
        traefik_domain_frame = customtkinter.CTkFrame(
            traefik_panel, fg_color="transparent"
        )
        traefik_domain_frame.grid(row=0, column=0, sticky="w", padx=40, pady=10)
        traefik_widgets.append(traefik_domain_frame)

        traefik_domain_label = customtkinter.CTkLabel(
            traefik_domain_frame, text="Domain for Traefik Router:", font=("", 12)
        )
        traefik_domain_label.grid(row=0, column=0, sticky="w", padx=(20, 10))
        traefik_widgets.append(traefik_domain_label)

        self.traefik_domain_entry = customtkinter.CTkEntry(
            traefik_domain_frame, width=250
        )
        self.traefik_domain_entry.grid(row=0, column=1, sticky="w")
        self.traefik_domain_entry.bind("<FocusOut>", self._on_traefik_domain_change)
        traefik_widgets.append(self.traefik_domain_entry)

        return row

    def _set_widget_state(self, widget, enabled):
        """
        Enable or disable a widget and all its children

        Args:
            widget: The widget to enable/disable
            enabled: Whether to enable or disable
        """
        state = "normal" if enabled else "disabled"

        # First handle the parent widget
        if hasattr(widget, "configure"):
            try:
                # Try to set state directly for widgets that support it
                if isinstance(
                    widget,
                    (
                        customtkinter.CTkButton,
                        customtkinter.CTkEntry,
                        customtkinter.CTkCheckBox,
                        customtkinter.CTkRadioButton,
                    ),
                ):
                    widget.configure(state=state)
                # For labels and other widgets without a state property
                elif isinstance(widget, customtkinter.CTkLabel) and hasattr(
                    widget, "cget"
                ):
                    try:
                        if enabled:
                            widget.configure(text_color=("gray10", "gray90"))
                        else:
                            widget.configure(text_color=("gray60", "gray60"))
                    except ValueError:
                        pass  # Skip if text_color is not supported
            except (ValueError, AttributeError):
                # Skip configuration if the widget doesn't support the attribute
                pass

        # Then handle all children recursively
        try:
            for child in widget.winfo_children():
                self._set_widget_state(child, enabled)
        except (AttributeError, TypeError):
            # Skip if widget doesn't have winfo_children method
            pass

    def update_network_mode(self, mode: str):
        """
        Update the network mode radio buttons

        Args:
            mode: The network mode ('bridge', 'host', or 'external')
        """
        self.network_mode_var.set(mode)
        # The radiobutton panel will automatically update the visibility

    def update_external_network(self, network_name: str):
        """
        Update the external network name entry

        Args:
            network_name: The external network name
        """
        current = self.network_name_entry.get()
        if current != network_name:
            self.network_name_entry.delete(0, "end")
            self.network_name_entry.insert(0, network_name)

    def update_web_port(self, port: int):
        """
        Update the web interface port entry

        Args:
            port: The port number
        """
        self.web_port_entry.delete(0, "end")
        self.web_port_entry.insert(0, str(port))

    def update_opensearch_port(self, port: int):
        """
        Update the OpenSearch port entry

        Args:
            port: The port number
        """
        self.opensearch_port_entry.delete(0, "end")
        self.opensearch_port_entry.insert(0, str(port))

    def update_logstash_port(self, port: int):
        """
        Update the Logstash port entry

        Args:
            port: The port number
        """
        self.logstash_port_entry.delete(0, "end")
        self.logstash_port_entry.insert(0, str(port))

    def update_expose_opensearch(self, value: bool):
        """
        Update the expose OpenSearch checkbox

        Args:
            value: The checkbox value
        """
        self.expose_opensearch_var.set(value)

    def update_expose_logstash(self, value: bool):
        """
        Update the expose Logstash checkbox

        Args:
            value: The checkbox value
        """
        self.expose_logstash_var.set(value)

    def update_remote_access(self, enabled: bool, domain_name: str = ""):
        """
        Update the remote access settings

        Args:
            enabled: Whether remote access is enabled
            domain_name: The domain name (if enabled)
        """
        if enabled:
            self.enable_remote_access_checkbox.select()
        else:
            self.enable_remote_access_checkbox.deselect()

        DisableablePanel._set_panel_state(
            self.remote_access_panel, self.remote_access_widgets, enabled
        )

        # Update domain name if provided
        if domain_name:
            self.domain_name_entry.delete(0, "end")
            self.domain_name_entry.insert(0, domain_name)

    def update_behind_reverse_proxy(self, value: bool):
        """Update UI with current behind reverse proxy setting"""
        if value:
            self.behind_reverse_proxy_checkbox.select()
        else:
            self.behind_reverse_proxy_checkbox.deselect()

        DisableablePanel._set_panel_state(
            self.reverse_proxy_panel, self.reverse_proxy_widgets, value
        )

    def update_configure_traefik_labels(self, value: bool):
        """Update UI with current configure traefik labels setting"""
        if value:
            self.configure_traefik_labels_checkbox.select()
        else:
            self.configure_traefik_labels_checkbox.deselect()

        DisableablePanel._set_panel_state(
            self.traefik_panel, self.traefik_widgets, value
        )

    def update_traefik_domain(self, domain: str):
        """
        Update the traefik domain entry

        Args:
            domain: The traefik domain
        """
        self.traefik_domain_entry.delete(0, "end")
        self.traefik_domain_entry.insert(0, domain)

    def update_custom_ports_enabled(self, enabled: bool):
        """
        Update the custom port mappings setting

        Args:
            enabled: Whether custom port mappings are enabled
        """
        if enabled:
            self.custom_ports_checkbox.select()
        else:
            self.custom_ports_checkbox.deselect()

        DisableablePanel._set_panel_state(self.ports_panel, self.ports_widgets, enabled)

    def _on_network_mode_change(self):
        """Handle network mode radio button change"""
        mode = self.network_mode_var.get()
        success, message = self.controller.set_network_mode(mode)
        if not success:
            self.show_error(message)

    def _on_network_name_change(self, event=None):
        """Handle network name entry change"""
        name = self.network_name_entry.get().strip()
        success, message = self.controller.set_external_network(name)
        if not success:
            self.show_error(message)

    def _on_web_port_change(self, event=None):
        """Handle web port entry change"""
        port = self.web_port_entry.get().strip()
        success, message = self.controller.set_web_port(port)
        if not success:
            self.show_error(message)

    def _on_opensearch_port_change(self, event=None):
        """Handle opensearch port entry change"""
        port = self.opensearch_port_entry.get().strip()
        success, message = self.controller.set_opensearch_port(port)
        if not success:
            self.show_error(message)

    def _on_logstash_port_change(self, event=None):
        """Handle logstash port entry change"""
        port = self.logstash_port_entry.get().strip()
        success, message = self.controller.set_logstash_port(port)
        if not success:
            self.show_error(message)

    def _on_expose_opensearch_change(self):
        """Handle expose opensearch checkbox change"""
        value = self.expose_opensearch_var.get()
        success, message = self.controller.set_expose_opensearch(value)
        if not success:
            self.show_error(message)

    def _on_expose_logstash_change(self):
        """Handle expose logstash checkbox change"""
        value = self.expose_logstash_var.get()
        success, message = self.controller.set_expose_logstash(value)
        if not success:
            self.show_error(message)

    def _on_traefik_domain_change(self, event=None):
        """Handle traefik domain entry change"""
        domain = self.traefik_domain_entry.get().strip()
        success = self.controller.set_traefik_domain(domain)
        if not success:
            self.show_error("Invalid Traefik domain")

    def _on_domain_name_change(self, event=None):
        """Handle domain name entry change"""
        domain = self.domain_name_entry.get().strip()
        success = self.controller.set_domain_name(domain)
        if not success:
            self.show_error("Invalid domain name")

    def _on_save(self):
        """Save all network settings."""
        success, message = self.controller.save_settings()
        if success:
            self.status_label.configure(text="✓ Settings saved successfully")
        else:
            self.show_error(message)

    def show_error(self, message):
        """
        Display an error message.

        Args:
            message: The error message to display
        """
        if not self.error_label:
            # Create an error label at the bottom of the frame
            # Use a high row number to ensure it's at the bottom
            # This avoids relying on _grid_widgets which isn't available in CTkScrollableFrame
            self.error_label = customtkinter.CTkLabel(
                self.frame, text="", text_color=("red", "red")
            )
            self.error_label.grid(
                row=1000,  # Use a high row number instead of relying on _grid_widgets
                column=0,
                padx=PADDING_LARGE,
                pady=PADDING_SMALL,
                sticky="w",
            )

        self.error_label.configure(text=f"Error: {message}")

        # Clear the error after 5 seconds
        self.frame.after(5000, lambda: self.error_label.configure(text=""))

    def show_success(self, message):
        """
        Display a success message

        Args:
            message: The success message to display
        """
        self.status_label.configure(text=f"✓ {message}", text_color="green")

    def update_remote_access_enabled(self, enabled: bool):
        """
        Update the remote access enabled setting

        Args:
            enabled: Whether remote access is enabled
        """
        # Forward to the existing update_remote_access method
        self.update_remote_access(enabled, self.domain_name_entry.get())

    def update_domain_name(self, domain_name: str):
        """
        Update the domain name entry field

        Args:
            domain_name: The domain name
        """
        current = self.domain_name_entry.get()
        if current != domain_name:
            self.domain_name_entry.delete(0, "end")
            self.domain_name_entry.insert(0, domain_name)
