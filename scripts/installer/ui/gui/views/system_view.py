import customtkinter
import os

from components.styles import *
from components.frame import Frame
from components.label import Label
from components.input_field import InputField, InputGroup
from components.controlled_checkbox import ControlledCheckbox
from components.disableable_panel import DisableablePanel
from components.button import Button
from controllers.system_controller import SystemController
from views.base_view import BaseView


class SystemView(BaseView):
    """View for Malcolm system settings"""

    def __init__(self, parent, controller: SystemController):
        """
        Initialize with parent frame and controller

        Args:
            parent: The parent tkinter widget
            controller: The system controller
        """
        super().__init__(parent, controller)

        # Set up the layout
        self.setup_ui()

        # Register with controller AFTER UI elements are created
        self.controller.set_view(self)

    def setup_ui(self):
        """Set up UI components by calling section builders."""
        row = 0

        # Add title and description
        row = self.add_title_and_description(
            "System Configuration",
            "Configure system settings and behavior for Malcolm.",
        )

        # Create sections
        row = self._create_initial_setup_section(row)
        row = self._create_profile_section(row)
        row = self._create_database_section(row)
        row = self._create_resource_section(row)
        row = self._create_behavior_section(row)
        row = self._create_locations_section(row)
        row = self._create_index_management_section(row)
        row = self._create_system_management_section(row)
        row = self._create_save_section(row)

    def _create_initial_setup_section(self, row: int) -> int:
        """Create the initial setup section"""
        # Create section container
        container, section_row = InputGroup.create(
            self.frame,
            "Initial Setup",
            "Configure basic Malcolm settings.",
            row=row,
            nesting_level=0,
        )

        # UID/GID Setup
        uid_container, uid_entry = InputField.create(
            container,
            "Process User ID (UID):",
            placeholder=str(os.getuid()),
            row=section_row,
            validation_func=self.controller.set_puid,
            nesting_level=1,
        )
        self.register_component("puid_entry", uid_entry)
        section_row += 1

        gid_container, gid_entry = InputField.create(
            container,
            "Process Group ID (GID):",
            placeholder=str(os.getgid()),
            row=section_row,
            validation_func=self.controller.set_pgid,
            nesting_level=1,
        )
        self.register_component("pgid_entry", gid_entry)
        section_row += 1

        # Node Name
        node_container, node_entry = InputField.create(
            container,
            "Node Name:",
            placeholder="Enter node name for traffic metadata",
            row=section_row,
            validation_func=self.controller.set_node_name,
            nesting_level=1,
        )
        self.register_component("node_name_entry", node_entry)

        return row + 1

    def _create_profile_section(self, row: int) -> int:
        # """Create the profile selection section"""
        # # Create section container
        # container, section_row = InputGroup.create(
        #     self.frame,
        #     "Running Profile",
        #     "Select the Malcolm running profile.",
        #     row=row,
        #     nesting_level=0
        # )

        # # Create radio buttons for profile selection
        # profile_var = customtkinter.StringVar(value=self.controller.model.profile)

        # for i, (value, text) in enumerate(self.controller.model.PROFILES.items()):
        #     display_text = text.split(" - ")[1] if " - " in text else text
        #     radio = customtkinter.CTkRadioButton(
        #         container,
        #         text=display_text,
        #         value=value,
        #         variable=profile_var,
        #         command=lambda: self.controller.set_profile(profile_var.get())
        #     )
        #     radio.grid(row=section_row + i, column=0, padx=PADDING_HIERARCHY_LEVEL_1, pady=(0, PADDING_SMALL), sticky="w")

        # self.register_component("profile_var", profile_var)

        return row + 1

    def _create_database_section(self, row: int) -> int:
        """Create the database configuration section"""
        # Create section container
        container, section_row = InputGroup.create(
            self.frame,
            "Database Configuration",
            "Configure OpenSearch and Logstash settings.",
            row=row,
            nesting_level=0,
        )

        # Local OpenSearch checkbox and panel
        checkbox, panel, widgets = DisableablePanel.create_checkbox_panel(
            container,
            "Use local OpenSearch instance",
            self.controller.set_use_local_opensearch,
            lambda: self.controller.model.use_local_opensearch,
            row=section_row,
            nesting_level=1,
        )
        self.register_component("use_local_opensearch_checkbox", checkbox)

        # Remote store configuration (shown when local OpenSearch is disabled)
        remote_container, remote_section_row = InputGroup.create(
            container,
            "Remote Document Store",
            "Configure remote OpenSearch or Elasticsearch connection.",
            row=section_row + 1,
            nesting_level=1,
        )

        # Store type selection
        store_var = customtkinter.StringVar(
            value=self.controller.model.remote_store_type
        )
        for i, (value, text) in enumerate(
            self.controller.model.REMOTE_STORE_TYPES.items()
        ):
            display_text = text.split(" - ")[1] if " - " in text else text
            radio = customtkinter.CTkRadioButton(
                remote_container,
                text=display_text,
                value=value,
                variable=store_var,
                command=lambda: self.controller.set_remote_store_type(store_var.get()),
            )
            radio.grid(
                row=remote_section_row + i,
                column=0,
                padx=PADDING_HIERARCHY_LEVEL_2,
                pady=(0, PADDING_SMALL),
                sticky="w",
            )

        self.register_component("store_type_var", store_var)
        remote_section_row += len(self.controller.model.REMOTE_STORE_TYPES)

        # Connection URL
        url_container, url_entry = InputField.create(
            remote_container,
            "Connection URL:",
            placeholder="https://192.168.1.123:9200",
            row=remote_section_row,
            validation_func=self.controller.set_connection_url,
            nesting_level=2,
        )
        self.register_component("connection_url_entry", url_entry)
        remote_section_row += 1

        # SSL Validation checkbox
        ssl_checkbox = ControlledCheckbox(
            remote_container,
            text="Require SSL validation",
            controller_set_method=self.controller.set_require_ssl_validation,
            controller_get_method=lambda: self.controller.model.require_ssl_validation,
        )
        ssl_checkbox.grid(
            row=remote_section_row,
            column=0,
            padx=PADDING_HIERARCHY_LEVEL_2,
            pady=(0, PADDING_SMALL),
            sticky="w",
        )
        self.register_component("require_ssl_validation_checkbox", ssl_checkbox)
        remote_section_row += 1

        # Kibana URL
        kibana_container, kibana_entry = InputField.create(
            remote_container,
            "Kibana URL:",
            placeholder="https://192.168.1.123:5601",
            row=remote_section_row,
            validation_func=self.controller.set_kibana_url,
            nesting_level=2,
        )
        self.register_component("kibana_url_entry", kibana_entry)
        remote_section_row += 1

        # Forward logs checkbox and panel
        forward_checkbox, forward_panel, forward_widgets = (
            DisableablePanel.create_checkbox_panel(
                container,
                "Forward logs to remote store",
                self.controller.set_forward_logs_to_remote,
                lambda: self.controller.model.forward_logs_to_remote,
                row=section_row + 2,
                nesting_level=1,
            )
        )
        self.register_component("forward_logs_checkbox", forward_checkbox)
        forward_section_row = 0

        # Secondary store type selection
        secondary_store_var = customtkinter.StringVar(
            value=self.controller.model.secondary_store_type
        )
        for i, (value, text) in enumerate(
            self.controller.model.REMOTE_STORE_TYPES.items()
        ):
            display_text = text.split(" - ")[1] if " - " in text else text
            radio = customtkinter.CTkRadioButton(
                forward_panel,
                text=display_text,
                value=value,
                variable=secondary_store_var,
                command=lambda: self.controller.set_secondary_store_type(
                    secondary_store_var.get()
                ),
            )
            radio.grid(
                row=forward_section_row + i,
                column=0,
                padx=PADDING_HIERARCHY_LEVEL_2,
                pady=(0, PADDING_SMALL),
                sticky="w",
            )

        self.register_component("secondary_store_type_var", secondary_store_var)
        forward_section_row += len(self.controller.model.REMOTE_STORE_TYPES)

        # Secondary URL
        secondary_url_container, secondary_url_entry = InputField.create(
            forward_panel,
            "Secondary URL:",
            placeholder="https://192.168.1.124:9200",
            row=forward_section_row,
            validation_func=self.controller.set_secondary_url,
            nesting_level=2,
        )
        self.register_component("secondary_url_entry", secondary_url_entry)
        forward_section_row += 1

        # Secondary SSL Validation checkbox
        secondary_ssl_checkbox = ControlledCheckbox(
            forward_panel,
            text="Require SSL validation for secondary store",
            controller_set_method=self.controller.set_secondary_ssl_validation,
            controller_get_method=lambda: self.controller.model.secondary_ssl_validation,
        )
        secondary_ssl_checkbox.grid(
            row=forward_section_row,
            column=0,
            padx=PADDING_HIERARCHY_LEVEL_2,
            pady=(0, PADDING_SMALL),
            sticky="w",
        )
        self.register_component(
            "secondary_ssl_validation_checkbox", secondary_ssl_checkbox
        )
        forward_section_row += 1

        # Logstash host:port
        logstash_container, logstash_entry = InputField.create(
            forward_panel,
            "Logstash Host:Port:",
            placeholder="192.168.1.124:5044",
            row=forward_section_row,
            validation_func=self.controller.set_logstash_host_port,
            nesting_level=2,
        )
        self.register_component("logstash_host_port_entry", logstash_entry)

        return row + 1

    def _create_resource_section(self, row: int) -> int:
        """Create the resource settings section"""
        # Create section container
        container, section_row = InputGroup.create(
            self.frame,
            "Resource Settings",
            "Configure memory and worker settings.",
            row=row,
            nesting_level=0,
        )

        # OpenSearch Memory
        os_mem_container, os_mem_entry = InputField.create(
            container,
            "OpenSearch Memory:",
            placeholder="2048",
            row=section_row,
            validation_func=self.controller.set_opensearch_memory,
            units_text="MB",
            nesting_level=1,
        )
        self.register_component("opensearch_memory_entry", os_mem_entry)
        section_row += 1

        # Logstash Memory
        ls_mem_container, ls_mem_entry = InputField.create(
            container,
            "Logstash Memory:",
            placeholder="2048",
            row=section_row,
            validation_func=self.controller.set_logstash_memory,
            units_text="MB",
            nesting_level=1,
        )
        self.register_component("logstash_memory_entry", ls_mem_entry)
        section_row += 1

        # Logstash Workers
        ls_workers_container, ls_workers_entry = InputField.create(
            container,
            "Logstash Workers:",
            placeholder="4",
            row=section_row,
            validation_func=self.controller.set_logstash_workers,
            nesting_level=1,
        )
        self.register_component("logstash_workers_entry", ls_workers_entry)

        return row + 1

    def _create_behavior_section(self, row: int) -> int:
        """Create the system behavior section"""
        # Create section container
        container, section_row = InputGroup.create(
            self.frame,
            "System Behavior",
            "Configure system restart and log rotation settings.",
            row=row,
            nesting_level=0,
        )

        # Auto-restart checkbox and panel
        checkbox, panel, widgets = DisableablePanel.create_checkbox_panel(
            container,
            "Enable automatic container restart",
            self.controller.set_auto_restart,
            lambda: self.controller.model.auto_restart,
            row=section_row,
            nesting_level=1,
        )
        self.register_component("auto_restart_checkbox", checkbox)

        # Restart behavior selection
        restart_var = customtkinter.StringVar(
            value=self.controller.model.restart_behavior
        )
        for i, (value, text) in enumerate(
            self.controller.model.RESTART_BEHAVIORS.items()
        ):
            display_text = text.split(" - ")[1] if " - " in text else text
            radio = customtkinter.CTkRadioButton(
                panel,
                text=display_text,
                value=value,
                variable=restart_var,
                command=lambda: self.controller.set_restart_behavior(restart_var.get()),
            )
            radio.grid(
                row=i,
                column=0,
                padx=PADDING_HIERARCHY_LEVEL_2,
                pady=(0, PADDING_SMALL),
                sticky="w",
            )

        self.register_component("restart_behavior_var", restart_var)

        return row + 1

    def _create_locations_section(self, row: int) -> int:
        """Create the system locations section"""
        # Create section container
        container, section_row = InputGroup.create(
            self.frame,
            "System Locations",
            "Configure paths for data storage and logs.",
            row=row,
            nesting_level=0,
        )

        # Default paths checkbox and panel
        checkbox, panel, widgets = DisableablePanel.create_checkbox_panel(
            container,
            "Use custom paths",
            lambda val: self.controller.set_use_default_paths(not val),
            lambda: not self.controller.model.use_default_paths,
            row=section_row,
            nesting_level=1,
        )
        self.register_component("use_default_paths_checkbox", checkbox)

        # Create path input fields
        paths = [
            (
                "OpenSearch Data Path:",
                "opensearch_path",
                self.controller.set_opensearch_path,
            ),
            ("Zeek Logs Path:", "zeek_path", self.controller.set_zeek_path),
            ("PCAP Storage Path:", "pcap_path", self.controller.set_pcap_path),
            ("Suricata Logs Path:", "suricata_path", self.controller.set_suricata_path),
            ("Index Path:", "index_path", self.controller.set_index_path),
            ("Snapshot Path:", "snapshot_path", self.controller.set_snapshot_path),
        ]

        for i, (label, component_name, validation_func) in enumerate(paths):
            container, entry = InputField.create(
                panel,
                label,
                placeholder=f"/path/to/{component_name}",
                row=i,
                validation_func=validation_func,
                nesting_level=2,
            )
            self.register_component(f"{component_name}_entry", entry)

        return row + 1

    def _create_index_management_section(self, row: int) -> int:
        """Create the index management section"""
        # Create section container
        container, section_row = InputGroup.create(
            self.frame,
            "Index Management",
            "Configure index settings and retention.",
            row=row,
            nesting_level=0,
        )

        # Index management checkbox and panel
        checkbox, panel, widgets = DisableablePanel.create_checkbox_panel(
            container,
            "Enable index management",
            self.controller.set_enable_index_management,
            lambda: self.controller.model.enable_index_management,
            row=section_row,
            nesting_level=1,
        )
        self.register_component("enable_index_management_checkbox", checkbox)
        panel_row = 0

        # Hot/Warm architecture checkbox
        hot_warm_checkbox, hot_warm_panel, hot_warm_widgets = (
            DisableablePanel.create_checkbox_panel(
                panel,
                "Use hot/warm architecture",
                self.controller.set_use_hot_warm,
                lambda: self.controller.model.use_hot_warm,
                row=panel_row,
                nesting_level=2,
            )
        )
        self.register_component("use_hot_warm_checkbox", hot_warm_checkbox)
        panel_row += 1

        # Hot duration
        hot_container, hot_entry = InputField.create(
            hot_warm_panel,
            "Hot Duration:",
            placeholder="24h",
            row=0,
            validation_func=self.controller.set_hot_duration,
            nesting_level=3,
        )
        self.register_component("hot_duration_entry", hot_entry)

        # SPI retention
        spi_container, spi_entry = InputField.create(
            panel,
            "SPI Retention:",
            placeholder="90d",
            row=panel_row,
            validation_func=self.controller.set_spi_retention,
            nesting_level=2,
        )
        self.register_component("spi_retention_entry", spi_entry)
        panel_row += 1

        # Segments to optimize
        segments_container, segments_entry = InputField.create(
            panel,
            "Segments to Optimize:",
            placeholder="4",
            row=panel_row,
            validation_func=self.controller.set_segments_to_optimize,
            nesting_level=2,
        )
        self.register_component("segments_to_optimize_entry", segments_entry)
        panel_row += 1

        # Replica count
        replica_container, replica_entry = InputField.create(
            panel,
            "Replica Count:",
            placeholder="1",
            row=panel_row,
            validation_func=self.controller.set_replica_count,
            nesting_level=2,
        )
        self.register_component("replica_count_entry", replica_entry)
        panel_row += 1

        # History weeks
        history_container, history_entry = InputField.create(
            panel,
            "History Weeks:",
            placeholder="12",
            row=panel_row,
            validation_func=self.controller.set_history_weeks,
            nesting_level=2,
        )
        self.register_component("history_weeks_entry", history_entry)

        return row + 1

    def _create_system_management_section(self, row: int) -> int:
        """Create the system management section"""
        # Create section container
        container, section_row = InputGroup.create(
            self.frame,
            "System Management",
            "Configure system-wide settings and thresholds.",
            row=row,
            nesting_level=0,
        )

        # Auto-delete indices checkbox and panel
        indices_checkbox, indices_panel, indices_widgets = (
            DisableablePanel.create_checkbox_panel(
                container,
                "Auto-delete indices",
                self.controller.set_auto_delete_indices,
                lambda: self.controller.model.auto_delete_indices,
                row=section_row,
                nesting_level=1,
            )
        )
        self.register_component("auto_delete_indices_checkbox", indices_checkbox)
        section_row += 1

        # Index size threshold
        threshold_container, threshold_entry = InputField.create(
            indices_panel,
            "Index Size Threshold:",
            placeholder="Enter size threshold",
            row=0,
            validation_func=self.controller.set_index_size_threshold,
            nesting_level=2,
        )
        self.register_component("index_size_threshold_entry", threshold_entry)

        # Use name for deletion checkbox
        name_checkbox = ControlledCheckbox(
            indices_panel,
            text="Use name for deletion",
            controller_set_method=self.controller.set_use_name_for_deletion,
            controller_get_method=lambda: self.controller.model.use_name_for_deletion,
        )
        name_checkbox.grid(
            row=1,
            column=0,
            padx=PADDING_HIERARCHY_LEVEL_2,
            pady=(0, PADDING_SMALL),
            sticky="w",
        )
        self.register_component("use_name_for_deletion_checkbox", name_checkbox)

        # Auto-delete PCAPs checkbox and panel
        pcaps_checkbox, pcaps_panel, pcaps_widgets = (
            DisableablePanel.create_checkbox_panel(
                container,
                "Auto-delete PCAPs",
                self.controller.set_auto_delete_pcaps,
                lambda: self.controller.model.auto_delete_pcaps,
                row=section_row,
                nesting_level=1,
            )
        )
        self.register_component("auto_delete_pcaps_checkbox", pcaps_checkbox)

        # PCAP size threshold
        pcap_threshold_container, pcap_threshold_entry = InputField.create(
            pcaps_panel,
            "PCAP Size Threshold:",
            placeholder="Enter size threshold",
            row=0,
            validation_func=self.controller.set_pcap_size_threshold,
            nesting_level=2,
        )
        self.register_component("pcap_size_threshold_entry", pcap_threshold_entry)

        return row + 1

    def _create_save_section(self, row: int) -> int:
        """Create the save button section"""
        save_container, next_row = self.create_save_button_section(
            self._save_settings, row
        )
        return next_row

    def _save_settings(self):
        """Save all system settings"""
        success, message = self.controller.save_settings()
        if success:
            self.show_success(message)
        else:
            self.show_error(message)

    # Update methods for controller to call
    def update_puid(self, value: int):
        """Update UI with current process user ID"""
        entry = self.get_component("puid_entry")
        if entry:
            entry.delete(0, "end")
            entry.insert(0, str(value))

    def update_pgid(self, value: int):
        """Update UI with current process group ID"""
        entry = self.get_component("pgid_entry")
        if entry:
            entry.delete(0, "end")
            entry.insert(0, str(value))

    def update_node_name(self, value: str):
        """Update UI with current node name"""
        entry = self.get_component("node_name_entry")
        if entry:
            entry.delete(0, "end")
            entry.insert(0, value)

    def update_profile(self, value: str):
        """Update UI with current profile selection"""
        var = self.get_component("profile_var")
        if var:
            var.set(value)

    def update_opensearch_memory(self, value: int):
        """Update UI with current OpenSearch memory allocation"""
        entry = self.get_component("opensearch_memory_entry")
        if entry:
            entry.delete(0, "end")
            entry.insert(0, str(value))

    def update_logstash_memory(self, value: int):
        """Update UI with current Logstash memory allocation"""
        entry = self.get_component("logstash_memory_entry")
        if entry:
            entry.delete(0, "end")
            entry.insert(0, str(value))

    def update_logstash_workers(self, value: int):
        """Update UI with current number of Logstash workers"""
        entry = self.get_component("logstash_workers_entry")
        if entry:
            entry.delete(0, "end")
            entry.insert(0, str(value))

    def update_auto_restart(self, value: bool):
        """Update UI with current auto-restart setting"""
        checkbox = self.get_component("auto_restart_checkbox")
        if checkbox:
            checkbox.refresh_from_controller()

    def update_restart_behavior(self, value: str):
        """Update UI with current restart behavior"""
        var = self.get_component("restart_behavior_var")
        if var:
            var.set(value)

    def update_use_default_paths(self, value: bool):
        """Update UI with current use default paths setting"""
        checkbox = self.get_component("use_default_paths_checkbox")
        if checkbox:
            checkbox.refresh_from_controller()

    def update_enable_index_management(self, value: bool):
        """Update UI with current index management setting"""
        checkbox = self.get_component("enable_index_management_checkbox")
        if checkbox:
            checkbox.refresh_from_controller()

    def update_use_hot_warm(self, value: bool):
        """Update UI with current hot/warm architecture setting"""
        checkbox = self.get_component("use_hot_warm_checkbox")
        if checkbox:
            checkbox.refresh_from_controller()

    def update_hot_duration(self, value: str):
        """Update UI with current hot duration"""
        entry = self.get_component("hot_duration_entry")
        if entry:
            entry.delete(0, "end")
            entry.insert(0, value)

    def update_spi_retention(self, value: str):
        """Update UI with current SPI retention"""
        entry = self.get_component("spi_retention_entry")
        if entry:
            entry.delete(0, "end")
            entry.insert(0, value)

    def update_segments_to_optimize(self, value: int):
        """Update UI with current segments to optimize"""
        entry = self.get_component("segments_to_optimize_entry")
        if entry:
            entry.delete(0, "end")
            entry.insert(0, str(value))

    def update_replica_count(self, value: int):
        """Update UI with current replica count"""
        entry = self.get_component("replica_count_entry")
        if entry:
            entry.delete(0, "end")
            entry.insert(0, str(value))

    def update_history_weeks(self, value: int):
        """Update UI with current history weeks"""
        entry = self.get_component("history_weeks_entry")
        if entry:
            entry.delete(0, "end")
            entry.insert(0, str(value))

    def update_auto_delete_indices(self, value: bool):
        """Update UI with current auto-delete indices setting"""
        checkbox = self.get_component("auto_delete_indices_checkbox")
        if checkbox:
            checkbox.refresh_from_controller()

    def update_index_size_threshold(self, value: str):
        """Update UI with current index size threshold"""
        entry = self.get_component("index_size_threshold_entry")
        if entry:
            entry.delete(0, "end")
            entry.insert(0, value)

    def update_use_name_for_deletion(self, value: bool):
        """Update UI with current use name for deletion setting"""
        checkbox = self.get_component("use_name_for_deletion_checkbox")
        if checkbox:
            checkbox.refresh_from_controller()

    def update_auto_delete_pcaps(self, value: bool):
        """Update UI with current auto-delete PCAPs setting"""
        checkbox = self.get_component("auto_delete_pcaps_checkbox")
        if checkbox:
            checkbox.refresh_from_controller()

    def update_pcap_size_threshold(self, value: str):
        """Update UI with current PCAP size threshold"""
        entry = self.get_component("pcap_size_threshold_entry")
        if entry:
            entry.delete(0, "end")
            entry.insert(0, value)

    def update_use_local_opensearch(self, value: bool):
        """Update UI with current local OpenSearch setting"""
        checkbox = self.get_component("use_local_opensearch_checkbox")
        if checkbox:
            checkbox.refresh_from_controller()

    def update_remote_store_type(self, value: str):
        """Update UI with current remote store type"""
        var = self.get_component("store_type_var")
        if var:
            var.set(value)

    def update_secondary_store_type(self, value: str):
        """Update UI with current secondary store type"""
        var = self.get_component("secondary_store_type_var")
        if var:
            var.set(value)

    def update_connection_url(self, value: str):
        """Update UI with current connection URL"""
        entry = self.get_component("connection_url_entry")
        if entry:
            entry.delete(0, "end")
            entry.insert(0, value)

    def update_require_ssl_validation(self, value: bool):
        """Update UI with current SSL validation setting"""
        checkbox = self.get_component("require_ssl_validation_checkbox")
        if checkbox:
            checkbox.refresh_from_controller()

    def update_kibana_url(self, value: str):
        """Update UI with current Kibana URL"""
        entry = self.get_component("kibana_url_entry")
        if entry:
            entry.delete(0, "end")
            entry.insert(0, value)

    def update_forward_logs_to_remote(self, value: bool):
        """Update UI with current forward logs setting"""
        checkbox = self.get_component("forward_logs_checkbox")
        if checkbox:
            checkbox.refresh_from_controller()

    def update_secondary_url(self, value: str):
        """Update UI with current secondary URL"""
        entry = self.get_component("secondary_url_entry")
        if entry:
            entry.delete(0, "end")
            entry.insert(0, value)

    def update_secondary_ssl_validation(self, value: bool):
        """Update UI with current secondary SSL validation setting"""
        checkbox = self.get_component("secondary_ssl_validation_checkbox")
        if checkbox:
            checkbox.refresh_from_controller()

    def update_logstash_host_port(self, value: str):
        """Update UI with current Logstash host:port"""
        entry = self.get_component("logstash_host_port_entry")
        if entry:
            entry.delete(0, "end")
            entry.insert(0, value)
