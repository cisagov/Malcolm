import os
import customtkinter
from typing import Callable, Optional, Dict

from controllers.auth_controller import AuthController
from views.base_view import BaseView


class AuthView(BaseView):
    """View for Malcolm authentication settings"""

    def __init__(self, parent, controller: AuthController):
        """
        Initialize with parent frame and controller

        Args:
            parent: The parent tkinter widget
            controller: The authentication controller
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
            text="Authentication Configuration",
            font=customtkinter.CTkFont(size=20, weight="bold"),
        )
        title.grid(row=0, column=0, columnspan=3, padx=20, pady=(20, 10), sticky="w")

        # Description
        description = customtkinter.CTkLabel(
            self.frame,
            text="Configure authentication settings for Malcolm",
            font=customtkinter.CTkFont(size=12),
        )
        description.grid(
            row=1, column=0, columnspan=3, padx=20, pady=(0, 20), sticky="w"
        )

        # Create sections
        current_row = self._create_auth_method_section(row=2)
        current_row = self._create_https_section(row=current_row)

        # Save button
        self.save_button = customtkinter.CTkButton(
            self.frame, text="Save Settings", command=self._on_save
        )
        self.save_button.grid(row=current_row, column=2, padx=10, pady=20, sticky="e")

    def _create_auth_method_section(self, row: int) -> int:
        """
        Create the authentication method section

        Args:
            row: The starting row

        Returns:
            int: The next available row
        """
        # Section header
        section_label = customtkinter.CTkLabel(
            self.frame,
            text="Authentication Method",
            font=customtkinter.CTkFont(size=16, weight="bold"),
        )
        section_label.grid(
            row=row, column=0, columnspan=3, padx=20, pady=(20, 5), sticky="w"
        )
        row += 1

        # Description
        description = customtkinter.CTkLabel(
            self.frame,
            text="Select the authentication method for Malcolm",
            font=customtkinter.CTkFont(size=12),
        )
        description.grid(
            row=row, column=0, columnspan=3, padx=20, pady=(0, 10), sticky="w"
        )
        row += 1

        # Auth method label
        auth_method_label = customtkinter.CTkLabel(
            self.frame, text="Authentication Method:"
        )
        auth_method_label.grid(row=row, column=0, padx=(20, 5), pady=5, sticky="w")

        # Auth method dropdown
        auth_method_values = list(self.controller.model.AUTH_METHODS.values())
        self.auth_method_var = customtkinter.StringVar(
            value=auth_method_values[0]
        )  # Default to first option
        self.auth_method_dropdown = customtkinter.CTkOptionMenu(
            self.frame,
            values=auth_method_values,
            variable=self.auth_method_var,
            command=self._on_auth_method_change,
            width=300,
        )
        self.auth_method_dropdown.grid(row=row, column=1, padx=5, pady=5, sticky="w")
        row += 1

        return row

    def _create_https_section(self, row: int) -> int:
        """
        Create the HTTPS settings section

        Args:
            row: The starting row

        Returns:
            int: The next available row
        """
        # Section header
        section_label = customtkinter.CTkLabel(
            self.frame,
            text="HTTPS Configuration",
            font=customtkinter.CTkFont(size=16, weight="bold"),
        )
        section_label.grid(
            row=row, column=0, columnspan=3, padx=20, pady=(20, 5), sticky="w"
        )
        row += 1

        # Description
        description = customtkinter.CTkLabel(
            self.frame,
            text="Configure HTTPS and reverse proxy settings",
            font=customtkinter.CTkFont(size=12),
        )
        description.grid(
            row=row, column=0, columnspan=3, padx=20, pady=(0, 10), sticky="w"
        )
        row += 1

        # Use HTTPS checkbox
        self.use_https_var = customtkinter.BooleanVar(value=True)
        self.use_https_checkbox = customtkinter.CTkCheckBox(
            self.frame,
            text="Require encrypted HTTPS connections",
            variable=self.use_https_var,
            command=self._on_use_https_change,
            onvalue=True,
            offvalue=False,
        )
        self.use_https_checkbox.grid(
            row=row, column=0, columnspan=2, padx=(20, 5), pady=5, sticky="w"
        )
        row += 1

        # Behind reverse proxy checkbox
        self.behind_reverse_proxy_var = customtkinter.BooleanVar(value=False)
        self.behind_reverse_proxy_checkbox = customtkinter.CTkCheckBox(
            self.frame,
            text="Malcolm is running behind another reverse proxy (Traefik, Caddy, etc.)",
            variable=self.behind_reverse_proxy_var,
            command=self._on_behind_reverse_proxy_change,
            onvalue=True,
            offvalue=False,
        )
        self.behind_reverse_proxy_checkbox.grid(
            row=row, column=0, columnspan=2, padx=(20, 5), pady=5, sticky="w"
        )
        row += 1

        return row

    def _on_auth_method_change(self, value: str):
        """Handle auth method change"""
        # Convert display name back to key
        method_key = None
        for key, display in self.controller.model.AUTH_METHODS.items():
            if display == value:
                method_key = key
                break

        if method_key:
            success, message = self.controller.set_auth_method(method_key)
            if not success:
                self.status_label.configure(text=f"Error: {message}")
            else:
                self.status_label.configure(text="")

    def _on_use_https_change(self):
        """Handle HTTPS checkbox change"""
        value = self.use_https_var.get()
        success, message = self.controller.set_use_https(value)
        if not success:
            self.status_label.configure(text=f"Error: {message}")
        else:
            self.status_label.configure(text="")

    def _on_behind_reverse_proxy_change(self):
        """Handle reverse proxy checkbox change"""
        value = self.behind_reverse_proxy_var.get()
        success, message = self.controller.set_behind_reverse_proxy(value)
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

    def update_auth_method(self, method: str):
        """Update the auth method dropdown with the model value"""
        # Get the display name for the method key
        display_name = self.controller.model.AUTH_METHODS.get(method, "Basic")
        self.auth_method_var.set(display_name)

    def update_use_https(self, value: bool):
        """Update the HTTPS checkbox with the model value"""
        self.use_https_var.set(value)

    def update_behind_reverse_proxy(self, value: bool):
        """Update the reverse proxy checkbox with the model value"""
        self.behind_reverse_proxy_var.set(value)
