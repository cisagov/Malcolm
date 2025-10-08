#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Welcome View
==========

Welcome view for the Malcolm installer, providing introduction and system requirements check.
"""

import customtkinter
import os
from PIL import Image
from controllers.welcome_controller import WelcomeController
from scripts.malcolm_common import GetMalcolmDir
from views.base_view import BaseView


class WelcomeView(BaseView):
    """View for the Malcolm welcome screen."""

    def __init__(self, parent, controller: WelcomeController):
        """
        Initialize with parent frame and controller.

        Args:
            parent: The parent tkinter widget
            controller: The welcome controller
        """
        super().__init__(parent, controller)

        # Create the main frame
        self.frame = customtkinter.CTkFrame(parent)
        self.frame.pack(fill="both", expand=True, padx=20, pady=20)

        # Set up the layout
        self._create_ui()

        # Status message at the bottom of the screen
        self.status_label = customtkinter.CTkLabel(self.frame, text="")
        self.status_label.pack(side="bottom", padx=10, pady=(10, 10), anchor="w")

        # Register with controller AFTER UI elements are created
        self.controller.set_view(self)

    def _create_ui(self):
        """Create all UI elements."""
        # Center content frame
        self.content_frame = customtkinter.CTkFrame(self.frame, fg_color="transparent")
        self.content_frame.pack(fill="both", expand=True, padx=20, pady=20)

        # Logo
        try:
            # Get the base project directory using the utility function
            Malcolm_dir = GetMalcolmDir()

            # Use relative path from the project base
            logo_path = os.path.join(
                Malcolm_dir, "docs", "images", "logo", "Malcolm_banner.png"
            )

            if os.path.exists(logo_path):
                logo_image = customtkinter.CTkImage(
                    light_image=Image.open(logo_path),
                    dark_image=Image.open(logo_path),
                    size=(500, 150),  # Adjusted size for the banner
                )
                logo_label = customtkinter.CTkLabel(
                    self.content_frame,
                    image=logo_image,
                    text="",  # No text, just the image
                )
                logo_label.pack(pady=(20, 10))
            else:
                print(f"Logo not found at: {logo_path}")
        except Exception as e:
            print(f"Error loading logo: {e}")

        # Title
        title = customtkinter.CTkLabel(
            self.content_frame,
            text="Welcome to Malcolm",
            font=customtkinter.CTkFont(size=24, weight="bold"),
        )
        title.pack(pady=(10, 20))

        # Description
        description = customtkinter.CTkLabel(
            self.content_frame,
            text="Malcolm is a powerful, easily deployable network traffic analysis tool suite for\nfull packet capture artifacts (PCAP files) and Zeek logs.",
            font=customtkinter.CTkFont(size=14),
            wraplength=600,
        )
        description.pack(pady=(0, 20))

        # Installer description
        installer_desc = customtkinter.CTkLabel(
            self.content_frame,
            text="This installer will guide you through the process of setting up Malcolm on your system.",
            font=customtkinter.CTkFont(size=14),
            wraplength=600,
        )
        installer_desc.pack(pady=(0, 20))

        # Configuration areas frame
        config_frame = customtkinter.CTkFrame(
            self.content_frame, fg_color="transparent"
        )
        config_frame.pack(pady=(10, 30))

        # Configuration bulletpoints
        bullet_points = [
            "• Database: Configure the OpenSearch/Elasticsearch database settings",
            "• Network: Set up Docker networking and port configurations",
            "• Authentication: Configure authentication methods (LDAP or basic auth)",
        ]

        for point in bullet_points:
            bullet = customtkinter.CTkLabel(
                config_frame,
                text=point,
                font=customtkinter.CTkFont(size=14),
                anchor="w",
            )
            bullet.pack(pady=5, anchor="w")

        # Get Started button
        self.get_started_button = customtkinter.CTkButton(
            self.content_frame,
            text="Get Started →",
            command=self._on_continue,
            height=40,
            width=150,
        )
        self.get_started_button.pack(pady=(20, 0))

    def update_system_info(self, info):
        """
        Update the system information display.

        Args:
            info: Dictionary with system information
        """
        # We're not showing system info in this simplified view
        # This is just kept for compatibility with the controller
        pass

    def _on_continue(self):
        """Handle get started button click."""
        success, message = self.controller.mark_introduction_read()
        if success:
            # Navigate to next tab
            # The main application will handle this when detecting navigation events
            pass
        else:
            self.show_error(message)

    def show_error(self, message):
        """
        Display an error message.

        Args:
            message: The error message to display
        """
        self.status_label.configure(text=message, text_color="red")

    def show_success(self, message):
        """
        Display a success message.

        Args:
            message: The success message to display
        """
        self.status_label.configure(text=message, text_color="green")
