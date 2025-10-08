#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2025 Battelle Energy Alliance, LLC.  All rights reserved.

"""
Installation View
==============

View for Malcolm installation process, showing status and output of the installation.
"""

import os
import customtkinter
from typing import Callable, Optional, Dict

from controllers.installation_controller import InstallationController
from views.base_view import BaseView


class InstallationView(BaseView):
    """View for Malcolm installation process"""

    def __init__(self, parent, controller: InstallationController):
        """
        Initialize with parent frame and controller

        Args:
            parent: The parent tkinter widget
            controller: The installation controller
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
            text="Malcolm Installation",
            font=customtkinter.CTkFont(size=20, weight="bold"),
        )
        title.grid(row=0, column=0, columnspan=3, padx=20, pady=(20, 10), sticky="w")

        # Description
        description = customtkinter.CTkLabel(
            self.frame,
            text="Install Malcolm with your configured settings",
            font=customtkinter.CTkFont(size=12),
        )
        description.grid(
            row=1, column=0, columnspan=3, padx=20, pady=(0, 20), sticky="w"
        )

        # Installation status section
        self._create_status_section(row=2)

        # Installation output section
        self._create_output_section(row=5)

        # Buttons section
        self._create_button_section(row=7)

    def _create_status_section(self, row: int) -> int:
        """
        Create the installation status section

        Args:
            row: The starting row

        Returns:
            int: The next available row
        """
        # Section header
        section_label = customtkinter.CTkLabel(
            self.frame,
            text="Installation Status",
            font=customtkinter.CTkFont(size=16, weight="bold"),
        )
        section_label.grid(
            row=row, column=0, columnspan=3, padx=20, pady=(20, 5), sticky="w"
        )
        row += 1

        # Status frame
        status_frame = customtkinter.CTkFrame(self.frame)
        status_frame.grid(
            row=row, column=0, columnspan=3, padx=20, pady=10, sticky="ew"
        )

        # Status label
        status_label = customtkinter.CTkLabel(
            status_frame, text="Status:", font=customtkinter.CTkFont(size=14)
        )
        status_label.grid(row=0, column=0, padx=10, pady=10, sticky="w")

        # Status value
        self.status_value = customtkinter.CTkLabel(
            status_frame,
            text="Not Started",
            font=customtkinter.CTkFont(size=14, weight="bold"),
        )
        self.status_value.grid(row=0, column=1, padx=10, pady=10, sticky="w")

        row += 1

        # Status message
        self.status_message = customtkinter.CTkLabel(
            self.frame, text="", font=customtkinter.CTkFont(size=12)
        )
        self.status_message.grid(
            row=row, column=0, columnspan=3, padx=20, pady=(0, 10), sticky="w"
        )

        row += 1
        return row

    def _create_output_section(self, row: int) -> int:
        """
        Create the installation output section

        Args:
            row: The starting row

        Returns:
            int: The next available row
        """
        # Section header
        section_label = customtkinter.CTkLabel(
            self.frame,
            text="Installation Output",
            font=customtkinter.CTkFont(size=16, weight="bold"),
        )
        section_label.grid(
            row=row, column=0, columnspan=3, padx=20, pady=(20, 5), sticky="w"
        )
        row += 1

        # Output text box
        self.output_textbox = customtkinter.CTkTextbox(
            self.frame,
            width=800,
            height=300,
            font=customtkinter.CTkFont(family="Courier", size=12),
        )
        self.output_textbox.grid(
            row=row, column=0, columnspan=3, padx=20, pady=10, sticky="nsew"
        )
        self.output_textbox.configure(state="disabled")  # Read-only initially

        # Make the output section expand with the window
        self.frame.grid_rowconfigure(row, weight=1)
        self.frame.grid_columnconfigure(2, weight=1)

        row += 1
        return row

    def _create_button_section(self, row: int) -> int:
        """
        Create the buttons section

        Args:
            row: The starting row

        Returns:
            int: The next available row
        """
        # Button frame
        button_frame = customtkinter.CTkFrame(self.frame, fg_color="transparent")
        button_frame.grid(row=row, column=0, columnspan=3, padx=20, pady=20, sticky="e")

        # Start installation button
        self.start_button = customtkinter.CTkButton(
            button_frame,
            text="Start Installation",
            command=self.start_installation,
            fg_color="#2fa572",  # Green color
            hover_color="#268c61",  # Darker green on hover
        )
        self.start_button.grid(row=0, column=0, padx=(0, 10), pady=0)

        # Cancel installation button
        self.cancel_button = customtkinter.CTkButton(
            button_frame,
            text="Cancel Installation",
            command=self._on_cancel,
            state="disabled",
            fg_color="#d9534f",  # Red color
            hover_color="#c9302c",  # Darker red on hover
        )
        self.cancel_button.grid(row=0, column=1, padx=0, pady=0)

        row += 1
        return row

    def start_installation(self):
        """Start the installation process"""
        success, message = self.controller.start_installation()
        if success:
            self.start_button.configure(state="disabled")
            self.cancel_button.configure(state="normal")
        else:
            self.show_error(message)

    def _on_cancel(self):
        """Handle cancel button click"""
        success, message = self.controller.cancel_installation()
        if success:
            self.cancel_button.configure(state="disabled")
            self.start_button.configure(state="normal")
        else:
            self.show_error(message)

    def update_installation_status(self, status: str, message: str):
        """
        Update the installation status display

        Args:
            status: The current status (Not Started, In Progress, Complete, Failed)
            message: The status message to display
        """
        self.status_value.configure(text=status)

        # Set color based on status
        if status == "Complete":
            self.status_value.configure(text_color="#2fa572")  # Green
        elif status == "Failed":
            self.status_value.configure(text_color="#d9534f")  # Red
        elif status == "In Progress":
            self.status_value.configure(text_color="#0275d8")  # Blue
        else:
            self.status_value.configure(text_color="gray")  # Default

        self.status_message.configure(text=message)

        # Update buttons based on status
        if status == "In Progress":
            self.start_button.configure(state="disabled")
            self.cancel_button.configure(state="normal")
        elif status == "Complete" or status == "Failed":
            self.start_button.configure(state="normal")
            self.cancel_button.configure(state="disabled")
        else:  # Not Started
            self.start_button.configure(state="normal")
            self.cancel_button.configure(state="disabled")

    def update_installation_output(self, output: str):
        """
        Update the installation output display

        Args:
            output: The output text to display
        """
        self.output_textbox.configure(state="normal")
        self.output_textbox.delete("0.0", "end")
        self.output_textbox.insert("0.0", output)
        self.output_textbox.configure(state="disabled")
        self.output_textbox.see("end")  # Scroll to the end

    def show_error(self, message: str):
        """
        Display an error message

        Args:
            message: The error message to display
        """
        self.status_label.configure(text=message, text_color="red")

    def show_success(self, message: str):
        """
        Display a success message

        Args:
            message: The success message to display
        """
        self.status_label.configure(text=message, text_color="green")
