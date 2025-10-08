#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Base View
==========

Base class for all views in the Malcolm installer GUI.
Provides common functionality and structure for views.
"""

import customtkinter
from typing import Dict, Any, Optional, Callable, Union, List, Tuple

from components.styles import PADDING_LARGE, PADDING_MEDIUM, PADDING_SMALL
from components.frame import Frame
from components.label import Label


class BaseView:
    """Base class for all views in the Malcolm installer GUI"""

    def __init__(self, parent, controller):
        """
        Initialize with parent frame and controller

        Args:
            parent: The parent tkinter widget
            controller: The controller for this view
        """
        self.parent = parent
        self.controller = controller
        self.frame = None
        self.status_label = None
        self.error_label = None

        # Component registry for easy access and management
        self.components = {}

        # Section registry to track UI sections
        self.sections = {}

        # Create the main frame
        self.create_ui()

    def create_ui(self):
        """
        Create the main UI frame for the view.
        Each view should override this method to set up their specific UI.
        """
        self.frame = Frame.create_tab(self.parent)
        return self.frame

    def setup_ui(self):
        """
        Set up UI components for the view.
        Each view should override this method to create their specific UI components.
        Should be called after create_ui().
        """
        pass

    def register_component(self, name: str, component: Any) -> Any:
        """
        Register a component in the component registry for easy access

        Args:
            name: The name/key to use for this component
            component: The component to register

        Returns:
            The component that was registered
        """
        self.components[name] = component
        return component

    def get_component(self, name: str) -> Any:
        """
        Get a component from the registry by name

        Args:
            name: The name of the component to retrieve

        Returns:
            The component, or None if not found
        """
        return self.components.get(name, None)

    def register_section(
        self, name: str, section_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Register a UI section for tracking and management

        Args:
            name: The name of the section
            section_data: Dictionary with section information (container, components, etc.)

        Returns:
            The section data dictionary
        """
        self.sections[name] = section_data
        return section_data

    def get_section(self, name: str) -> Dict[str, Any]:
        """
        Get a section by name

        Args:
            name: The name of the section to retrieve

        Returns:
            The section data dictionary, or None if not found
        """
        return self.sections.get(name, None)

    def update_section_visibility(self, section_name: str, visible: bool):
        """
        Show or hide a UI section

        Args:
            section_name: The name of the section to update
            visible: Whether to show (True) or hide (False) the section
        """
        section = self.get_section(section_name)
        if not section or "container" not in section:
            return

        if visible:
            # Check if grid_info exists and restore the original placement
            if "grid_info" in section:
                section["container"].grid(**section["grid_info"])
            else:
                # Default placement if no grid info stored
                section["container"].grid(sticky="ew")
        else:
            # Store current grid placement before hiding
            if "container" in section and hasattr(section["container"], "grid_info"):
                # Save the current grid info if visible
                try:
                    grid_info = section["container"].grid_info()
                    if grid_info:  # Only save if it's actually in the grid
                        section["grid_info"] = grid_info
                except Exception:
                    pass

            # Remove from grid
            section["container"].grid_remove()

    def create_section_container(
        self, parent=None, section_name: str = None
    ) -> customtkinter.CTkFrame:
        """
        Create a container frame for a UI section with optional registration

        Args:
            parent: The parent widget (defaults to self.frame if None)
            section_name: Optional name to register this section

        Returns:
            The created container frame
        """
        parent = parent or self.frame
        container = Frame.create(parent)

        if section_name:
            self.register_section(
                section_name, {"container": container, "components": {}}
            )

        return container

    def set_widget_state(self, widget: Any, enabled: bool):
        """
        Enable or disable a widget and all its children

        Args:
            widget: The widget to enable/disable
            enabled: Whether to enable (True) or disable (False)
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
            except ValueError:
                # Skip configuration if the widget doesn't support the attribute
                pass

        # Then handle all children
        for child in widget.winfo_children():
            self.set_widget_state(child, enabled)

    def update_dependent_widgets(self, condition: bool, widgets: List[Any]):
        """
        Update the state of widgets that depend on a condition

        Args:
            condition: The condition to check
            widgets: List of widgets to enable/disable based on the condition
        """
        for widget in widgets:
            self.set_widget_state(widget, condition)

    def show_error(self, message: str, duration: int = 5000):
        """
        Display an error message with automatic clearing

        Args:
            message: The error message to display
            duration: How long to display the message in milliseconds (0 for no auto-clear)
        """
        if not self.error_label:
            self.error_label = Label.error(self.frame, "")

            # Try to place at the bottom of the current view
            if hasattr(self.frame, "_grid_widgets"):
                self.error_label.grid(
                    row=len(self.frame._grid_widgets) + 1,
                    column=0,
                    padx=PADDING_LARGE,
                    pady=PADDING_SMALL,
                    sticky="w",
                )
            else:
                # Fallback if row count not available
                self.error_label.pack(
                    padx=PADDING_LARGE, pady=PADDING_SMALL, anchor="w"
                )

        self.error_label.configure(text=f"Error: {message}")

        # Clear the error after specified duration (if not 0)
        if duration > 0:
            self.frame.after(duration, lambda: self.error_label.configure(text=""))

    def show_success(self, message: str, duration: int = 5000):
        """
        Display a success message with automatic clearing

        Args:
            message: The success message to display
            duration: How long to display the message in milliseconds (0 for no auto-clear)
        """
        if not self.status_label:
            self.status_label = Label.success(self.frame, "")

            # Try to place at the bottom of the current view
            if hasattr(self.frame, "_grid_widgets"):
                self.status_label.grid(
                    row=len(self.frame._grid_widgets),
                    column=0,
                    padx=PADDING_LARGE,
                    pady=PADDING_SMALL,
                    sticky="w",
                )
            else:
                # Fallback if row count not available
                self.status_label.pack(
                    padx=PADDING_LARGE, pady=PADDING_SMALL, anchor="w"
                )

        self.status_label.configure(text=f"✓ {message}")

        # Clear the success message after specified duration (if not 0)
        if duration > 0:
            self.frame.after(duration, lambda: self.status_label.configure(text=""))

    def add_title_and_description(self, title: str, description: str) -> int:
        """
        Add title and description to the view

        Args:
            title: The title text
            description: The description text

        Returns:
            The next available row number
        """
        row = 0

        # Add title
        Label.title(self.frame, title, row)
        row += 1

        # Add description
        Label.description(self.frame, description, row)
        row += 1

        return row

    def create_save_button_section(
        self, callback: Callable, row: int
    ) -> Tuple[customtkinter.CTkFrame, int]:
        """
        Create a save button section with status label

        Args:
            callback: The function to call when save button is clicked
            row: The row to place the section

        Returns:
            Tuple of (container frame, next row)
        """
        # Create container for save button and status
        save_container = customtkinter.CTkFrame(self.frame, fg_color="transparent")
        save_container.grid(
            row=row, column=0, padx=PADDING_LARGE, pady=PADDING_LARGE, sticky="ew"
        )

        # Create save button
        save_button = customtkinter.CTkButton(
            save_container, text="Save Settings", command=callback, width=200
        )
        save_button.grid(row=0, column=0, padx=0, pady=0)

        # Create status label
        status_label = customtkinter.CTkLabel(
            save_container, text="", text_color=("green", "green")
        )
        status_label.grid(row=0, column=1, padx=PADDING_MEDIUM, pady=0, sticky="w")

        # Register components
        self.register_component("save_button", save_button)
        self.status_label = status_label
        self.register_component("status_label", status_label)
        self.register_component("save_container", save_container)

        return save_container, row + 1
