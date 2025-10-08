#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Input Field Components
=====================

Provides enhanced input field components with various configurations.
"""

import os
import customtkinter
from tkinter import filedialog
from typing import Callable, Optional, Union, Tuple, Any

from components.styles import *
from .font_manager import FontManager
from .frame import Frame
from .button import Button
from .label import Label


class InputField:
    """
    Enhanced component for creating input fields with various configurations.

    Features:
    - Optional browse button for directory/file selection
    - Optional units label
    - Built-in validation
    - Consistent styling
    """

    @staticmethod
    def create(
        parent: Any,
        label_text: str,
        placeholder: str = "",
        width: int = 300,
        row: Optional[int] = None,
        column: int = 0,
        sticky: str = "ew",
        browse_button: bool = False,
        browse_type: str = "directory",
        browse_callback: Optional[Callable] = None,
        on_change: Optional[Callable] = None,
        validation_func: Optional[Callable] = None,
        units_text: Optional[str] = None,
        initial_value: str = "",
        nesting_level: int = 0,
    ) -> Tuple[customtkinter.CTkFrame, customtkinter.CTkEntry]:
        """
        Create an enhanced input field with various options

        Args:
            parent: The parent frame/widget
            label_text: Text for the label
            placeholder: Placeholder text for the input field
            width: Width of the input field (default: 400)
            row: Row number for grid layout (optional)
            column: Column number for grid layout (default: 0)
            sticky: Sticky parameter for grid layout (default: "ew")
            browse_button: Whether to add a browse button (default: False)
            browse_type: Type of browse functionality - "directory", "file", or "save" (default: "directory")
            browse_callback: Custom callback for browse button (default: None, uses built-in browser)
            on_change: Callback when input value changes (default: None)
            validation_func: Function to validate input (default: None)
            units_text: Optional text for units label (e.g., "GB", "MB")
            initial_value: Initial value for the input field (default: "")
            nesting_level: Hierarchical nesting level (0=top, 1=first indent, etc.)

        Returns:
            tuple: (container, entry_widget) - The container frame and the entry widget
        """
        # Create container frame
        container = customtkinter.CTkFrame(parent, fg_color="transparent")

        # Choose padding based on nesting level
        if nesting_level == 0:
            container_padding = PADDING_HIERARCHY_BASE
        elif nesting_level == 1:
            container_padding = PADDING_HIERARCHY_LEVEL_1
        elif nesting_level == 2:
            container_padding = PADDING_HIERARCHY_LEVEL_2
        else:
            container_padding = PADDING_HIERARCHY_LEVEL_3

        # Configure grid columns based on components
        col_count = 1  # Label column
        col_count += 1  # Entry column
        if browse_button:
            col_count += 1  # Browse button column
        if units_text:
            col_count += 1  # Units column

        # Configure column weights
        container.grid_columnconfigure(0, weight=0)  # Label column (fixed)
        container.grid_columnconfigure(1, weight=1)  # Entry column (expandable)
        for i in range(2, col_count):
            container.grid_columnconfigure(i, weight=0)  # Other columns (fixed)

        # Position the container if row is specified
        if row is not None:
            container.grid(
                row=row,
                column=column,
                sticky=sticky,
                padx=container_padding,  # Use nesting-appropriate padding
                pady=PADDING_SMALL,
            )

        # Create label
        label = Label.bold(container, label_text)
        label.grid(row=0, column=0, padx=(0, 10), pady=10, sticky="w")

        # Create entry field
        entry = customtkinter.CTkEntry(
            container, placeholder_text=placeholder, width=width
        )
        entry.grid(row=0, column=1, padx=5, pady=10, sticky="ew")

        # Set initial value if provided
        if initial_value:
            entry.delete(0, "end")
            entry.insert(0, initial_value)

        # Column tracker for additional components
        next_col = 2

        # Add browse button if requested
        if browse_button:
            if browse_callback is None:
                # Use default browse behavior based on browse_type
                if browse_type == "directory":
                    browse_callback = lambda: InputField._browse_directory(entry)
                elif browse_type == "file":
                    browse_callback = lambda: InputField._browse_file(entry)
                elif browse_type == "save":
                    browse_callback = lambda: InputField._browse_save_file(entry)

            browse_btn = Button.create(
                container, text="Browse", command=browse_callback, width=80
            )
            browse_btn.grid(row=0, column=next_col, padx=(10, 0), pady=10, sticky="e")
            next_col += 1

        # Add units label if requested
        if units_text:
            units_label = Label.regular(container, units_text)
            units_label.grid(row=0, column=next_col, padx=(5, 0), pady=10, sticky="w")

        # Set up validation and change events
        if validation_func or on_change:

            def _on_focus_out(event):
                value = entry.get().strip()

                # Call validation function if provided
                if validation_func:
                    is_valid, message = validation_func(value)
                    if not is_valid and message:
                        # Show validation error (using nearest parent with show_error method)
                        InputField._show_error_in_parent(container, message)

                # Call on_change callback if provided
                if on_change:
                    on_change(value)

            entry.bind("<FocusOut>", _on_focus_out)

        return container, entry

    @staticmethod
    def _browse_directory(entry_widget):
        """
        Open directory browser and update entry widget

        Args:
            entry_widget: The entry widget to update
        """
        # Get the current path from the entry, if any
        current_path = entry_widget.get().strip()
        initial_dir = (
            current_path
            if current_path and os.path.exists(current_path)
            else os.path.expanduser("~")
        )

        # Open directory browser
        path = filedialog.askdirectory(initialdir=initial_dir)

        # Update entry if a path was selected
        if path:
            entry_widget.delete(0, "end")
            entry_widget.insert(0, path)

            # Trigger focus out event to run validation
            entry_widget.event_generate("<FocusOut>")

    @staticmethod
    def _browse_file(entry_widget, file_types=None):
        """
        Open file browser and update entry widget

        Args:
            entry_widget: The entry widget to update
            file_types: List of file types to show, e.g., [("Text files", "*.txt")]
        """
        # Get the current path from the entry, if any
        current_path = entry_widget.get().strip()
        initial_dir = (
            os.path.dirname(current_path) if current_path else os.path.expanduser("~")
        )

        # Open file browser
        if not file_types:
            file_types = [("All files", "*.*")]

        path = filedialog.askopenfilename(initialdir=initial_dir, filetypes=file_types)

        # Update entry if a file was selected
        if path:
            entry_widget.delete(0, "end")
            entry_widget.insert(0, path)

            # Trigger focus out event to run validation
            entry_widget.event_generate("<FocusOut>")

    @staticmethod
    def _browse_save_file(entry_widget, file_types=None, default_ext=None):
        """
        Open save file dialog and update entry widget

        Args:
            entry_widget: The entry widget to update
            file_types: List of file types to show, e.g., [("Text files", "*.txt")]
            default_ext: Default extension to add
        """
        # Get the current path from the entry, if any
        current_path = entry_widget.get().strip()
        initial_dir = (
            os.path.dirname(current_path) if current_path else os.path.expanduser("~")
        )
        initial_file = os.path.basename(current_path) if current_path else ""

        # Open save file dialog
        if not file_types:
            file_types = [("All files", "*.*")]

        path = filedialog.asksaveasfilename(
            initialdir=initial_dir,
            initialfile=initial_file,
            filetypes=file_types,
            defaultextension=default_ext,
        )

        # Update entry if a path was selected
        if path:
            entry_widget.delete(0, "end")
            entry_widget.insert(0, path)

            # Trigger focus out event to run validation
            entry_widget.event_generate("<FocusOut>")

    @staticmethod
    def _show_error_in_parent(widget, message):
        """
        Find the nearest parent with show_error method and display the error

        Args:
            widget: The widget to start searching from
            message: The error message to display
        """
        current = widget

        # Try to find a parent with show_error method
        while current:
            # Check if parent has show_error method
            if hasattr(current, "show_error") and callable(current.show_error):
                current.show_error(message)
                return

            # Move up to parent
            if hasattr(current, "master"):
                current = current.master
            else:
                break

        # If no parent with show_error found, use basic error display
        print(f"Validation error: {message}")


class InputGroup:
    """
    Group of related input fields with a label
    """

    @staticmethod
    def create(
        parent,
        title: str,
        description: Optional[str] = None,
        row: Optional[int] = None,
        column: int = 0,
        nesting_level: int = 0,
    ) -> Tuple[customtkinter.CTkFrame, int]:
        """
        Create a container for a group of related input fields

        Args:
            parent: The parent frame/widget
            title: Title for the group
            description: Optional description text
            row: Row number for grid layout (optional)
            column: Column number for grid layout (default: 0)
            nesting_level: Hierarchical nesting level (0=top, 1=first indent, etc.)

        Returns:
            tuple: (container, next_row) - The container frame and the next row number (starting at 0)
        """
        # Create the container
        container = Frame.create(parent)

        # Choose padding based on nesting level
        if nesting_level == 0:
            container_padding = PADDING_HIERARCHY_BASE
        elif nesting_level == 1:
            container_padding = PADDING_HIERARCHY_LEVEL_1
        elif nesting_level == 2:
            container_padding = PADDING_HIERARCHY_LEVEL_2
        else:
            container_padding = PADDING_HIERARCHY_LEVEL_3

        if row is not None:
            container.grid(
                row=row,
                column=column,
                padx=container_padding,  # Use nesting-appropriate padding
                pady=PADDING_SMALL,
                sticky="ew",
            )

        # Store nesting level in container for child components
        container._nesting_level = nesting_level

        # Current row in the container
        container_row = 0

        # Add title
        Label.section_header(container, title, container_row)
        container_row += 1

        # Add description if provided
        if description:
            Label.section_description(container, description, container_row)
            container_row += 1

        return container, container_row
