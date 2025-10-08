#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Disableable Panel Component
========================

A panel that is enabled or disabled based on a condition.
"""

import customtkinter
from components.styles import *
from .frame import Frame


class DisableablePanel:
    """A panel that is enabled or disabled based on a condition."""

    @staticmethod
    def create_checkbox_panel(
        parent,
        checkbox_text,
        controller_set_method,
        controller_get_method,
        row=None,
        column=0,
        indent=None,  # Changed from hardcoded 10 to None, will be determined by nesting level
        create_panel=True,  # Whether to create a panel (can be disabled for standalone checkboxes)
        nesting_level=0,  # Added nesting_level parameter to determine indentation
    ):
        """
        Create a checkbox with a panel that is enabled when the checkbox is checked.

        Args:
            parent: The parent frame/widget
            checkbox_text: Text for the checkbox
            controller_set_method: Controller method to call when checkbox changes
            controller_get_method: Controller method to call to get current checkbox state
            row: Row number for grid layout (optional)
            column: Column number for grid layout (default: 0)
            indent: Indentation for the dependent panel (optional, defaults to nesting level based)
            create_panel: Whether to create a dependent panel (default: True)
            nesting_level: Hierarchical nesting level (0=top, 1=first indent, etc.)

        Returns:
            tuple: (checkbox, panel_frame, contained_widgets) - The checkbox, panel frame, and list to add widgets to
        """
        from .controlled_checkbox import ControlledCheckbox

        # Determine indentation based on nesting level if not explicitly provided
        if indent is None:
            if nesting_level == 0:
                indent = INDENT_BASE
            elif nesting_level == 1:
                indent = INDENT_LEVEL_1
            elif nesting_level == 2:
                indent = INDENT_LEVEL_2
            else:
                indent = INDENT_LEVEL_3

        # Determine padding based on nesting level
        if nesting_level == 0:
            checkbox_padding = PADDING_HIERARCHY_BASE
        elif nesting_level == 1:
            checkbox_padding = PADDING_HIERARCHY_LEVEL_1
        elif nesting_level == 2:
            checkbox_padding = PADDING_HIERARCHY_LEVEL_2
        else:
            checkbox_padding = PADDING_HIERARCHY_LEVEL_3

        # Create the checkbox (controlled by controller logic)
        checkbox = ControlledCheckbox(
            parent,
            text=checkbox_text,
            controller_set_method=controller_set_method,
            controller_get_method=controller_get_method,
        )

        # Position checkbox with appropriate padding
        if row is not None:
            checkbox.grid(
                row=row,
                column=column,
                padx=checkbox_padding,
                pady=(PADDING_SMALL, 0),
                sticky="w",
            )

        # Create the panel that depends on the checkbox (if requested)
        panel = None
        contained_widgets = []

        if create_panel:
            next_row = row + 1 if row is not None else None

            # Create a visually distinct panel that clearly shows it belongs to the checkbox
            # Use a slightly different background color than the parent to show nesting
            is_nested = nesting_level > 0

            # Adjust panel appearance based on nesting level
            bg_color = ("gray92", "gray17") if is_nested else ("gray95", "gray15")
            border_color = ("gray80", "gray30") if is_nested else ("gray85", "gray25")

            panel = customtkinter.CTkFrame(
                parent,
                fg_color=bg_color,  # Subtle background color
                corner_radius=6,  # Rounded corners
                border_width=1,  # Light border
                border_color=border_color,  # Border color
            )

            # Position panel with tight spacing to checkbox to show relationship
            if next_row is not None:
                panel.grid(
                    row=next_row,
                    column=column,
                    padx=(
                        indent,
                        PADDING_SMALL,
                    ),  # Indent on left side and small padding on right
                    pady=(
                        PADDING_SMALL / 2,
                        PADDING_SMALL,
                    ),  # Tight spacing to checkbox
                    sticky="ew",  # Expand horizontally
                )

            # Make panel expand to fill available width
            panel.grid_columnconfigure(0, weight=1)

            # Store properties in the panel for later access
            panel._dp_child_panels = []  # Store child panels
            panel._dp_is_enabled_func = controller_get_method  # Store enabling function
            panel._dp_widgets = contained_widgets  # Store the widgets list
            panel._dp_is_nested = is_nested  # Track nesting level
            panel._dp_nesting_level = nesting_level  # Store nesting level

            # Create a wrapper function to handle the checkbox state changes
            # This avoids infinite recursion issues
            def update_panel_state():
                # Get the current state from the controller
                is_enabled = controller_get_method()
                DisableablePanel._set_panel_state(panel, contained_widgets, is_enabled)

            # Update panel state initially
            update_panel_state()

            # Attach the panel update function to the checkbox
            checkbox.add_command_handler(update_panel_state)

        return checkbox, panel, contained_widgets

    @staticmethod
    def create_radiobutton_panel(
        parent,
        radio_value,
        radio_variable,
        row=None,
        column=0,
        indent=None,  # Changed from hardcoded 10 to None
        nesting_level=0,  # Added nesting level parameter
    ):
        """
        Create a panel that is enabled when a specific radio button option is selected.

        Args:
            parent: The parent frame/widget
            radio_value: The value of the radio button that enables this panel
            radio_variable: The StringVar containing the selected radio value
            row: Row number for grid layout (optional)
            column: Column number for grid layout (default: 0)
            indent: Indentation for the dependent panel (optional, defaults to nesting level based)
            nesting_level: Hierarchical nesting level (0=top, 1=first indent, etc.)

        Returns:
            tuple: (panel_frame, contained_widgets) - The panel frame and list to add widgets to
        """
        panel = None
        contained_widgets = []

        # Determine indentation based on nesting level if not explicitly provided
        if indent is None:
            if nesting_level == 0:
                indent = INDENT_BASE
            elif nesting_level == 1:
                indent = INDENT_LEVEL_1
            elif nesting_level == 2:
                indent = INDENT_LEVEL_2
            else:
                indent = INDENT_LEVEL_3

        next_row = row + 1 if row is not None else None

        # Create a visually distinct panel
        is_nested = nesting_level > 0

        # Adjust panel appearance based on nesting level
        bg_color = ("gray92", "gray17") if is_nested else ("gray95", "gray15")
        border_color = ("gray80", "gray30") if is_nested else ("gray85", "gray25")

        panel = customtkinter.CTkFrame(
            parent,
            fg_color=bg_color,
            corner_radius=6,
            border_width=1,
            border_color=border_color,
        )

        # Position panel
        if next_row is not None:
            panel.grid(
                row=next_row,
                column=column,
                padx=(indent, 0),
                pady=(PADDING_SMALL / 2, PADDING_SMALL),
                sticky="ew",
            )

        # Make panel expand horizontally
        panel.grid_columnconfigure(0, weight=1)

        # Store properties in the panel for later access
        panel._dp_child_panels = []  # Store child panels
        panel._dp_is_enabled_func = (
            lambda: radio_variable.get() == radio_value
        )  # Store enabling function
        panel._dp_widgets = contained_widgets  # Store the widgets list
        panel._dp_is_nested = is_nested  # Track nesting level
        panel._dp_nesting_level = nesting_level  # Store nesting level

        # Create wrapper function to handle radio button state changes
        def update_panel_state(*args):
            # Check if this panel should be enabled
            is_enabled = radio_variable.get() == radio_value
            DisableablePanel._set_panel_state(panel, contained_widgets, is_enabled)

        # Update panel state initially
        update_panel_state()

        # Track the variable for changes
        radio_variable.trace_add("write", update_panel_state)

        return panel, contained_widgets

    @staticmethod
    def create_nested_panel(
        parent,
        is_enabled_callback,
        row=None,
        column=0,
        indent=None,  # Changed from hardcoded 20 to None
        nesting_level=0,  # Added nesting level parameter
    ):
        """
        Create a nested panel that can be enabled/disabled based on a callback.

        Args:
            parent: The parent frame/widget
            is_enabled_callback: Function returning True/False to determine if panel is enabled
            row: Row number for grid layout (optional)
            column: Column number for grid layout (default: 0)
            indent: Indentation for the panel (optional, defaults to nesting level based)
            nesting_level: Hierarchical nesting level (0=top, 1=first indent, etc.)

        Returns:
            tuple: (panel_frame, contained_widgets, update_func) - The panel frame, widget list, and update function
        """
        # Determine indentation based on nesting level if not explicitly provided
        if indent is None:
            if nesting_level == 0:
                indent = INDENT_BASE
            elif nesting_level == 1:
                indent = INDENT_LEVEL_1
            elif nesting_level == 2:
                indent = INDENT_LEVEL_2
            else:
                indent = INDENT_LEVEL_3

        is_nested = nesting_level > 0

        # Adjust panel appearance based on nesting level
        bg_color = ("gray92", "gray17") if is_nested else ("gray95", "gray15")
        border_color = ("gray80", "gray30") if is_nested else ("gray85", "gray25")

        panel = customtkinter.CTkFrame(
            parent,
            fg_color=bg_color,
            corner_radius=6,
            border_width=1,
            border_color=border_color,
        )

        if row is not None:
            panel.grid(
                row=row,
                column=column,
                padx=(indent, 0),
                pady=(PADDING_SMALL / 2, PADDING_SMALL),
                sticky="ew",
            )

        panel.grid_columnconfigure(0, weight=1)
        contained_widgets = []

        # Store properties in the panel for later access
        panel._dp_child_panels = []  # Store child panels
        panel._dp_is_enabled_func = is_enabled_callback  # Store enabling function
        panel._dp_widgets = contained_widgets  # Store the widgets list
        panel._dp_is_nested = is_nested  # Track nesting level
        panel._dp_nesting_level = nesting_level  # Store nesting level

        # Function to update the panel state
        def update_panel_state():
            is_enabled = is_enabled_callback()
            DisableablePanel._set_panel_state(panel, contained_widgets, is_enabled)

        # Update initially
        update_panel_state()

        return panel, contained_widgets, update_panel_state

    @staticmethod
    def register_child_panel(parent_panel, child_panel):
        """
        Register a child panel with a parent panel to enable proper state handling.

        Args:
            parent_panel: The parent panel frame
            child_panel: The child panel frame to register
        """
        if hasattr(parent_panel, "_dp_child_panels"):
            parent_panel._dp_child_panels.append(child_panel)

    @staticmethod
    def _set_panel_state(panel, widgets, enabled, parent_forced=False):
        """
        Enable or disable all widgets in a panel and its child panels.

        Args:
            panel: The panel frame
            widgets: List of widgets to enable/disable
            enabled: Whether to enable (True) or disable (False) the widgets
            parent_forced: Whether this state change is forced by a parent panel
        """
        if panel is None:
            return  # Nothing to do if panel doesn't exist

        state = "normal" if enabled else "disabled"

        # If this is forced by parent and we're enabling, check the panel's own state
        if parent_forced and enabled and hasattr(panel, "_dp_is_enabled_func"):
            # When re-enabling, respect the panel's own state
            enabled = panel._dp_is_enabled_func()

        # Set the state of all tracked widgets
        for widget in widgets:
            if hasattr(widget, "configure"):
                try:
                    # Set state for widgets that likely support it
                    if isinstance(
                        widget,
                        (
                            customtkinter.CTkButton,
                            customtkinter.CTkEntry,
                            customtkinter.CTkCheckBox,
                            customtkinter.CTkRadioButton,
                            customtkinter.CTkComboBox,
                            customtkinter.CTkSlider,
                            customtkinter.CTkOptionMenu,
                        ),
                    ):
                        widget.configure(state=state)
                    # For CTkLabel and widgets without a state property
                    elif isinstance(widget, customtkinter.CTkLabel):
                        if enabled:
                            # Reset to default color
                            widget.configure(text_color=("gray10", "gray90"))
                        else:
                            # Grayed out color
                            widget.configure(text_color=("gray50", "gray70"))
                except ValueError:
                    # Skip if the widget doesn't support the configuration
                    pass

        # Visual indication of disabled state for the panel
        is_nested = getattr(panel, "_dp_is_nested", False)

        if enabled:
            # Normal appearance - slightly different colors for nested panels
            bg_color = ("gray92", "gray17") if is_nested else ("gray95", "gray15")
            border_color = ("gray80", "gray30") if is_nested else ("gray85", "gray25")

            panel.configure(
                fg_color=bg_color, border_width=1, border_color=border_color
            )
        else:
            # Disabled appearance
            bg_color = ("gray88", "gray22") if is_nested else ("gray90", "gray20")
            border_color = ("gray75", "gray40") if is_nested else ("gray80", "gray35")

            panel.configure(
                fg_color=bg_color, border_width=1, border_color=border_color
            )

        # Process any child panels
        if hasattr(panel, "_dp_child_panels"):
            for child_panel in panel._dp_child_panels:
                # Use the stored widgets list if available
                child_widgets = getattr(child_panel, "_dp_widgets", [])

                # Apply state to child panel recursively
                DisableablePanel._set_panel_state(
                    child_panel, child_widgets, enabled, parent_forced=True
                )
