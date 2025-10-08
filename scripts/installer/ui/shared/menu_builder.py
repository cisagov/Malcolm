#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2025 Battelle Energy Alliance, LLC.  All rights reserved.

"""Menu building utilities for TUI installer interface."""

from typing import List, Optional, Any
from enum import Enum


class MenuBuilder:
    """Utility class for building consistent menu displays across TUI interfaces."""

    def __init__(self):
        """Initialize the menu builder."""
        self.menu_lines: List[str] = []

    def clear(self) -> None:
        """Clear the current menu content."""
        self.menu_lines.clear()

    def add_header(self, title: str, separator: str = "---") -> None:
        """Add a header section to the menu.

        Args:
            title: The header title
            separator: The separator characters to use
        """
        self.menu_lines.append(f"{separator} {title} {separator}")

    def add_description(self, description: str) -> None:
        """Add a description line to the menu.

        Args:
            description: The description text
        """
        self.menu_lines.append(description)

    def add_blank_line(self) -> None:
        """Add a blank line to the menu."""
        self.menu_lines.append("")

    def add_item(
        self, number: int, label: str, current_value: Any, question: str = None
    ) -> None:
        """Add a menu item with current value display.

        Args:
            number: The item number
            label: The item label
            current_value: The current value to display
            question: Question text to display below the item
        """
        value_display = self._format_value_display(current_value)
        self.menu_lines.append(f"  {number}. {label}: {value_display}")

        if question:
            self.menu_lines.append(f"     {question}")

    def add_tree_item(
        self,
        prefix: str,
        number: int,
        label: str,
        current_value: Any,
        question: str = None,
    ) -> None:
        """Add a tree-style menu item with prefix formatting.

        Args:
            prefix: The tree prefix (e.g., "├── ", "└── ")
            number: The item number
            label: The item label
            current_value: The current value to display
            question: Question text to display below the item
        """
        value_display = self._format_value_display(current_value)
        self.menu_lines.append(f"{prefix}{number}. {label} (current: {value_display})")

        if question:
            # Adjust help text indentation based on prefix
            indent = " " * (len(prefix) + 2)
            self.menu_lines.append(f"{indent}{question}")

    def add_action_section(self, title: str = "Actions") -> None:
        """Add an actions section header.

        Args:
            title: The actions section title
        """
        self.menu_lines.append("")
        self.menu_lines.append(f"--- {title} ---")

    def add_action(self, key: str, description: str) -> None:
        """Add an action item to the menu.

        Args:
            key: The action key/letter
            description: The action description
        """
        self.menu_lines.append(f"  {key}. {description}")

    def add_separator(self, separator: str = "-", length: int = 33) -> None:
        """Add a separator line.

        Args:
            separator: The separator character
            length: The length of the separator line
        """
        self.menu_lines.append(separator * length)

    def build(self) -> str:
        """Build the complete menu as a single string.

        Returns:
            The complete menu as a multi-line string
        """
        return "\n".join(self.menu_lines)

    def display(self) -> None:
        """Display the menu using print."""
        print(self.build())

    def _format_value_display(self, value: Any) -> str:
        """Format a value for display in the menu.

        Args:
            value: The value to format

        Returns:
            Formatted string representation of the value
        """
        return _format_scalar(value, empty_label="empty")


class ValueFormatter:
    """Utility class for formatting values in menu displays."""

    @staticmethod
    def normalize_display_string(value: str) -> str:
        """Normalize enum-like strings for consistent UI display.

        Example mappings:
          - yes/no -> Yes/No
          - always -> Always
          - unless-stopped -> Unless-stopped
          - customize -> Customize
          - disabled/enabled -> Disabled/Enabled
          - local/remote -> Local/Remote
        """
        if value is None:
            return "Not Set"
        lower = str(value).strip().lower()
        mapping = {
            "yes": "Yes",
            "no": "No",
            "always": "Always",
            "unless-stopped": "Unless-stopped",
            "customize": "Customize",
            "disabled": "Disabled",
            "enabled": "Enabled",
            "local": "Local",
            "remote": "Remote",
        }
        return mapping.get(lower, value)

    @staticmethod
    def format_config_value(label: str, value: Any) -> str:
        """Format a configuration value for display.

        Args:
            label: The item label (used for password detection)
            value: The value to format

        Returns:
            Formatted string representation
        """
        if "password" in label.lower() and value:
            return "********"
        return _format_scalar(value, empty_label="empty")

    @staticmethod
    def format_summary_value(label: str, value: Any) -> str:
        """Format a value for summary display.

        Args:
            label: The item label
            value: The value to format

        Returns:
            Formatted string representation for summary
        """
        return _format_scalar(value, empty_label="Not Set")


def _format_scalar(value: Any, *, empty_label: str) -> str:
    """Format primitive, enum, and scalar values consistently.

    - bool -> Yes/No
    - Enum -> normalized enum value string
    - None/empty -> empty_label
    - other -> normalized string
    """
    # Attempt centralized outbound mapping first to normalize enums/labels
    try:
        from scripts.installer.core.transform_registry import apply_outbound

        value = apply_outbound("", value)
    except Exception:
        pass

    if value is None or value == "":
        return empty_label
    if isinstance(value, bool):
        return "Yes" if value else "No"
    if isinstance(value, Enum):
        # Prefer human-friendly name for enums whose .value is not a string (e.g., auto() / Flag)
        try:
            enum_value = value.value
            if isinstance(enum_value, str):
                return ValueFormatter.normalize_display_string(enum_value)
        except Exception:
            pass

        # Fall back to the enum name, prettified (e.g., DOCKER_COMPOSE -> Docker Compose)
        try:
            name = getattr(value, "name", str(value))
            if isinstance(name, str) and name:
                pretty = name.replace("_", " ").strip().title()
                return ValueFormatter.normalize_display_string(pretty)
        except Exception:
            pass

        return ValueFormatter.normalize_display_string(str(value))
    return ValueFormatter.normalize_display_string(str(value))
