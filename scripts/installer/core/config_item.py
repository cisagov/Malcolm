#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2025 Battelle Energy Alliance, LLC.  All rights reserved.


"""Base configuration item class for Malcolm installer.

This module provides the ConfigItem class that serves as the foundation
for all Malcolm configuration items.
"""

from dataclasses import dataclass, field, InitVar
from typing import Any, Callable, Optional, Tuple, Union

from scripts.malcolm_constants import WidgetType


@dataclass
class ConfigItem:
    """
    Base class for all configuration items.

    This class represents a single configurable value with all its associated data/metadata.

    Attributes:
        key: Unique conceptual identifier for the config item (should always be a KEY_CONFIG_ITEM_... constant)
        label: Human-readable display name for the item
        default_value: Initial/fallback value for the item
        value: Current configuration value
        is_modified: Whether the item has been modified via set_value
        validator: Callback to check if incoming value is valid
        visible: Whether the item should be visible in the UI
        choices: List of choices for the item (used for UI widgets)
        ui_depth: Depth of the item in the UI tree
        ui_parent: Parent of the item in the UI tree
        is_password: Whether the field should be displayed as sensitive
        accept_blank: Whether the field should accept a blank/empty value
        _question: Question attached to this ConfigItem to present to the user (either a str or "Callable")
        widget_type: GUI element associated with this ConfigItem
        metadata: dict = Contains information to perform inspection on
    """

    key: str
    label: str
    default_value: Any = None
    value: Any = field(init=False)
    validator: Optional[Callable[[Any], Tuple[bool, str]]] = None
    choices: list = field(default_factory=list)
    is_modified: bool = False
    is_visible: bool = True
    ui_depth: int = 0
    ui_parent: Optional[str] = None
    is_password: bool = False
    accept_blank: bool = False
    widget_type: WidgetType = None
    metadata: dict = field(default_factory=dict)

    # Use InitVar to accept `question` in __init__ but store internally as _question
    question: InitVar[Union[str, Callable[[], Any]]] = ""
    _question: Union[str, Callable[[], Any]] = field(init=False)

    def __post_init__(self, question):
        self.value = self.default_value
        self.ui_depth = 0
        self.ui_parent = None
        self.is_modified = False
        self._question = question

        # if the UI metadata declares a password widget we treat the field as a password
        if not self.is_password and self.metadata.get("widget_type") == "password":
            self.is_password = True

    def set_visible(self, visible: bool):
        """Set the visibility of the item

        Args:
            value: The new value to set
        """

        self.is_visible = visible

    def set_value(self, value: Any) -> Tuple[bool, str]:
        """Set and validate a new value.

        Args:
            value: The new value to set

        Returns:
            Tuple of (success, error_message)
        """
        if self.validator:
            result = self.validator(value)
            # Handle different validator return types
            if isinstance(result, tuple):
                valid, error = result
            else:
                # Validator returned just a boolean
                valid = result
                error = "Invalid value" if not valid else ""

            if not valid:
                return False, error

        # This is intentionally set to true even if the value is the same as the default value
        # Presumably if the user has explicitly set the value, they want to keep it so don't clobber it
        self.is_modified = True
        self.value = value
        return True, ""

    def get_value(self) -> Any:
        """Get the current value. Default is returned if value is None."""
        if self.value is None:
            return self.default_value
        return self.value

    def reset(self):
        """Reset value to default."""
        self.value = self.default_value
        self.is_modified = False

    @property
    def question(self) -> str:  # noqa: F811
        result = self._question() if callable(self._question) else self._question
        return "" if result is None else str(result)

    @question.setter
    def question(self, value: Union[str, Callable[[], Any]]):
        self._question = value


class ListOfStringsConfigItem(ConfigItem):
    """Custom ConfigItem that converts comma-separated strings to lists of strings"""

    def set_value(self, value: Any) -> Tuple[bool, str]:
        """Set and validate a new value, with automatic string-to-list conversion."""

        # Convert string input to list if needed
        if isinstance(value, str):
            if value.strip():
                converted_value = [s.strip() for s in value.split(",") if s.strip()]
            else:
                converted_value = []
        else:
            converted_value = value

        # Now validate the converted value
        if self.validator:
            result = self.validator(converted_value)
            if isinstance(result, tuple):
                valid, error = result
            else:
                valid = result
                error = "Invalid value" if not valid else ""

            if not valid:
                return False, error

        # Store the converted value
        self.is_modified = True
        self.value = converted_value
        return True, ""
