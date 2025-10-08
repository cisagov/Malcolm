#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2025 Battelle Energy Alliance, LLC.  All rights reserved.

"""Register and apply configuration dependency rules using observers."""

from typing import Dict, Any, TYPE_CHECKING, Callable

if TYPE_CHECKING:
    from scripts.installer.core.malcolm_config import MalcolmConfig

from scripts.installer.core.dependencies import (
    DEPENDENCY_CONFIG,
    get_complex_dependencies,
    DependencySpec,
    VisibilityRule,
    ValueRule,
)
# Keep wildcard import for keys per standards
from scripts.installer.configs.constants.configuration_item_keys import *
from scripts.installer.utils.logger_utils import InstallerLogger


class DependencyManager:
    """Manages configuration item dependencies using declarative rules.

    This class processes dependency specifications and sets up the necessary
    observer relationships to handle visibility and value dependencies between
    configuration items.
    """

    def __init__(self, malcolm_config: "MalcolmConfig"):
        """Initialize the dependency manager.

        Args:
            malcolm_config: The MalcolmConfig instance to manage dependencies for
        """
        self.config = malcolm_config
        self._registered_observers = []  # Track for debugging/cleanup
        self._visibility_observers: Dict[str, Callable[[Any], None]] = {}

    def register_all_dependencies(self):
        """Register all dependency rules defined in the configuration."""
        InstallerLogger.debug("Registering configuration dependencies...")

        # Register standard dependencies
        dependency_count = 0
        for item_key, dep_spec in DEPENDENCY_CONFIG.items():
            self._register_dependency(item_key, dep_spec)
            dependency_count += 1

        # Register complex dependencies
        complex_deps = get_complex_dependencies()
        for item_key, dep_spec in complex_deps.items():
            self._register_dependency(item_key, dep_spec)
            dependency_count += 1

        # Bulk enablement is handled declaratively via ValueRule definitions
        InstallerLogger.debug(f"Registered {dependency_count} dependency rules")

    def _register_dependency(self, item_key: str, dep_spec: DependencySpec):
        """Register a single dependency specification.

        Args:
            item_key: The configuration item key this dependency applies to
            dep_spec: The dependency specification
        """
        if dep_spec.visibility:
            self._register_visibility_rule(item_key, dep_spec.visibility)

        if dep_spec.value:
            self._register_value_rule(item_key, dep_spec.value)

    def _register_visibility_rule(self, item_key: str, visibility_rule: VisibilityRule):
        """Register a visibility dependency rule.

        Args:
            item_key: The target configuration item key
            visibility_rule: The visibility rule specification
        """
        item = self.config.get_item(item_key)
        if not item:
            InstallerLogger.warning(
                f"Cannot register visibility rule for unknown item: {item_key}"
            )
            return

        # Set UI parent if specified
        if visibility_rule.ui_parent is not None:
            item.ui_parent = visibility_rule.ui_parent
        elif not visibility_rule.is_top_level:
            # For non-top-level items, set the first dependency as the parent
            if isinstance(visibility_rule.depends_on, list):
                item.ui_parent = visibility_rule.depends_on[0]
            else:
                item.ui_parent = visibility_rule.depends_on

        if item.ui_parent:
            children = self.config._parent_map.setdefault(item.ui_parent, [])
            if item_key not in children:
                children.append(item_key)

        # Create observer function
        def visibility_observer(_):
            """Observer function that updates item visibility."""
            try:
                if isinstance(visibility_rule.depends_on, list):
                    # Multi-dependency: get values for all dependencies
                    values = [
                        self.config.get_value(dep_key)
                        for dep_key in visibility_rule.depends_on
                    ]
                    visible = visibility_rule.condition(*values)
                else:
                    # Single dependency
                    value = self.config.get_value(visibility_rule.depends_on)
                    visible = visibility_rule.condition(value)

                if item.ui_parent and not self.config.is_item_visible(item.ui_parent):
                    visible = False

                self.config._set_item_visible(item_key, visible)

            except Exception as e:
                InstallerLogger.error(
                    f"Error in visibility observer for {item_key}: {e}"
                )
                # Set visible by default on error to avoid hiding items
                self.config._set_item_visible(item_key, True)

        # Register observers for all dependencies
        if isinstance(visibility_rule.depends_on, list):
            for dep_key in visibility_rule.depends_on:
                self.config.observe(dep_key, visibility_observer)
                self._registered_observers.append((dep_key, visibility_observer))
        else:
            self.config.observe(visibility_rule.depends_on, visibility_observer)
            self._registered_observers.append(
                (visibility_rule.depends_on, visibility_observer)
            )

        self._visibility_observers[item_key] = visibility_observer
        # Trigger initial evaluation
        visibility_observer(None)

    def handle_parent_visibility_change(self, parent_key: str, visible: bool) -> None:
        """React to parent visibility toggles by updating child visibility."""

        child_keys = self.config._parent_map.get(parent_key, [])
        if not child_keys:
            return

        if not visible:
            for child_key in child_keys:
                self.config._set_item_visible(child_key, False)
        else:
            for child_key in child_keys:
                observer = self._visibility_observers.get(child_key)
                if observer:
                    observer(None)

    def _register_value_rule(self, item_key: str, value_rule: ValueRule):
        """Register a value dependency rule.

        Args:
            item_key: The target configuration item key
            value_rule: The value rule specification
        """
        item = self.config.get_item(item_key)
        if not item:
            InstallerLogger.warning(
                f"Cannot register value rule for unknown item: {item_key}"
            )
            return

        # Create observer function
        def value_observer(_):
            """Observer function that updates item value when conditions are met."""
            try:
                # Check if we should only apply to unmodified items
                if value_rule.only_if_unmodified and item.is_modified:
                    return

                dep_values = None
                if isinstance(value_rule.depends_on, list):
                    # Multi-dependency: get values for all dependencies
                    dep_values = [
                        self.config.get_value(dep_key)
                        for dep_key in value_rule.depends_on
                    ]
                    should_set = value_rule.condition(*dep_values)
                else:
                    # Single dependency
                    dep_values = self.config.get_value(value_rule.depends_on)
                    should_set = value_rule.condition(dep_values)

                if should_set:
                    # Compute default value (callable defaults receive dependency values)
                    try:
                        if callable(value_rule.default_value):
                            if isinstance(value_rule.depends_on, list):
                                new_val = value_rule.default_value(*dep_values)
                            else:
                                new_val = value_rule.default_value(dep_values)
                        else:
                            new_val = value_rule.default_value
                    except Exception as e:
                        InstallerLogger.warning(
                            f"Default value function for {item_key} raised: {e}"
                        )
                        return

                    # Apply via MalcolmConfig API to avoid touching internals
                    try:
                        self.config.apply_default(item_key, new_val)
                    except Exception as e:
                        # Do not break dependency processing; surface the error
                        InstallerLogger.warning(
                            f"Failed to apply default for {item_key}: {e}"
                        )

            except Exception as e:
                InstallerLogger.error(f"Error in value observer for {item_key}: {e}")

        # Register observers for all dependencies
        if isinstance(value_rule.depends_on, list):
            for dep_key in value_rule.depends_on:
                self.config.observe(dep_key, value_observer)
                self._registered_observers.append((dep_key, value_observer))
        else:
            self.config.observe(value_rule.depends_on, value_observer)
            self._registered_observers.append((value_rule.depends_on, value_observer))

        # Trigger initial evaluation
        value_observer(None)

    def cleanup(self):
        """Clean up all registered observers."""
        InstallerLogger.debug("Cleaning up dependency observers...")
        for dep_key, observer in self._registered_observers:
            self.config.unobserve(dep_key, observer)
        self._registered_observers.clear()

    def get_dependency_info(self, item_key: str) -> Dict[str, Any]:
        """Get information about dependencies for a configuration item.

        Args:
            item_key: The configuration item key

        Returns:
            Dictionary with dependency information
        """
        info = {
            "has_visibility_rule": False,
            "has_value_rule": False,
            "visibility_depends_on": None,
            "value_depends_on": None,
            "ui_parent": None,
            "is_top_level": False,
        }

        # Check standard dependencies
        if item_key in DEPENDENCY_CONFIG:
            dep_spec = DEPENDENCY_CONFIG[item_key]
            if dep_spec.visibility:
                info["has_visibility_rule"] = True
                info["visibility_depends_on"] = dep_spec.visibility.depends_on
                info["ui_parent"] = dep_spec.visibility.ui_parent
                info["is_top_level"] = dep_spec.visibility.is_top_level
            if dep_spec.value:
                info["has_value_rule"] = True
                info["value_depends_on"] = dep_spec.value.depends_on

        # Check complex dependencies
        complex_deps = get_complex_dependencies()
        if item_key in complex_deps:
            dep_spec = complex_deps[item_key]
            if dep_spec.visibility:
                info["has_visibility_rule"] = True
                info["visibility_depends_on"] = dep_spec.visibility.depends_on
                info["ui_parent"] = dep_spec.visibility.ui_parent
                info["is_top_level"] = dep_spec.visibility.is_top_level
            if dep_spec.value:
                info["has_value_rule"] = True
                info["value_depends_on"] = dep_spec.value.depends_on

        return info
