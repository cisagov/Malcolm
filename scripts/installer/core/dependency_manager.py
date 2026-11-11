#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2026 Battelle Energy Alliance, LLC.  All rights reserved.

"""Register and apply configuration dependency rules using observers."""

from typing import Dict, Any, TYPE_CHECKING, Callable, List, Tuple

if TYPE_CHECKING:
    from scripts.installer.core.malcolm_config import MalcolmConfig

from scripts.installer.core.dependencies import (
    DEPENDENCY_CONFIG,
    DEFAULT_VALUE_UNCHANGED,
    DependencySpec,
    RuleKind,
    VisibilityRule,
    ValueRule,
)

# The refresh at the end of a load repeats until no rule changes anything. A handful of passes is
#   plenty for the current rules (the longest chain of rules feeding each other is short); if this
#   limit is ever hit, a set of rules is fighting over a value and the log says so.
MAX_REFRESH_PASSES = 10

# Keep wildcard import for keys per standards
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
        # every (item key, value rule) pair, in registration order, for the end-of-load refresh
        self._value_rules: List[Tuple[str, ValueRule]] = []

    def register_all_dependencies(self):
        """Register all dependency rules defined in the configuration."""
        InstallerLogger.debug("Registering configuration dependencies...")

        # Register standard dependencies
        dependency_count = 0
        for item_key, dep_spec in DEPENDENCY_CONFIG.items():
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

        for value_rule in dep_spec.value_rules:
            self._register_value_rule(item_key, value_rule)

    def _register_visibility_rule(self, item_key: str, visibility_rule: VisibilityRule):
        """Register a visibility dependency rule.

        Args:
            item_key: The target configuration item key
            visibility_rule: The visibility rule specification
        """
        item = self.config.get_item(item_key)
        if not item:
            InstallerLogger.warning(f"Cannot register visibility rule for unknown item: {item_key}")
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
                if callable(visibility_rule.condition):
                    if isinstance(visibility_rule.depends_on, list):
                        # Multi-dependency: get values for all dependencies
                        values = [self.config.get_value(dep_key) for dep_key in visibility_rule.depends_on]
                        visible = visibility_rule.condition(*values)
                    else:
                        # Single dependency
                        value = self.config.get_value(visibility_rule.depends_on)
                        visible = visibility_rule.condition(value)
                else:
                    visible = bool(visibility_rule.condition)

                if item.ui_parent and not self.config.is_item_visible(item.ui_parent):
                    visible = False

                self.config._set_item_visible(item_key, visible)

            except Exception as e:
                InstallerLogger.error(f"Error in visibility observer for {item_key}: {e}")
                # Set visible by default on error to avoid hiding items
                self.config._set_item_visible(item_key, True)

        # Register observers for all dependencies
        if isinstance(visibility_rule.depends_on, list):
            for dep_key in visibility_rule.depends_on:
                self.config.observe(dep_key, visibility_observer)
                self._registered_observers.append((dep_key, visibility_observer))
        else:
            self.config.observe(visibility_rule.depends_on, visibility_observer)
            self._registered_observers.append((visibility_rule.depends_on, visibility_observer))

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

        Raises:
            ValueError: If the rule doesn't say what kind of rule it is.
        """
        item = self.config.get_item(item_key)
        if not item:
            InstallerLogger.warning(f"Cannot register value rule for unknown item: {item_key}")
            return

        if not isinstance(value_rule.kind, RuleKind):
            raise ValueError(f"Value rule for {item_key} must set kind to a RuleKind")

        self._value_rules.append((item_key, value_rule))

        def value_observer(_):
            """Apply the rule after one of the settings it depends on changes."""
            try:
                # while a load is in progress, rules wait for refresh_after_load()
                if self.config.is_loading():
                    return
                # a value the user set, in this session or via a load, is left alone unless the rule is forced
                if value_rule.only_if_unmodified and self.config.is_user_set(item_key):
                    return
                new_val = self._compute_rule_value(item_key, value_rule)
                if new_val is not DEFAULT_VALUE_UNCHANGED:
                    try:
                        self.config.apply_default(item_key, new_val)
                    except Exception as e:
                        # Do not break dependency processing; surface the error
                        InstallerLogger.warning(f"Failed to apply default for {item_key}: {e}")
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

    def _compute_rule_value(self, item_key: str, value_rule: ValueRule) -> Any:
        """Return the value a rule would set right now, or DEFAULT_VALUE_UNCHANGED if it doesn't apply."""
        if isinstance(value_rule.depends_on, list):
            dep_values = [self.config.get_value(dep_key) for dep_key in value_rule.depends_on]
        else:
            dep_values = [self.config.get_value(value_rule.depends_on)]

        if callable(value_rule.condition):
            if not value_rule.condition(*dep_values):
                return DEFAULT_VALUE_UNCHANGED
        elif not value_rule.condition:
            return DEFAULT_VALUE_UNCHANGED

        if not callable(value_rule.default_value):
            return value_rule.default_value
        try:
            return value_rule.default_value(*dep_values)
        except Exception as e:
            InstallerLogger.error(
                f"Default value function for {item_key} "
                f"({value_rule.default_value=}, {value_rule.depends_on=}) raised: {e}"
            )
            return DEFAULT_VALUE_UNCHANGED

    def refresh_after_load(self) -> None:
        """Bring every value rule up to date once a load has finished.

        Rules are paused while values are loaded (see MalcolmConfig.bulk_load) so that one loaded
        value can't rewrite another partway through. This runs them all afterward, by kind:

        - DERIVED and INVARIANT rules run as they normally would.
        - CASCADE rules only fill in settings that no source supplied. A loaded value was set on
          purpose, so a cascade must not replace it just because its parent was loaded too.

        Applying one rule can change the inputs of another, so this repeats until a full pass
        changes nothing.
        """
        for _ in range(MAX_REFRESH_PASSES):
            changed = False
            for item_key, value_rule in self._value_rules:
                protects_user_value = value_rule.only_if_unmodified or (value_rule.kind == RuleKind.CASCADE)
                if protects_user_value and self.config.is_user_set(item_key):
                    continue
                new_val = self._compute_rule_value(item_key, value_rule)
                if new_val is DEFAULT_VALUE_UNCHANGED:
                    continue
                old_val = self.config.get_value(item_key)
                try:
                    self.config.apply_default(item_key, new_val)
                except Exception as e:
                    InstallerLogger.warning(f"Failed to apply default for {item_key}: {e}")
                    continue
                if self.config.get_value(item_key) != old_val:
                    changed = True
                    if self.config.is_loaded(item_key):
                        # only an INVARIANT rule can get here for a loaded value
                        InstallerLogger.warning(
                            f'Loaded value "{self.config.loggable_value(item_key, old_val)}" for {item_key} '
                            f'conflicts with other settings; '
                            f'using "{self.config.loggable_value(item_key, self.config.get_value(item_key))}"'
                        )
            if not changed:
                return
        InstallerLogger.error(
            f"Configuration rules did not settle after {MAX_REFRESH_PASSES} passes; please report this as a bug"
        )

    def has_derived_rule(self, item_key: str) -> bool:
        """True if the item's value is computed from other settings by a DERIVED rule."""
        spec = DEPENDENCY_CONFIG.get(item_key)
        return bool(spec) and any(rule.kind == RuleKind.DERIVED for rule in spec.value_rules)

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

        # Check dependencies
        if item_key in DEPENDENCY_CONFIG:
            dep_spec = DEPENDENCY_CONFIG[item_key]
            if dep_spec.visibility:
                info["has_visibility_rule"] = True
                info["visibility_depends_on"] = dep_spec.visibility.depends_on
                info["ui_parent"] = dep_spec.visibility.ui_parent
                info["is_top_level"] = dep_spec.visibility.is_top_level
            if value_rules := dep_spec.value_rules:
                info["has_value_rule"] = True
                info["value_depends_on"] = (
                    value_rules[0].depends_on if len(value_rules) == 1 else [r.depends_on for r in value_rules]
                )

        return info
