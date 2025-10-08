#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2025 Battelle Energy Alliance, LLC.  All rights reserved.

"""Custom exceptions for the Malcolm installer configuration."""

class MalcolmConfigError(Exception):
    """Base class for configuration-related errors."""

    pass


class ConfigItemNotFoundError(MalcolmConfigError):
    """Raised when a configuration item is not found."""

    def __init__(self, key: str):
        super().__init__(f"Configuration item '{key}' not found.")
        self.key = key


class ConfigValueValidationError(MalcolmConfigError):
    """Raised when a configuration value fails validation."""

    def __init__(self, key: str, value: any, message: str):
        super().__init__(f"Invalid value for '{key}': {message} (value was '{value}').")
        self.key = key
        self.value = value


class DependencyError(MalcolmConfigError):
    """Raised for errors related to dependency resolution."""

    pass


class FileOperationError(MalcolmConfigError):
    """Raised for errors during file operations (load/save)."""

    pass
