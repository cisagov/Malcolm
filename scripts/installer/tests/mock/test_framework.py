#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2025 Battelle Energy Alliance, LLC.  All rights reserved.

"""Test framework infrastructure for Malcolm installer."""

import os
import sys
import tempfile
import unittest
from unittest.mock import patch, MagicMock, mock_open
from typing import Dict, Any, Optional
from enum import Enum

# Add the project root directory to the Python path
sys.path.insert(
    0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
)

from scripts.installer.core.install_context import InstallContext
from scripts.installer.core.malcolm_config import MalcolmConfig
from scripts.malcolm_common import UserInterfaceMode, OrchestrationFramework
from scripts.installer.platforms.base import BaseInstaller
from scripts.installer.configs.constants.installation_item_keys import (
    KEY_INSTALLATION_ITEM_AUTO_TWEAKS,
    KEY_INSTALLATION_ITEM_DOCKER_INSTALL_METHOD,
    KEY_INSTALLATION_ITEM_DOCKER_EXTRA_USERS,
    KEY_INSTALLATION_ITEM_LOAD_MALCOLM_IMAGES,
)


class TestPhase(Enum):
    """Test phases for jumping to specific points in the installer."""

    CONFIGURATION_PHASE = "config"
    INSTALLATION_PHASE = "install"
    DOCKER_INSTALL = "docker_install"
    DOCKER_COMPOSE_INSTALL = "docker_compose_install"
    SYSTEM_TWEAKS = "tweaks"
    DOCKER_OPS = "docker_ops"
    FILESYSTEM_PREP = "filesystem"
    ANCILLARY_CONFIG = "ancillary"


class MockUI:
    """Mock UI implementation for testing."""

    def __init__(self, responses: Dict[str, Any] = None):
        self.ui_mode = UserInterfaceMode.InteractionInput
        self.responses = responses or {}
        self.called_methods = []

    def ask_yes_no(self, prompt: str, default: bool = True) -> bool:
        """Mock yes/no prompts."""
        self.called_methods.append(("ask_yes_no", prompt, default))
        return self.responses.get(prompt, default)

    def ask_string(self, prompt: str, default: str = "") -> str:
        """Mock string input prompts."""
        self.called_methods.append(("ask_string", prompt, default))
        return self.responses.get(prompt, default)

    def display_message(self, message: str):
        """Mock message display."""
        self.called_methods.append(("display_message", message))


class MockPlatform(BaseInstaller):
    """Mock platform installer for comprehensive testing."""

    def __init__(
        self,
        orchestration_mode: OrchestrationFramework = OrchestrationFramework.DOCKER_COMPOSE,
        ui: MockUI = None,
        debug: bool = False,
        config_only: bool = False,
    ):
        """Initialize mock platform."""
        from scripts.installer.configs.constants.enums import ControlFlow

        self.orchestration_mode = orchestration_mode
        self.ui = ui or MockUI()
        self.debug = debug
        self.config_only = config_only

        # Control flow setup
        self.control_flow = ControlFlow.CONFIG if config_only else ControlFlow.INSTALL

        # Platform information
        self.platform = "linux"
        self.distro = "ubuntu"
        self.codename = "focal"
        self.version = "20.04"

        # Mock system resources
        self.total_memory_gigs = 16.0
        self.total_cores = 8

        # Command execution tracking
        self.run_process_results = {}
        self.executed_commands = []

        # Installation state
        self.docker_installed = False
        self.docker_compose_installed = False
        self.packages_installed = set()

    def run_process(
        self,
        command,
        privileged=False,
        stdin=None,
        retry=1,
        retry_sleep_sec=5,
        stderr=True,
    ):
        """Mock process execution with detailed tracking."""
        cmd_str = " ".join(command) if isinstance(command, list) else command
        self.executed_commands.append(
            {
                "command": cmd_str,
                "privileged": privileged,
                "stdin": stdin,
                "retry": retry,
                "retry_sleep_sec": retry_sleep_sec,
                "stderr": stderr,
            }
        )

        # Return pre-configured result or default success
        if cmd_str in self.run_process_results:
            return self.run_process_results[cmd_str]

        # Default behavior based on command patterns
        if "docker info" in cmd_str:
            return (
                (0, ["Server: Docker Engine"])
                if self.docker_installed
                else (1, ["Cannot connect to Docker"])
            )
        # handle compose version probes (v1 and v2 forms)
        elif (
            "docker-compose --version" in cmd_str
            or "docker compose --version" in cmd_str
            or "docker-compose version" in cmd_str
            or "docker compose version" in cmd_str
        ):
            return (
                (0, ["docker-compose version 2.0.0"])
                if self.docker_compose_installed
                else (1, ["Command not found"])
            )
        elif cmd_str.startswith("apt-get install") or cmd_str.startswith("yum install"):
            # Extract package names and mark as installed
            packages = [
                p
                for p in cmd_str.split()
                if not p.startswith("-") and p not in ["apt-get", "yum", "install"]
            ]
            self.packages_installed.update(packages)
            return (0, [f'Successfully installed {" ".join(packages)}'])

        return (0, [])  # Default success

    def set_command_result(self, command: str, return_code: int, output: list):
        """Set expected result for a specific command."""
        self.run_process_results[command] = (return_code, output)

    def package_is_installed(self, package_name: str) -> bool:
        """Mock package installation check."""
        return package_name in self.packages_installed

    def install_package(self, packages: list) -> bool:
        """Mock package installation."""
        self.packages_installed.update(packages)
        return True

    def install_dependencies(self) -> bool:
        """Mock dependency installation."""
        basic_deps = ["curl", "wget", "git"]
        self.packages_installed.update(basic_deps)
        return True

    def install_docker(self, install_context: InstallContext) -> bool:
        """Mock Docker installation."""
        self.docker_installed = True
        return True

    def install_docker_compose(self) -> bool:
        """Mock Docker Compose installation."""
        self.docker_compose_installed = True
        return True

    def create_user(self, username: str, uid: int = None, gid: int = None) -> bool:
        """Mock user creation."""
        return True

    # new abstract method requirement
    def install(self, malcolm_config, config_dir: str, ctx, logger=None) -> bool:
        """No-op install for tests."""
        return True


class MockFileSystem:
    """Mock filesystem operations for testing."""

    def __init__(self):
        self.files = {}
        self.directories = set()

    def add_file(self, path: str, content: str = ""):
        """Add a mock file with content."""
        self.files[path] = content
        # Ensure parent directories exist
        parent = os.path.dirname(path)
        if parent:
            self.directories.add(parent)

    def add_directory(self, path: str):
        """Add a mock directory."""
        self.directories.add(path)

    def exists(self, path: str) -> bool:
        """Check if path exists."""
        return path in self.files or path in self.directories

    def read_file(self, path: str) -> str:
        """Read file content."""
        return self.files.get(path, "")

    def list_directory(self, path: str) -> list:
        """List directory contents."""
        if path not in self.directories:
            raise FileNotFoundError(f"Directory not found: {path}")

        # Find all files/dirs that are direct children
        children = []
        for file_path in self.files:
            if os.path.dirname(file_path) == path:
                children.append(os.path.basename(file_path))
        for dir_path in self.directories:
            if os.path.dirname(dir_path) == path:
                children.append(os.path.basename(dir_path))

        return sorted(set(children))


class BaseInstallerTest(unittest.TestCase):
    """Base test class with common setup and utilities."""

    def setUp(self):
        """Set up test fixtures."""
        self.mock_ui = MockUI()
        self.mock_platform = MockPlatform(ui=self.mock_ui, debug=True)
        self.mock_filesystem = MockFileSystem()
        self.temp_dir = tempfile.mkdtemp()
        self.mock_logger = MagicMock()

        # Setup common mock files
        self.mock_filesystem.add_file(
            "/etc/sysctl.conf", "# System control configuration"
        )
        self.mock_filesystem.add_file("/etc/default/grub", 'GRUB_CMDLINE_LINUX=""')
        self.mock_filesystem.add_directory("/etc/security/limits.d")
        self.mock_filesystem.add_directory("/etc/systemd/system.conf.d")

        # Mock InstallerYesOrNo to avoid interactive prompts
        self.installer_yes_or_no_patcher = patch(
            "scripts.malcolm_common.InstallerYesOrNo", return_value=False
        )
        self.installer_yes_or_no_patcher.start()

    def tearDown(self):
        """Clean up test fixtures."""
        import shutil

        shutil.rmtree(self.temp_dir, ignore_errors=True)

        # Stop the InstallerYesOrNo patcher
        self.installer_yes_or_no_patcher.stop()

    def create_test_config(self, **overrides) -> MalcolmConfig:
        """Create a test Malcolm configuration."""
        config = MalcolmConfig()

        # Set common test values
        test_values = {
            "RUNTIME_BIN": "docker",
            "MALCOLM_PROFILE": "malcolm",
            "PCAP_NODE_NAME": "test-node",
            "PROCESS_USER_ID": 1000,
            "PROCESS_GROUP_ID": 1000,
        }
        test_values.update(overrides)

        for key, value in test_values.items():
            try:
                config.set_value(key, value)
            except:
                pass  # Skip if key doesn't exist

        return config

    def create_test_context(self, **overrides) -> InstallContext:
        """Create a test installation context."""
        defaults = {
            KEY_INSTALLATION_ITEM_AUTO_TWEAKS: True,
            KEY_INSTALLATION_ITEM_DOCKER_INSTALL_METHOD: "repo",
            KEY_INSTALLATION_ITEM_DOCKER_EXTRA_USERS: [],
        }
        defaults.update(overrides)

        ctx = InstallContext()
        # Set the values using the proper method
        for key, value in defaults.items():
            if ctx.set_item_value(key, value):
                continue
            if hasattr(ctx, key):
                setattr(ctx, key, value)

        # Helper: if an archive path is provided, ensure corresponding toggle is set
        if ctx.image_archive_path and hasattr(ctx, "image_archive_path"):
            ctx.image_source = "archive"
            ctx.load_images_from_archive = True
            ctx.set_item_value(KEY_INSTALLATION_ITEM_LOAD_MALCOLM_IMAGES, True)

        return ctx

    def assert_command_executed(self, command_pattern: str, privileged: bool = None):
        """Assert that a command matching the pattern was executed."""
        executed = [cmd["command"] for cmd in self.mock_platform.executed_commands]

        matching_commands = [cmd for cmd in executed if command_pattern in cmd]
        self.assertTrue(
            len(matching_commands) > 0,
            f"Command pattern '{command_pattern}' not found in executed commands: {executed}",
        )

        if privileged is not None:
            matching_details = [
                cmd
                for cmd in self.mock_platform.executed_commands
                if command_pattern in cmd["command"] and cmd["privileged"] == privileged
            ]
            self.assertTrue(
                len(matching_details) > 0,
                f"Command pattern '{command_pattern}' not found with privileged={privileged}",
            )

    def assert_no_command_executed(self, command_pattern: str):
        """Assert that no command matching the pattern was executed."""
        executed = [cmd["command"] for cmd in self.mock_platform.executed_commands]
        matching_commands = [cmd for cmd in executed if command_pattern in cmd]
        self.assertEqual(
            len(matching_commands),
            0,
            f"Command pattern '{command_pattern}' was unexpectedly executed: {matching_commands}",
        )

    def patch_filesystem(self):
        """Context manager to patch filesystem operations with mock."""
        return patch.multiple(
            "os.path",
            exists=self.mock_filesystem.exists,
            isfile=self.mock_filesystem.exists,
            isdir=lambda path: path in self.mock_filesystem.directories,
        )


def create_test_flags():
    """Create test flags for jumping to specific installer phases."""
    import argparse

    parser = argparse.ArgumentParser(description="Test specific installer phases")
    parser.add_argument(
        "--test-phase",
        choices=[p.value for p in TestPhase],
        help="Jump to specific installer phase for testing",
    )
    parser.add_argument(
        "--mock-docker-installed",
        action="store_true",
        help="Mock Docker as already installed",
    )
    parser.add_argument(
        "--mock-docker-compose-installed",
        action="store_true",
        help="Mock Docker Compose as already installed",
    )
    parser.add_argument(
        "--mock-system-tweaks-applied",
        action="store_true",
        help="Mock system tweaks as already applied",
    )
    parser.add_argument(
        "--fail-docker-install",
        action="store_true",
        help="Force Docker installation to fail",
    )
    parser.add_argument(
        "--fail-system-tweaks", action="store_true", help="Force system tweaks to fail"
    )

    return parser


if __name__ == "__main__":
    # Run basic framework tests
    unittest.main()
