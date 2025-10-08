#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2025 Battelle Energy Alliance, LLC.  All rights reserved.

import os
import sys
from datetime import datetime
from typing import Optional

from scripts.installer.configs.constants.enums import InstallerResult


class SkipReasons:
    """Centralized skip reason strings for consistent observability."""

    KUBERNETES = "Skipped for Kubernetes orchestration"
    DRY_RUN = "Skipped in dry-run mode"
    CONFIG_ONLY = "Skipped in configuration-only mode"


try:
    from colorama import init as ColoramaInit, Fore, Style

    ColoramaInit()
    colorama_imported = True
except ImportError:
    # Fallback: define no-op color/Style so references to Fore/Style still work
    colorama_imported = False

    class _NoColor:
        RED = GREEN = YELLOW = BLUE = MAGENTA = CYAN = ""

    class _NoStyle:
        RESET_ALL = ""

    Fore = _NoColor()  # type: ignore
    Style = _NoStyle()  # type: ignore


class InstallerLogger:
    """A static logger for installer steps with color-coded, simplified console output."""

    _console_output_enabled = True
    _main_log_file: Optional[str] = None
    _debug_enabled = False
    _buffer_console_enabled = False
    _buffered_lines: list[str] = []

    def __init__(self):
        """Constructor disabled - use static methods only."""
        raise NotImplementedError(
            "InstallerLogger is now entirely static. Use static methods directly."
        )

    @classmethod
    def set_console_output(cls, enabled: bool):
        cls._console_output_enabled = enabled

    @classmethod
    def set_log_file(cls, main_log_file: Optional[str]):
        """Set the main log file for all logging operations."""
        cls._main_log_file = main_log_file

    @classmethod
    def set_debug_enabled(cls, enabled: bool):
        """Enable or disable debug-level logging."""
        cls._debug_enabled = enabled

    @classmethod
    def set_buffered_console(cls, enabled: bool):
        """Buffer console output instead of printing immediately (for DUI dialogs)."""
        cls._buffer_console_enabled = enabled
        if not enabled:
            cls._buffered_lines.clear()

    @classmethod
    def flush_buffer_to_console(cls):
        """Flush buffered console lines in order, then clear the buffer."""
        if not cls._buffered_lines:
            return
        try:
            for line in cls._buffered_lines:
                # Write directly to stdout; lines already contain timestamps and labels
                print(line, file=sys.stdout)
        finally:
            cls._buffered_lines.clear()

    @classmethod
    def generate_timestamped_filename(cls, base_name: str = "malcolm_install") -> str:
        """Generate a timestamped filename for logging."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        return f"{base_name}_{timestamp}.log"

    @staticmethod
    def _log(label: str, color: str, message: str, file: object = sys.stdout):
        """Log a message to console or file based on configuration."""
        timestamp = f"[{InstallerLogger._timestamp()}]"

        # always write to file when a log file is specified
        if InstallerLogger._main_log_file:
            # Write to file when log file is specified
            formatted_message = f"{timestamp} ({label}) {message}\n"
            try:
                with open(InstallerLogger._main_log_file, "a", encoding="utf-8") as f:
                    f.write(formatted_message)
            except Exception:
                pass
        # optionally emit to console when not using file logging
        elif InstallerLogger._console_output_enabled:
            # Write to console when no log file specified
            if InstallerLogger._buffer_console_enabled:
                # buffer the fully formatted string without ANSI if colorama not loaded
                if colorama_imported:
                    line = f"{timestamp} {color}({label}){Style.RESET_ALL} {message}"
                else:
                    line = f"{timestamp} ({label}) {message}"
                InstallerLogger._buffered_lines.append(line)
            else:
                if colorama_imported:
                    print(
                        f"{timestamp} {color}({label}){Style.RESET_ALL} {message}",
                        file=file,
                    )
                else:
                    print(f"{timestamp} ({label}) {message}", file=file)

    @staticmethod
    def start(label: str, step_name: Optional[str] = None):
        """Log the start of a given action."""
        # use _log to honor buffering and file logging decisions
        InstallerLogger._log("START", Fore.BLUE, f"[{label}]")

    @staticmethod
    def end(
        label: str,
        status: InstallerResult,
        message: Optional[str] = None,
        step_name: Optional[str] = None,
    ):
        """Log the end of a given action."""
        log_message = f"[{label}]"
        if message:
            log_message += f": {message}"

        if status == InstallerResult.SUCCESS:
            InstallerLogger._log("SUCCESS", Fore.GREEN, log_message)
        elif status == InstallerResult.SKIPPED:
            InstallerLogger._log("SKIP", Fore.MAGENTA, log_message)
        else:  # FAILURE
            InstallerLogger._log("FAIL", Fore.RED, log_message, file=sys.stderr)

    @staticmethod
    def _timestamp() -> str:
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    @staticmethod
    def info(message: str):
        """Log a simple info message."""
        InstallerLogger._log("info", "", message)

    @staticmethod
    def warning(message: str):
        """Log a simple warning message."""
        InstallerLogger._log("WARNING", Fore.YELLOW, message, file=sys.stderr)

    @staticmethod
    def error(message: str):
        """Log a simple error message."""
        InstallerLogger._log("ERROR", Fore.RED, message, file=sys.stderr)

    @staticmethod
    def debug(message: str):
        """Log a debug message - only shown when debug is enabled."""
        if InstallerLogger._debug_enabled:
            InstallerLogger._log("DEBUG", Fore.CYAN, message)
