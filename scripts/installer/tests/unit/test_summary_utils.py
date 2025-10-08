#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Unit tests for summary_utils formatting helpers."""

import os
import sys
import unittest

# Add the project root directory to the Python path
sys.path.insert(
    0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", ".."))
)

from enum import Enum

from scripts.installer.utils.summary_utils import (
    _normalize_display_string,
    format_summary_value,
)
from scripts.installer.configs.constants.enums import DockerRestartPolicy


class TestSummaryUtils(unittest.TestCase):
    def test_normalize_display_string(self):
        self.assertEqual(_normalize_display_string("yes"), "Yes")
        self.assertEqual(_normalize_display_string("no"), "No")
        self.assertEqual(_normalize_display_string("unless-stopped"), "Unless-stopped")
        self.assertEqual(_normalize_display_string("Always"), "Always")

    def test_format_summary_value_password_mask(self):
        self.assertEqual(format_summary_value("Admin Password", "secret"), "********")
        self.assertEqual(format_summary_value("API password", "abc"), "********")

    def test_format_summary_value_enum(self):
        # Should display normalized enum value
        val = format_summary_value("Restart Policy", DockerRestartPolicy.UNLESS_STOPPED)
        self.assertEqual(val, "Unless-stopped")

    def test_format_summary_value_str(self):
        self.assertEqual(format_summary_value("Runtime", "docker"), "docker")
        self.assertEqual(format_summary_value("Enabled", "yes"), "Yes")

    def test_format_summary_value_none(self):
        self.assertEqual(format_summary_value("Something", None), "Not set")


if __name__ == "__main__":
    unittest.main()

