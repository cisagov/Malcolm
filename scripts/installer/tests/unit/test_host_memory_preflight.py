#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2026 Battelle Energy Alliance, LLC.  All rights reserved.

"""Tests for the installer's read-only physical memory warning."""

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scripts.installer.utils.host_memory_preflight import linux_swap_total_kib, low_memory_warning
from scripts.installer.utils.logger_utils import InstallerLogger
from scripts.malcolm_constants import OrchestrationFramework, PROFILE_HEDGEHOG, PROFILE_MALCOLM, PresentationMode
from scripts import install
from scripts.malcolm_common import suggest_ls_memory, suggest_os_memory


class HostMemoryPreflightTest(unittest.TestCase):

    def test_heap_recommendations_remain_unchanged(self):
        # The project's maintainers intentionally retain these existing defaults.
        self.assertEqual(suggest_os_memory(8), '4g')
        self.assertEqual(suggest_ls_memory(8), '2500m')

    def test_unsupported_host_warning_before_any_settings_change(self):
        for ram_gib in (4, 8, 11, 16, 23):
            with self.subTest(ram_gib=ram_gib):
                warning = low_memory_warning(ram_gib, swap_kib=0)
                self.assertIn(f'{ram_gib} GiB RAM', warning)
                self.assertIn('at least 24 GiB', warning)
                self.assertIn('No swap was detected', warning)
                self.assertIn('heap defaults are unchanged', warning)

    def test_supported_or_unknown_host_no_warning(self):
        for ram in (24, 32, 96, 0, -1, None, 'not-a-number'):
            with self.subTest(ram=ram):
                self.assertIsNone(low_memory_warning(ram, swap_kib=0))

    def test_swap_is_helpful_but_does_not_replace_ram(self):
        self.assertIn('cannot replace', low_memory_warning(8, swap_kib=2048))
        self.assertNotIn('No swap was detected', low_memory_warning(8, swap_kib=None))

    def test_linux_swap_detection_and_read_errors(self):
        with tempfile.TemporaryDirectory() as directory:
            file_path = Path(directory) / 'meminfo'
            file_path.write_text('MemTotal:       8192000 kB\nSwapTotal: 0 kB\n')
            with mock.patch('scripts.installer.utils.host_memory_preflight.sys.platform', 'linux'):
                self.assertEqual(linux_swap_total_kib(str(file_path)), 0)
                file_path.write_text('SwapTotal: 2048000 kB\n')
                self.assertEqual(linux_swap_total_kib(str(file_path)), 2048000)
                file_path.write_text('SwapTotal: not-a-number kB\n')
                self.assertIsNone(linux_swap_total_kib(str(file_path)))
                self.assertIsNone(linux_swap_total_kib(str(file_path) + '-missing'))
            with mock.patch('scripts.installer.utils.host_memory_preflight.sys.platform', 'darwin'):
                self.assertIsNone(linux_swap_total_kib(str(file_path)))

    def test_warning_once_and_visible_to_interactive_ui(self):
        config = mock.Mock()
        config.get_value.side_effect = lambda key: (
            PROFILE_MALCOLM if key == 'malcolmProfile' else OrchestrationFramework.DOCKER_COMPOSE
        )
        ui = mock.Mock()
        with mock.patch.dict(install.SYSTEM_INFO, {'total_mem_gb': 8}), mock.patch.object(
            install, 'linux_swap_total_kib', return_value=0
        ), mock.patch.object(InstallerLogger, 'warning') as log:
            self.assertTrue(install.show_host_memory_warning(config, ui, PresentationMode.MODE_TUI))
            log.assert_called_once()
            ui.display_message.assert_called_once()
            self.assertIn('24 GiB', ui.display_message.call_args.args[0])
            config.set_value.assert_not_called()

    def test_silent_mode_logs_but_does_not_open_dialog(self):
        config = mock.Mock()
        config.get_value.side_effect = lambda key: (
            PROFILE_MALCOLM if key == 'malcolmProfile' else OrchestrationFramework.DOCKER_COMPOSE
        )
        with mock.patch.dict(install.SYSTEM_INFO, {'total_mem_gb': 8}), mock.patch.object(
            install, 'linux_swap_total_kib', return_value=None
        ), mock.patch.object(InstallerLogger, 'warning') as log:
            self.assertTrue(install.show_host_memory_warning(config, None, PresentationMode.MODE_SILENT))
            log.assert_called_once()

    def test_skip_hedgehog_kubernetes_or_sufficient_ram(self):
        for profile, mode, memory in (
            (PROFILE_HEDGEHOG, OrchestrationFramework.DOCKER_COMPOSE, 8),
            (PROFILE_MALCOLM, OrchestrationFramework.KUBERNETES, 8),
            (PROFILE_MALCOLM, OrchestrationFramework.DOCKER_COMPOSE, 24),
        ):
            with self.subTest(profile=profile, mode=mode, memory=memory):
                config = mock.Mock()
                config.get_value.side_effect = lambda key: (
                    profile if key == 'malcolmProfile' else mode
                )
                ui = mock.Mock()
                with mock.patch.dict(install.SYSTEM_INFO, {'total_mem_gb': memory}), mock.patch.object(
                    InstallerLogger, 'warning'
                ) as log:
                    self.assertFalse(install.show_host_memory_warning(config, ui, PresentationMode.MODE_TUI))
                    ui.display_message.assert_not_called()
                    log.assert_not_called()


if __name__ == '__main__':
    unittest.main()
