#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2026 Battelle Energy Alliance, LLC.  All rights reserved.

"""Behaviour and timestamp regression tests for container log formatting."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from scripts import malcolm_common

import unittest
from unittest import mock


class ProcessLogLineTest(unittest.TestCase):

    def setUp(self):
        super().setUp()
        self.color_patch = mock.patch.object(malcolm_common, 'coloramaImported', False)
        self.color_patch.start()
        self.addCleanup(self.color_patch.stop)

    def format(self, text, debug=False):
        return malcolm_common.ProcessLogLine(text.encode(), debug=debug)

    def test_plain_lines_keep_content_and_remove_container_suffix(self):
        self.assertEqual(self.format('worker-container | plain text'), 'worker | plain text')

    def test_json_without_timestamp(self):
        actual = self.format('worker-container | {"message":"hello","size":2}')
        self.assertEqual(actual, 'worker | {"message": "hello", "size": 2}')

    def test_json_with_own_timestamp(self):
        actual = self.format('filebeat-container | {"message":"done","time":"2026-10-15T12:34:56Z"}')
        self.assertEqual(actual, 'filebeat | 2026-10-15T12:34:56Z done')

    def test_timestamped_json_is_decoded_without_crashing(self):
        actual = self.format('worker-container | 2026-10-15T12:34:56Z {"message":"hello"}')
        self.assertEqual(actual, 'worker | 2026-10-15T12:34:56Z {"message": "hello"}')

    def test_timestamped_filebeat_json_is_simplified(self):
        actual = self.format('filebeat-container | 2026-10-15T12:34:56Z {"log.level":"info","message":"done"}')
        self.assertEqual(actual, 'filebeat | 2026-10-15T12:34:56Z done')

    def test_timestamped_non_json_stays_plain_text(self):
        line = 'worker-container | 2026-10-15T12:34:56Z not-a-json-message'
        self.assertEqual(self.format(line), 'worker | 2026-10-15T12:34:56Z not-a-json-message')

    def test_filebeat_processed_file_summary(self):
        actual = self.format('filebeat-container | {"message":"processed","source_file":"capture.log","finished":true}')
        self.assertEqual(actual, 'filebeat | processed: capture.log')

    def test_filebeat_removes_noisy_fields(self):
        actual = self.format('filebeat-container | {"log.level":"info","message":"processed"}')
        self.assertEqual(actual, 'filebeat | processed')

    def test_dashboards_noise_fields_are_removed(self):
        actual = self.format('dashboards-container | {"pid":10,"type":"log","message":"ready"}')
        self.assertEqual(actual, 'dashboards | {"message": "ready"}')

    def test_scheduled_job_start_and_success_hidden_by_default(self):
        for message in ('starting', 'job succeeded'):
            with self.subTest(message=message):
                line = (
                    'worker-container | {"job.schedule":"* * * * *",'
                    '"job.position":1,"job.command":"echo hello",'
                    f'"msg":"{message}","level":"info"}}'
                )
                self.assertIsNone(self.format(line))
                self.assertEqual(self.format(line, debug=True), f'worker |  echo hello: {message}')

    def test_scheduled_job_failure_is_shown(self):
        line = (
            'worker-container | {"job.schedule":"* * * * *",'
            '"job.position":1,"job.command":"echo hello",'
            '"msg":"failed","level":"info"}'
        )
        self.assertEqual(self.format(line), 'worker |  echo hello: failed')

    def test_credentials_are_masked_before_formatting(self):
        line = 'worker-container | GET https://bob:secret@example.org/private'
        self.assertNotIn('secret', self.format(line))

    def test_json_time_field_takes_precedence_over_line_timestamp(self):
        line = 'worker-container | 2026-10-15T12:34:56Z {"message":"hello","timestamp":"2026-10-15T01:00:00Z"}'
        self.assertEqual(self.format(line), 'worker | 2026-10-15T01:00:00Z {"message": "hello"}')


if __name__ == '__main__':
    unittest.main()
