#!/usr/bin/env python3
# Copyright (c) 2026 Battelle Energy Alliance, LLC. All rights reserved.
"""Exercise prune_files.sh in a sandbox with mocked disk-usage commands."""

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


_SCRIPT = Path(__file__).resolve().parents[4] / 'shared/bin/prune_files.sh'


class PruneFilesTest(unittest.TestCase):

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.mock_bin = root / 'bin'
        self.mock_bin.mkdir()
        self.destination = root / 'capture data'
        self.destination.mkdir()
        self.log_file = self.destination / 'old.pcap'
        self.log_file.write_bytes(b'packet contents')
        helpers = {
            'df': """#!/bin/sh
printf 'Filesystem 1K-blocks Used Available Use%% Mounted on\\n'
if [ -f './old.pcap' ]; then percentage="$MOCK_PCT_BEFORE"; else percentage="$MOCK_PCT_AFTER"; fi
printf 'mock 100 60 40 %s%% /\\n' "$percentage"
""",
            'du': """#!/bin/sh
if [ -f './old.pcap' ]; then printf '%s .\\n' "$MOCK_BYTES_BEFORE"; else printf '0 .\\n'; fi
""",
            'find': """#!/bin/sh
if [ -f './old.pcap' ]; then printf '1 128 ./old.pcap\\0'; fi
""",
            'sort': '#!/bin/sh\\ncat\\n',
            'date': '#!/bin/sh\\nprintf "1970-01-01\\n"\\n',
            'numfmt': '#!/bin/sh\\nprintf "128B\\n"\\n',
        }
        for name, data in helpers.items():
            # Convert line-escape markers in the simple shell stub strings.
            data = data.replace('\\n', '\n') if name in ('sort', 'date', 'numfmt') else data
            script = self.mock_bin / name
            script.write_text(data)
            script.chmod(0o755)
        self.env = os.environ.copy()
        self.env.update({
            'PATH': str(self.mock_bin) + os.pathsep + self.env['PATH'],
            'MOCK_PCT_BEFORE': '60',
            'MOCK_PCT_AFTER': '59',
            'MOCK_BYTES_BEFORE': '1000000000',
        })

    def run_prune(self, *args, destination=None):
        return subprocess.run(
            [shutil.which('bash'), str(_SCRIPT), '-p',
             str(destination or self.destination), *args],
            cwd=self.temp.name, env=self.env,
            capture_output=True, text=True, timeout=9,
        )

    def test_path_with_spaces_is_accepted_and_pruned(self):
        self.env['MOCK_PCT_BEFORE'] = '70'
        result = self.run_prune('-t', '60')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(self.log_file.exists(), result.stdout)

    def test_prune_when_disk_usage_equals_percent_threshold(self):
        plain_path = Path(self.temp.name) / 'capture'
        self.destination.rename(plain_path)
        self.destination = plain_path
        self.log_file = plain_path / 'old.pcap'
        result = self.run_prune('-t', '60')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(self.log_file.exists(), result.stdout)

    def test_prune_when_directory_size_equals_gb_threshold(self):
        plain_path = Path(self.temp.name) / 'capture'
        self.destination.rename(plain_path)
        self.destination = plain_path
        self.log_file = plain_path / 'old.pcap'
        result = self.run_prune('-m', '1')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(self.log_file.exists(), result.stdout)

    def test_below_threshold_keeps_old_capture(self):
        self.env['MOCK_PCT_BEFORE'] = '59'
        plain_path = Path(self.temp.name) / 'capture'
        self.destination.rename(plain_path)
        self.destination = plain_path
        self.log_file = plain_path / 'old.pcap'
        result = self.run_prune('-t', '60')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(self.log_file.exists())


if __name__ == '__main__':
    unittest.main()
