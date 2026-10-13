#!/usr/bin/env python3
# Copyright (c) 2026 Battelle Energy Alliance, LLC. All rights reserved.
"""Regressions for the Filebeat cleanup process lock.

Extract the production entrypoint to avoid container-only magic and Malcolm imports.
"""

import ast
import fcntl
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

_SOURCE = Path(__file__).resolve().parents[4] / 'filebeat/scripts/clean-processed-folder.py'


def _load_main(lock_path, cleanup):
    source = ast.parse(_SOURCE.read_text())
    function = next(
        entry for entry in source.body
        if isinstance(entry, ast.FunctionDef) and entry.name == 'main'
    )
    context = {
        'fcntl': fcntl,
        'os': os,
        'lock_filename': str(lock_path),
        'prune_files': cleanup,
        'set_logging': lambda *args, **kwargs: None,
        'get_verbosity_env_var_count': lambda *args: 0,
    }
    exec(compile(ast.Module(body=[function], type_ignores=[]),
                 str(_SOURCE), 'exec'), context)
    return context['main']


class CleanupLockfileTest(unittest.TestCase):

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.lockfile = Path(self.directory.name) / 'filebeat-cleanup.lock'
        self.cleanup = mock.Mock()
        self.run_cleanup = _load_main(self.lockfile, self.cleanup)

    def test_contender_does_not_unlink_other_process_lock(self):
        self.lockfile.touch()
        with self.lockfile.open('a') as owner:
            fcntl.flock(owner, fcntl.LOCK_EX | fcntl.LOCK_NB)
            inode = os.stat(self.lockfile).st_ino
            self.run_cleanup()
            self.cleanup.assert_not_called()
            self.assertTrue(self.lockfile.exists())
            self.assertEqual(os.stat(self.lockfile).st_ino, inode)
            # A third process must not get a new inode either.
            self.run_cleanup()
            self.cleanup.assert_not_called()
            self.assertEqual(os.stat(self.lockfile).st_ino, inode)
            fcntl.flock(owner, fcntl.LOCK_UN)
        self.run_cleanup()
        self.cleanup.assert_called_once_with()

    def test_success_keeps_persistent_lock_inode(self):
        self.run_cleanup()
        self.cleanup.assert_called_once_with()
        self.assertTrue(self.lockfile.exists())
        inode = os.stat(self.lockfile).st_ino
        self.run_cleanup()
        self.assertEqual(self.cleanup.call_count, 2)
        self.assertEqual(os.stat(self.lockfile).st_ino, inode)

    def test_failed_prune_preserves_lock_and_allows_retry(self):
        self.cleanup.side_effect = RuntimeError('cleanup failed')
        with self.assertRaisesRegex(RuntimeError, 'cleanup failed'):
            self.run_cleanup()
        self.assertTrue(self.lockfile.exists())
        inode = os.stat(self.lockfile).st_ino
        self.cleanup.side_effect = None
        self.run_cleanup()
        self.assertEqual(self.cleanup.call_count, 2)
        self.assertEqual(os.stat(self.lockfile).st_ino, inode)

    def test_recursive_attempt_cannot_run_concurrent_prune(self):
        calls = []

        def cleanup():
            calls.append('cleanup')
            self.run_cleanup()

        self.run_cleanup = _load_main(self.lockfile, cleanup)
        self.run_cleanup()
        self.assertEqual(calls, ['cleanup'])
        self.assertTrue(self.lockfile.exists())


if __name__ == '__main__':
    unittest.main()
