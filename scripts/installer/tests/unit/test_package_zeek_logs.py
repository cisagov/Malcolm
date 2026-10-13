#!/usr/bin/env python3
# Copyright (c) 2026 Battelle Energy Alliance, LLC. All rights reserved.
"""Integration tests for log packaging using real gzip and tar files."""

import gzip
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import unittest


_SCRIPT = Path(__file__).resolve().parents[4] / 'scripts/package_zeek_logs.sh'
_BASH = shutil.which('bash')
_REQUIRED = ('awk', 'date', 'dirname', 'find', 'gunzip', 'mktemp', 'realpath', 'tar')


@unittest.skipUnless(_BASH and all(shutil.which(name) for name in _REQUIRED), 'Requires packaging shell tools')
class PackageZeekLogsTest(unittest.TestCase):

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.logs = self.root / 'logs'
        self.logs.mkdir()
        self.work = self.root / 'work'
        self.work.mkdir()
        self.env = dict(os.environ, TMPDIR=str(self.work))

    def add_log(self, relative, content):
        path = self.logs / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        with gzip.open(path, 'wb') as archive:
            archive.write(content)
        return path

    def package(self):
        originals = {p: p.read_bytes() for p in self.logs.rglob('*.log.gz')}
        result = subprocess.run(
            [_BASH, str(_SCRIPT), '-d', str(self.logs)],
            cwd=self.root, env=self.env, capture_output=True, text=True, timeout=15,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        output = Path(result.stdout.strip())
        self.assertTrue(output.is_file(), result.stdout)
        self.assertEqual(output.parent, self.logs.resolve())
        with tarfile.open(output, 'r:gz') as archive:
            files = {
                member.name.removeprefix('./'): archive.extractfile(member).read()
                for member in archive.getmembers() if member.isfile()
            }
        for path, content in originals.items():
            self.assertEqual(path.read_bytes(), content)
        self.assertEqual(list(self.work.iterdir()), [])
        return files

    def test_standard_rotated_log_layout(self):
        self.add_log('2026-10-13/conn.10:00:00-11:00:00.log.gz', b'#fields\tts\tuid\n1\tC1\n')
        self.assertEqual(self.package(), {'2026_10_13_10.00/conn.log': b'#fields\tts\tuid\n1\tC1\n'})

    def test_base_directory_with_spaces_and_glob_characters(self):
        destination = self.root / 'Zeek logs [batch]'
        self.logs.rename(destination)
        self.logs = destination
        self.add_log('2026-10-13/dns.10:00:00-11:00:00.log.gz', b'dns content\n')
        self.assertEqual(self.package(), {'2026_10_13_10.00/dns.log': b'dns content\n'})

    def test_nested_paths_preserve_whitespace(self):
        for prefix in ('uploaded logs', 'uploaded\tlogs', 'uploaded\nlogs'):
            with self.subTest(prefix=prefix):
                log = self.add_log(f'{prefix}/2026-10-13/conn.10:00:00-11:00:00.log.gz', b'connection\n')
                self.assertEqual(self.package(), {'2026_10_13_10.00/conn.log': b'connection\n'})
                log.unlink()

    def test_multiple_rotations_of_one_type_are_preserved(self):
        self.add_log('2026-10-13/conn.10:00:00-10:30:00.log.gz', b'first rotation\n')
        self.add_log('2026-10-13/conn.10:30:00-11:00:00.log.gz', b'second rotation\n')
        files = self.package()
        self.assertEqual(set(files), {'2026_10_13_10.00/conn.log', '2026_10_13_10.01/conn.log'})
        self.assertEqual(set(files.values()), {b'first rotation\n', b'second rotation\n'})

    def test_corrupt_log_fails_and_cleans_temporary_work(self):
        path = self.logs / '2026-10-13/conn.10:00:00-11:00:00.log.gz'
        path.parent.mkdir()
        path.write_bytes(b'not a gzip archive')
        result = subprocess.run(
            [_BASH, str(_SCRIPT), '-d', str(self.logs)], cwd=self.root,
            env=self.env, capture_output=True, text=True, timeout=15,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(path.read_bytes(), b'not a gzip archive')
        self.assertEqual(list(self.work.iterdir()), [])
        self.assertEqual(list(self.logs.glob('zeek-logs-compressed-*.tar.gz')), [])


if __name__ == '__main__':
    unittest.main()
