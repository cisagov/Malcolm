# Copyright (c) 2026 Battelle Energy Alliance, LLC. All rights reserved.

"""Exercise the real pipeline staging helper without a Logstash deployment."""

import os
import shutil
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
HELPER = ROOT / 'logstash/scripts/logstash-stage-pipelines.sh'


@unittest.skipUnless(shutil.which('bash') and shutil.which('rsync'), 'bash and rsync required')
class TestLogstashPipelineAssets(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='pipeline assets ')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.source = self.root / 'host source'
        self.runtime = self.root / 'runtime destination'
        self.source.mkdir()
        self.runtime.mkdir()

    def stage(self, source=None, runtime=None):
        return subprocess.run(
            ['bash', str(HELPER), str(source or self.source), str(runtime or self.runtime)],
            capture_output=True,
            text=True,
            check=False,
        )

    def write(self, path, content):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding='utf-8')

    def test_nested_dictionary_and_filter_are_copied(self):
        self.write(self.source / 'enrichment/25_site.conf', 'filter { translate {} }\n')
        self.write(self.source / 'enrichment/lookups/site.yaml', 'reference: equipment\n')
        result = self.stage()
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual('reference: equipment\n', (self.runtime / 'enrichment/lookups/site.yaml').read_text())
        self.assertTrue((self.runtime / 'enrichment/25_site.conf').is_file())

    def test_preserves_bundled_files_and_overrides_same_name(self):
        self.write(self.runtime / 'zeek/1000_original.conf', 'original')
        self.write(self.runtime / 'zeek/1200_override.conf', 'old')
        self.write(self.source / 'zeek/1200_override.conf', 'replacement')
        self.assertEqual(0, self.stage().returncode)
        self.assertEqual('original', (self.runtime / 'zeek/1000_original.conf').read_text())
        self.assertEqual('replacement', (self.runtime / 'zeek/1200_override.conf').read_text())

    def test_empty_and_missing_sources_are_noops(self):
        (self.source / 'empty').mkdir()
        self.assertEqual(0, self.stage().returncode)
        self.assertEqual([], list(self.runtime.iterdir()))
        self.assertEqual(0, self.stage(source=self.root / 'missing').returncode)

    def test_new_pipeline_and_regular_assets(self):
        self.write(self.source / 'site/01_input.conf', 'input { pipeline { address => "site" } }')
        self.write(self.source / 'site/99_output.conf', 'output { stdout {} }')
        self.write(self.source / 'site/script.rb', 'def filter(event); [event]; end')
        self.assertEqual(0, self.stage().returncode)
        self.assertEqual(3, len(list((self.runtime / 'site').iterdir())))

    def test_read_only_source_produces_writable_runtime_copy(self):
        source = self.source / 'enrichment/25_site.conf'
        self.write(source, 'filter {}')
        source.chmod(0o444)
        self.assertEqual(0, self.stage().returncode)
        target = self.runtime / 'enrichment/25_site.conf'
        self.assertTrue(target.stat().st_mode & stat.S_IWUSR)
        self.assertFalse(source.stat().st_mode & stat.S_IWUSR)
        target.write_text('updated')
        self.assertEqual('filter {}', source.read_text())

    def test_source_symlinks_are_not_followed(self):
        secret = self.root / 'outside.txt'
        self.write(secret, 'outside')
        self.write(self.source / 'enrichment/25_site.conf', 'filter {}')
        (self.source / 'enrichment/link.txt').symlink_to(secret)
        (self.source / 'linked-pipeline').symlink_to(self.source / 'enrichment', target_is_directory=True)
        self.assertEqual(0, self.stage().returncode)
        self.assertFalse(os.path.lexists(self.runtime / 'enrichment/link.txt'))
        self.assertFalse(os.path.lexists(self.runtime / 'linked-pipeline'))

    def test_invalid_pipeline_name_is_rejected(self):
        self.write(self.source / 'bad name/25_site.conf', 'filter {}')
        result = self.stage()
        self.assertNotEqual(0, result.returncode)
        self.assertIn('Invalid pipeline directory name', result.stderr)

    def test_overlapping_paths_are_rejected(self):
        self.assertNotEqual(0, self.stage(runtime=self.source).returncode)
        self.assertNotEqual(0, self.stage(runtime=self.source / 'nested').returncode)

    def test_runtime_pipeline_symlink_is_rejected(self):
        outside = self.root / 'outside'
        outside.mkdir()
        (self.runtime / 'enrichment').symlink_to(outside, target_is_directory=True)
        self.write(self.source / 'enrichment/25_site.conf', 'filter {}')
        self.assertNotEqual(0, self.stage().returncode)
        self.assertEqual([], list(outside.iterdir()))

    def test_rsync_errors_propagate(self):
        fake_bin = self.root / 'bin'
        self.write(fake_bin / 'rsync', '#!/bin/sh\nexit 23\n')
        (fake_bin / 'rsync').chmod(0o755)
        self.write(self.source / 'enrichment/25_site.conf', 'filter {}')
        result = subprocess.run(
            ['bash', str(HELPER), str(self.source), str(self.runtime)],
            env={**os.environ, 'PATH': str(fake_bin) + os.pathsep + os.environ['PATH']},
            capture_output=True,
            check=False,
        )
        self.assertEqual(23, result.returncode)

    def test_startup_uses_helper_and_only_conf_files(self):
        startup = (ROOT / 'logstash/scripts/logstash-start.sh').read_text()
        self.assertIn('logstash-stage-pipelines.sh', startup)
        self.assertIn('path.config: {}/*.conf', startup)
        self.assertLess(startup.index('logstash-stage-pipelines.sh'), startup.index('> "$PIPELINES_CFG"'))


if __name__ == '__main__':
    unittest.main()
