# Copyright (c) 2026 Battelle Energy Alliance, LLC. All rights reserved.

"""Exercise the Dockerfile's ECS verification block with a local archive."""

import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
DOCKERFILE = ROOT / 'Dockerfiles/dashboards-helper.Dockerfile'


@unittest.skipUnless(shutil.which('sha256sum') and shutil.which('tar'), 'sha256sum and tar required')
class TestPinnedEcsSchema(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='ECS verification ')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.archive = self.root / 'source.tar.gz'
        payload = b'{"template":{"mappings":{"properties":{"test":{"type":"keyword"}}}}}'
        with tarfile.open(self.archive, 'w:gz') as archive:
            member = tarfile.TarInfo('ecs-fixture/generated/elasticsearch/template.json')
            member.size = len(payload)
            archive.addfile(member, io.BytesIO(payload))
        self.digest = hashlib.sha256(self.archive.read_bytes()).hexdigest()
        self.bin = self.root / 'bin'
        self.bin.mkdir()
        curl = self.bin / 'curl'
        curl.write_text('''#!/usr/bin/env python3
import os
import shutil
import sys
if os.environ.get('FAIL_DOWNLOAD') == 'true':
    sys.exit(22)
shutil.copyfile(os.environ['ECS_FIXTURE'], sys.argv[sys.argv.index('-o') + 1])
''')
        curl.chmod(0o755)
        (self.root / 'ecs').mkdir()

    def run_download_block(self, digest=None, **environment):
        docker = DOCKERFILE.read_text()
        start = docker.index('      curl -fsSL -o /tmp/ecs-source.tar.gz')
        end = docker.index('      mv /opt/ecs/generated/elasticsearch', start)
        block = docker[start:end].strip()
        self.assertTrue(block.endswith('&& \\'))
        block = block[:-4].rstrip()
        block = block.replace('/tmp/ecs-source.tar.gz', './ecs-source.tar.gz')
        return subprocess.run(
            ['sh', '-c', 'set -eu\n' + block],
            cwd=self.root,
            env={
                **os.environ,
                'PATH': str(self.bin) + os.pathsep + os.environ['PATH'],
                'ECS_FIXTURE': str(self.archive),
                'ECS_SOURCE_URL': 'https://example.invalid/ecs.tar.gz',
                'ECS_SHA256': digest or self.digest,
                **environment,
            },
            capture_output=True,
            text=True,
            check=False,
        )

    def test_verified_archive_is_extracted(self):
        result = self.run_download_block()
        self.assertEqual(0, result.returncode, result.stderr)
        result_file = self.root / 'ecs/generated/elasticsearch/template.json'
        self.assertEqual(
            'keyword', json.loads(result_file.read_text())['template']['mappings']['properties']['test']['type']
        )

    def test_wrong_digest_prevents_extraction(self):
        result = self.run_download_block(digest='0' * 64)
        self.assertNotEqual(0, result.returncode)
        self.assertEqual([], list((self.root / 'ecs').iterdir()))

    def test_changed_archive_prevents_extraction(self):
        self.archive.write_bytes(self.archive.read_bytes() + b'changed source')
        result = self.run_download_block()
        self.assertNotEqual(0, result.returncode)
        self.assertEqual([], list((self.root / 'ecs').iterdir()))

    def test_failed_download_prevents_extraction(self):
        result = self.run_download_block(FAIL_DOWNLOAD='true')
        self.assertNotEqual(0, result.returncode)
        self.assertEqual([], list((self.root / 'ecs').iterdir()))

    def test_pin_is_immutable_and_existing_template_processing_is_preserved(self):
        docker = DOCKERFILE.read_text()
        self.assertRegex(docker, r'ENV ECS_VERSION="[0-9]+\.[0-9]+\.[0-9]+"')
        self.assertIsNotNone(re.search(r'ENV ECS_COMMIT="[0-9a-f]{40}"', docker))
        self.assertIsNotNone(re.search(r'ENV ECS_SHA256="[0-9a-f]{64}"', docker))
        self.assertIn('https://codeload.github.com/elastic/ecs/tar.gz/${ECS_COMMIT}', docker)
        self.assertNotIn('ECS_RELEASES_URL', docker)
        self.assertNotIn('/elastic/ecs/releases/latest', docker)
        self.assertIn('mv /opt/ecs/generated/elasticsearch /opt/ecs-templates', docker)
        self.assertIn('rsync -av /opt/ecs-templates/ /opt/ecs-templates-os/', docker)
        self.assertIn('synthetic_source_keep', docker)


if __name__ == '__main__':
    unittest.main()
