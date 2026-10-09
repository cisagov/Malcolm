# Copyright (c) 2026 Battelle Energy Alliance, LLC. All rights reserved.

"""Run the real download helper with local artifacts and no external requests."""

import hashlib
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
HELPER = ROOT / 'shared/bin/download-verified-arkime.sh'


@unittest.skipUnless(shutil.which('sha256sum'), 'sha256sum required')
class TestVerifiedArkimeDownload(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='arkime verification ')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.fixture = self.root / 'fixtures'
        self.output = self.root / 'output'
        self.bin = self.root / 'bin'
        for path in (self.fixture, self.output, self.bin):
            path.mkdir()
        self.manifest = self.root / 'checksums.sha256'
        self.names = [name for arch in ('amd64', 'arm64') for name in self.artifact_names(arch)]
        rows = []
        for name in self.names:
            data = ('synthetic artifact ' + name).encode()
            (self.fixture / name).write_bytes(data)
            rows.append(f'{hashlib.sha256(data).hexdigest()}  {name}\n')
        self.manifest.write_text(''.join(rows))
        fake = self.bin / 'curl'
        fake.write_text('''#!/usr/bin/env python3
import os
import shutil
import sys
from pathlib import Path
name = sys.argv[-1].rsplit('/', 1)[-1]
with open(os.environ['DOWNLOAD_LOG'], 'a') as log:
    log.write(name + '\\n')
if name == os.environ.get('FAIL_ARTIFACT'):
    sys.exit(22)
output = Path(sys.argv[sys.argv.index('-o') + 1])
shutil.copyfile(Path(os.environ['FIXTURE_DIR']) / name, output)
if name == os.environ.get('CORRUPT_ARTIFACT'):
    with output.open('ab') as stream:
        stream.write(b'corrupt')
''')
        fake.chmod(0o755)

    @staticmethod
    def artifact_names(arch):
        return [f'arkime_6.7.0-1.debian13_{arch}.deb', f'ja4plus.{arch}.so']

    def run_helper(self, arch='amd64', version='6.7.0', **environment):
        return subprocess.run(
            ['sh', str(HELPER), version, arch, str(self.output), str(self.manifest)],
            env={
                **os.environ,
                'PATH': str(self.bin) + os.pathsep + os.environ['PATH'],
                'FIXTURE_DIR': str(self.fixture),
                'DOWNLOAD_LOG': str(self.root / 'downloads.log'),
                **environment,
            },
            capture_output=True,
            text=True,
            check=False,
        )

    def assert_no_temporary_directories(self):
        self.assertEqual([], list(self.output.glob('.arkime-download.*')))

    def test_both_architectures_are_verified_and_published(self):
        for arch in ('amd64', 'arm64'):
            with self.subTest(arch=arch):
                result = self.run_helper(arch=arch)
                self.assertEqual(0, result.returncode, result.stderr)
                for name in self.artifact_names(arch):
                    self.assertEqual((self.fixture / name).read_bytes(), (self.output / name).read_bytes())
        self.assert_no_temporary_directories()

    def test_corrupt_plugin_leaves_existing_pair_unchanged(self):
        names = self.artifact_names('amd64')
        for name in names:
            (self.output / name).write_text('previous verified artifact')
        result = self.run_helper(CORRUPT_ARTIFACT=names[1])
        self.assertNotEqual(0, result.returncode)
        for name in names:
            self.assertEqual('previous verified artifact', (self.output / name).read_text())
        self.assert_no_temporary_directories()

    def test_corrupt_package_is_not_published(self):
        result = self.run_helper(CORRUPT_ARTIFACT=self.artifact_names('amd64')[0])
        self.assertNotEqual(0, result.returncode)
        self.assertEqual([], list(self.output.iterdir()))

    def test_download_failure_is_propagated(self):
        result = self.run_helper(FAIL_ARTIFACT='ja4plus.amd64.so')
        self.assertNotEqual(0, result.returncode)
        self.assertEqual([], list(self.output.iterdir()))

    def test_unsupported_architecture_makes_no_request(self):
        self.assertNotEqual(0, self.run_helper(arch='ppc64le').returncode)
        self.assertFalse((self.root / 'downloads.log').exists())

    def test_missing_package_digest_makes_no_request(self):
        self.manifest.write_text('')
        self.assertNotEqual(0, self.run_helper().returncode)
        self.assertFalse((self.root / 'downloads.log').exists())
        self.assert_no_temporary_directories()

    def test_ambiguous_checksum_is_rejected(self):
        self.manifest.write_text(self.manifest.read_text() * 2)
        self.assertNotEqual(0, self.run_helper().returncode)
        self.assertFalse((self.root / 'downloads.log').exists())

    def test_unpinned_version_is_rejected(self):
        self.assertNotEqual(0, self.run_helper(version='99.0.0').returncode)
        self.assertFalse((self.root / 'downloads.log').exists())

    def test_docker_installs_only_after_pair_verification(self):
        docker = (ROOT / 'Dockerfiles/arkime.Dockerfile').read_text()
        call = '/usr/local/bin/download-verified-arkime.sh "$ARKIME_VERSION"'
        self.assertIn('COPY --chmod=755 shared/bin/download-verified-arkime.sh', docker)
        self.assertLess(docker.index(call), docker.index('dpkg -i'))
        self.assertIn('mv "/tmp/ja4plus.${DEBARCH}.so"', docker)
        self.assertNotIn('ARKIME_DEB_URL', docker)
        self.assertNotIn('ARKIME_JA4_SO_URL', docker)
        manifest = (ROOT / 'Dockerfiles/checksums/arkime-v6.7.0.sha256').read_text()
        lines = [line.split() for line in manifest.splitlines() if line and not line.startswith('#')]
        self.assertEqual(set(self.names), {row[1] for row in lines})
        self.assertEqual(4, len(lines))
        for digest, _ in lines:
            self.assertRegex(digest, r'^[0-9a-f]{64}$')


if __name__ == '__main__':
    unittest.main()
