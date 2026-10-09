# Copyright (c) 2026 Battelle Energy Alliance, LLC.  All rights reserved.

"""Tests for checksum-enforced Tini installation in Malcolm containers."""

import hashlib
import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
SCRIPT = ROOT / "shared/bin/install-verified-tini.sh"
CHECKSUMS = ROOT / "Dockerfiles/checksums/tini-v0.19.0.sha256"
IMAGES = [
    ROOT / "Dockerfiles/keycloak.Dockerfile",
    ROOT / "Dockerfiles/dashboards.Dockerfile",
]


class TestTiniVerification(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.dir = Path(self.temp.name)
        self.bin = self.dir / "bin"
        self.bin.mkdir()
        fake_curl = self.bin / "curl"
        fake_curl.write_text(
            "#!/bin/sh\n"
            "set -eu\n"
            "printf 'called\\n' >> \"$MOCK_CURL_LOG\"\n"
            'if [ "$MOCK_CURL_ERROR" = 1 ]; then exit 22; fi\n'
            'while [ "$#" -gt 0 ]; do\n'
            '  if [ "$1" = \'-o\' ]; then shift; target="$1"; fi\n'
            "  shift\n"
            "done\n"
            'cp "$MOCK_CURL_SOURCE" "$target"\n',
            encoding="utf-8",
        )
        fake_curl.chmod(0o755)
        self.content = {
            "amd64": b"mock executable for amd64",
            "arm64": b"mock executable for arm64",
        }
        self.manifest = self.dir / "checksums.sha256"
        self.manifest.write_text(
            "".join(
                f"{hashlib.sha256(payload).hexdigest()}  tini-{arch}\n"
                for arch, payload in self.content.items()
            ),
            encoding="utf-8",
        )
        self.download = self.dir / "download"
        self.target = self.dir / "tini"
        self.target.write_bytes(b"original executable")
        self.log = self.dir / "curl.log"

    def invoke(self, arch="amd64", *, contents=None, curl_error=False, manifest=None):
        self.download.write_bytes(
            self.content.get(arch, b"other") if contents is None else contents
        )
        env = os.environ.copy()
        env.update(
            PATH=f"{self.bin}{os.pathsep}{env['PATH']}",
            TINI_URL="https://example.invalid/tini",
            MOCK_CURL_SOURCE=str(self.download),
            MOCK_CURL_LOG=str(self.log),
            MOCK_CURL_ERROR="1" if curl_error else "0",
        )
        return subprocess.run(
            ["sh", str(SCRIPT), arch, str(manifest or self.manifest), str(self.target)],
            env=env,
            text=True,
            capture_output=True,
            timeout=10,
            check=False,
        )

    def test_both_supported_architectures_install_verified_binary(self):
        for arch, contents in self.content.items():
            with self.subTest(arch=arch):
                result = self.invoke(arch)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(self.target.read_bytes(), contents)
                self.assertTrue(self.target.stat().st_mode & stat.S_IXUSR)

    def test_modified_binary_is_rejected_without_overwriting(self):
        result = self.invoke(contents=b"tampered")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("FAILED", result.stdout + result.stderr)
        self.assertEqual(self.target.read_bytes(), b"original executable")

    def test_failed_download_preserves_existing_executable(self):
        result = self.invoke(curl_error=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.target.read_bytes(), b"original executable")

    def test_missing_manifest_rejected_before_network(self):
        result = self.invoke(manifest=self.dir / "absent")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.log.exists())

    def test_duplicate_checksum_entries_rejected_before_network(self):
        line = self.manifest.read_text().splitlines()[0]
        self.manifest.write_text(self.manifest.read_text() + line + "\n")
        result = self.invoke()
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.log.exists())

    def test_malformed_digest_rejected_before_network(self):
        self.manifest.write_text("123bad  tini-amd64\n")
        result = self.invoke()
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.log.exists())

    def test_unsupported_architecture_rejected_before_network(self):
        result = self.invoke("s390x")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Unsupported", result.stderr)
        self.assertFalse(self.log.exists())

    def test_repository_hashes_match_pinned_release(self):
        expected = {
            "tini-amd64": "93dcc18adc78c65a028a84799ecf8ad40c936fdfc5f2a57b1acda5a8117fa82c",
            "tini-arm64": "07952557df20bfd2a95f9bef198b445e006171969499a1d361bd9e6f8e5e0e81",
        }
        hashes = {
            filename: digest
            for digest, filename in (
                line.split() for line in CHECKSUMS.read_text().splitlines()
            )
        }
        self.assertEqual(hashes, expected)

    def test_both_dockerfiles_stage_and_verify_the_download(self):
        for path in IMAGES:
            with self.subTest(image=path.name):
                content = path.read_text()
                self.assertIn(
                    "COPY --chmod=755 shared/bin/install-verified-tini.sh", content
                )
                self.assertIn(
                    "COPY --chmod=644 Dockerfiles/checksums/tini-v0.19.0.sha256",
                    content,
                )
                self.assertIn(
                    'install-verified-tini.sh "$BINARCH" /tmp/tini-v0.19.0.sha256 /usr/bin/tini',
                    content,
                )
                self.assertNotIn("curl -sSLf -o /usr/bin/tini", content)
                self.assertLess(
                    content.index(
                        "COPY --chmod=755 shared/bin/install-verified-tini.sh"
                    ),
                    content.index("RUN export BINARCH="),
                )


if __name__ == "__main__":
    unittest.main()
