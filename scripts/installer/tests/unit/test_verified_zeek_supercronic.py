# Copyright (c) 2026 Battelle Energy Alliance, LLC.  All rights reserved.

"""Verify fail-closed Supercronic installation in the Zeek image."""

import hashlib
import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
INSTALLER = ROOT / "shared/bin/install-verified-supercronic.sh"
MANIFEST = ROOT / "Dockerfiles/checksums/supercronic-v0.2.49.sha256"
DOCKERFILE = ROOT / "Dockerfiles/zeek.Dockerfile"


class TestVerifiedZeekSupercronic(unittest.TestCase):
    def setUp(self):
        self.workspace = tempfile.TemporaryDirectory()
        self.addCleanup(self.workspace.cleanup)
        self.base = Path(self.workspace.name)
        self.curl_bin = self.base / "bin"
        self.curl_bin.mkdir()
        mock_curl = self.curl_bin / "curl"
        mock_curl.write_text(
            "#!/bin/sh\n"
            "set -eu\n"
            "printf 'called\\n' >> \"$MOCK_CURL_LOG\"\n"
            'if [ "$MOCK_CURL_FAIL" = 1 ]; then exit 22; fi\n'
            'while [ "$#" -gt 0 ]; do\n'
            '  case "$1" in -o) shift; target="$1" ;; esac\n'
            "  shift\n"
            "done\n"
            'cp "$MOCK_DOWNLOAD_SOURCE" "$target"\n',
            encoding="utf-8",
        )
        mock_curl.chmod(0o755)
        self.archives = {
            "amd64": b"#! /bin/sh\nprintf 'mock AMD64 executable\\n'\n",
            "arm64": b"#! /bin/sh\nprintf 'mock ARM64 executable\\n'\n",
        }
        self.manifest = self.base / "checksums.txt"
        self.manifest.write_text(
            "".join(
                f"{hashlib.sha256(payload).hexdigest()}  supercronic-linux-{arch}\n"
                for arch, payload in self.archives.items()
            ),
            encoding="utf-8",
        )
        self.target = self.base / "supercronic"
        self.target.write_bytes(b"existing executable")
        self.download = self.base / "download.bin"
        self.log = self.base / "downloads.log"

    def install(self, arch, *, manifest=None, payload=None, fail=False):
        self.download.write_bytes(
            self.archives.get(arch, b"mismatched binary")
            if payload is None
            else payload
        )
        env = os.environ.copy()
        env.update(
            PATH=str(self.curl_bin) + os.pathsep + env["PATH"],
            SUPERCRONIC_URL="https://example.invalid/v0.2.49/supercronic-linux-",
            MOCK_CURL_LOG=str(self.log),
            MOCK_CURL_FAIL="1" if fail else "0",
            MOCK_DOWNLOAD_SOURCE=str(self.download),
        )
        return subprocess.run(
            [
                "bash",
                str(INSTALLER),
                arch,
                str(manifest or self.manifest),
                str(self.target),
            ],
            env=env,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )

    def test_supported_architectures_install_verified_binaries(self):
        for arch in ("amd64", "arm64"):
            with self.subTest(arch=arch):
                result = self.install(arch)
                self.assertEqual(0, result.returncode, result.stderr)
                self.assertEqual(self.archives[arch], self.target.read_bytes())
                self.assertTrue(self.target.stat().st_mode & stat.S_IXUSR)

    def test_corrupted_binary_does_not_replace_existing_one(self):
        result = self.install("amd64", payload=b"tampered binary")
        self.assertNotEqual(0, result.returncode)
        self.assertIn("FAILED", result.stdout + result.stderr)
        self.assertEqual(b"existing executable", self.target.read_bytes())

    def test_missing_manifest_entry_prevents_download(self):
        self.manifest.write_text("", encoding="utf-8")
        result = self.install("amd64")
        self.assertNotEqual(0, result.returncode)
        self.assertFalse(self.log.exists())
        self.assertEqual(b"existing executable", self.target.read_bytes())

    def test_duplicate_checksum_prevents_download(self):
        contents = self.manifest.read_text(encoding="utf-8")
        self.manifest.write_text(contents + contents.splitlines()[0] + "\n")
        result = self.install("amd64")
        self.assertNotEqual(0, result.returncode)
        self.assertFalse(self.log.exists())
        self.assertEqual(b"existing executable", self.target.read_bytes())

    def test_unsupported_architecture_prevents_download(self):
        result = self.install("i386")
        self.assertNotEqual(0, result.returncode)
        self.assertIn("Unsupported", result.stderr)
        self.assertFalse(self.log.exists())
        self.assertEqual(b"existing executable", self.target.read_bytes())

    def test_failed_download_does_not_replace_existing_one(self):
        result = self.install("amd64", fail=True)
        self.assertNotEqual(0, result.returncode)
        self.assertEqual(b"existing executable", self.target.read_bytes())

    def test_checked_in_manifest_has_supported_release_digests(self):
        lines = MANIFEST.read_text(encoding="utf-8").splitlines()
        expected = {
            "supercronic-linux-amd64": "a53ae236602c7338aba3fbaff40bda6300eae3b9fedb8261eb06cfe3724430c1",
            "supercronic-linux-arm64": "02aa0cb229ba09050cba6638059dadb9eedc2276632ea43d6a57a2f8c1629dd5",
        }
        found = {
            filename: digest for digest, filename in (line.split() for line in lines)
        }
        self.assertEqual(expected, found)

    def test_dockerfile_checks_before_install_and_stages_manifest(self):
        source = DOCKERFILE.read_text(encoding="utf-8")
        self.assertIn(
            "COPY --chmod=755 shared/bin/install-verified-supercronic.sh", source
        )
        self.assertIn(
            "COPY --chmod=644 Dockerfiles/checksums/supercronic-v0.2.49.sha256", source
        )
        self.assertIn(
            '/usr/local/bin/install-verified-supercronic.sh "$BINARCH"', source
        )
        self.assertNotIn("curl -fsSL -o /usr/local/bin/supercronic", source)
        self.assertLess(
            source.index("COPY --chmod=755 shared/bin/install-verified-supercronic.sh"),
            source.index("RUN export BINARCH="),
        )


if __name__ == "__main__":
    unittest.main()
