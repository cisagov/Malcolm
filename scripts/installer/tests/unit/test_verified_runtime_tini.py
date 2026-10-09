"""Offline tests for verified Tini installation in Malcolm runtime images."""

import hashlib
import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
INSTALLER = ROOT / "shared/bin/install-verified-runtime-tini.sh"
MANIFEST = ROOT / "Dockerfiles/checksums/tini-runtime-v0.19.0.sha256"
IMAGES = ("filebeat", "logstash", "opensearch")
OFFICIAL_HASHES = {
    "tini-amd64": "93dcc18adc78c65a028a84799ecf8ad40c936fdfc5f2a57b1acda5a8117fa82c",
    "tini-arm64": "07952557df20bfd2a95f9bef198b445e006171969499a1d361bd9e6f8e5e0e81",
}


class VerifiedRuntimeTiniTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.folder = Path(temporary.name)
        self.fakebin = self.folder / "bin"
        self.fakebin.mkdir()
        curl = self.fakebin / "curl"
        curl.write_text(
            "#!/bin/sh\n"
            "set -eu\n"
            'printf "%s\\n" "$*" >> "$MOCK_CURL_LOG"\n'
            'if [ "$MOCK_CURL_FAIL" = 1 ]; then exit 22; fi\n'
            'while [ "$#" -gt 0 ]; do\n'
            '  if [ "$1" = "-o" ]; then shift; target="$1"; fi\n'
            "  shift\n"
            "done\n"
            'cp "$MOCK_CURL_CONTENT" "$target"\n',
            encoding="utf-8",
        )
        curl.chmod(0o755)
        self.logfile = self.folder / "curl.log"
        self.contentfile = self.folder / "download"
        self.output = self.folder / "installed-tini"
        self.original = b"original functional tini"
        self.output.write_bytes(self.original)
        self.fixture = {
            "amd64": b"synthetic executable for amd64",
            "arm64": b"synthetic executable for arm64",
        }
        self.checksums = self.folder / "checksums.sha256"
        self.checksums.write_text(
            "".join(
                f"{hashlib.sha256(blob).hexdigest()}  tini-{arch}\n"
                for arch, blob in self.fixture.items()
            ),
            encoding="utf-8",
        )

    def run_installer(
        self,
        arch="amd64",
        *,
        content=None,
        manifest=None,
        download_error=False,
    ):
        self.contentfile.write_bytes(
            self.fixture.get(arch, b"unknown") if content is None else content
        )
        environment = os.environ.copy()
        environment.update(
            PATH=str(self.fakebin) + os.pathsep + environment["PATH"],
            MOCK_CURL_LOG=str(self.logfile),
            MOCK_CURL_FAIL="1" if download_error else "0",
            MOCK_CURL_CONTENT=str(self.contentfile),
        )
        return subprocess.run(
            [
                "sh",
                str(INSTALLER),
                arch,
                str(self.checksums if manifest is None else manifest),
                f"https://example.invalid/v0.19.0/tini-{arch}",
                str(self.output),
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=20,
            env=environment,
        )

    def assert_existing_preserved(self):
        self.assertEqual(self.output.read_bytes(), self.original)

    def test_success_for_both_supported_architectures(self):
        for arch in ("amd64", "arm64"):
            with self.subTest(arch=arch):
                result = self.run_installer(arch)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(self.output.read_bytes(), self.fixture[arch])
                self.assertTrue(self.output.stat().st_mode & stat.S_IXUSR)
                self.assertIn(f"tini-{arch}", self.logfile.read_text())
                self.output.write_bytes(self.original)

    def test_integrity_mismatch_fails_without_overwriting(self):
        result = self.run_installer(content=b"tampered payload")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("FAILED", result.stdout + result.stderr)
        self.assert_existing_preserved()

    def test_http_failure_fails_without_overwriting(self):
        result = self.run_installer(download_error=True)
        self.assertNotEqual(result.returncode, 0)
        self.assert_existing_preserved()

    def test_absent_manifest_prevents_download(self):
        result = self.run_installer(manifest=self.folder / "missing")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.logfile.exists())
        self.assert_existing_preserved()

    def test_missing_target_checksum_prevents_download(self):
        self.checksums.write_text("")
        result = self.run_installer()
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.logfile.exists())
        self.assert_existing_preserved()

    def test_duplicate_entries_are_rejected(self):
        current = self.checksums.read_text()
        self.checksums.write_text(current + current.splitlines()[0] + "\n")
        result = self.run_installer()
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.logfile.exists())
        self.assert_existing_preserved()

    def test_short_checksum_is_rejected(self):
        self.checksums.write_text("invalid  tini-amd64\n")
        result = self.run_installer()
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.logfile.exists())
        self.assert_existing_preserved()

    def test_nonhex_64_digit_checksum_is_rejected(self):
        self.checksums.write_text("z" * 64 + "  tini-amd64\n")
        result = self.run_installer()
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.logfile.exists())
        self.assert_existing_preserved()

    def test_extra_fields_cannot_be_accepted(self):
        digest = hashlib.sha256(self.fixture["amd64"]).hexdigest()
        self.checksums.write_text(f"{digest}  tini-amd64  extraneous\n")
        result = self.run_installer()
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.logfile.exists())
        self.assert_existing_preserved()

    def test_unknown_architecture_is_rejected(self):
        result = self.run_installer(arch="386")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Unsupported Tini architecture", result.stderr)
        self.assertFalse(self.logfile.exists())
        self.assert_existing_preserved()

    def test_v0190_checksums_match_independent_release_download(self):
        values = {
            name: digest
            for digest, name in (
                line.split() for line in MANIFEST.read_text().splitlines()
            )
        }
        self.assertEqual(values, OFFICIAL_HASHES)

    def test_all_three_images_install_verified_tini(self):
        for name in IMAGES:
            with self.subTest(image=name):
                dockerfile = (ROOT / "Dockerfiles" / f"{name}.Dockerfile").read_text()
                self.assertIn("shared/bin/install-verified-runtime-tini.sh", dockerfile)
                self.assertIn(
                    "Dockerfiles/checksums/tini-runtime-v0.19.0.sha256",
                    dockerfile,
                )
                self.assertIn(
                    '/usr/local/bin/install-verified-runtime-tini.sh "$BINARCH"',
                    dockerfile,
                )
                self.assertIn("coreutils", dockerfile)
                self.assertNotIn("curl -sSLf -o /usr/bin/tini", dockerfile)
                self.assertLess(
                    dockerfile.index(
                        "ADD --chmod=755 shared/bin/install-verified-runtime-tini.sh"
                    ),
                    dockerfile.index(
                        '/usr/local/bin/install-verified-runtime-tini.sh "$BINARCH"'
                    ),
                )


if __name__ == "__main__":
    unittest.main()
