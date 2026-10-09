"""Fail-closed checksum verification for Filebeat's evtx_dump executable."""

import hashlib
import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
INSTALLER = ROOT / "shared/bin/install-verified-evtx.sh"
CHECKSUMS = ROOT / "Dockerfiles/checksums/evtx-v0.12.3.sha256"
DOCKERFILE = ROOT / "Dockerfiles/filebeat.Dockerfile"
RELEASE_HASHES = {
    "x86_64": "a64220cd31e006b4d37c90adb6cca776120f463953b59de71a8089563307b937",
    "aarch64": "f0e38baf52a2020c69ead437f6858cf8e76d5b99a7893e13f28f0973ef6d7ec5",
}


class TestVerifiedEvtxInstall(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.root = Path(self.dir.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        fake_curl = self.bin / "curl"
        fake_curl.write_text(
            "#!/bin/sh\n"
            "set -eu\n"
            "printf 'download\\n' >> \"$MOCK_CURL_LOG\"\n"
            'if [ "$MOCK_CURL_FAIL" = 1 ]; then exit 22; fi\n'
            'while [ "$#" -gt 0 ]; do\n'
            '  if [ "$1" = "-o" ]; then shift; out="$1"; fi\n'
            "  shift\n"
            "done\n"
            'cp "$MOCK_DOWNLOAD_SOURCE" "$out"\n'
        )
        fake_curl.chmod(0o755)
        self.content = {
            "x86_64": b"fake x86_64 ELF executable\n",
            "aarch64": b"fake aarch64 ELF executable\n",
        }
        self.manifest = self.root / "checksums.sha256"
        self.manifest.write_text(
            "".join(
                f"{hashlib.sha256(body).hexdigest()}  "
                f"evtx_dump-v0.12.3-{arch}-unknown-linux-gnu\n"
                for arch, body in self.content.items()
            )
        )
        self.source = self.root / "download"
        self.output = self.root / "evtx"
        self.output.write_bytes(b"original installed executable")
        self.log = self.root / "curl.log"

    def run_installer(
        self, arch="x86_64", *, body=None, manifest=None, download_error=False
    ):
        if body is None:
            body = self.content.get(arch, b"invalid arch")
        self.source.write_bytes(body)
        env = os.environ.copy()
        env.update(
            PATH=str(self.bin) + os.pathsep + env["PATH"],
            MOCK_CURL_LOG=str(self.log),
            MOCK_DOWNLOAD_SOURCE=str(self.source),
            MOCK_CURL_FAIL="1" if download_error else "0",
        )
        return subprocess.run(
            [
                "sh",
                str(INSTALLER),
                arch,
                str(manifest if manifest is not None else self.manifest),
                "https://example.invalid/evtx_dump",
                str(self.output),
            ],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
            env=env,
        )

    def assert_unmodified(self):
        self.assertEqual(self.output.read_bytes(), b"original installed executable")

    def test_both_supported_release_architectures_install(self):
        for arch, expected in self.content.items():
            with self.subTest(arch=arch):
                result = self.run_installer(arch)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(self.output.read_bytes(), expected)
                self.assertTrue(self.output.stat().st_mode & stat.S_IXUSR)
                self.output.write_bytes(b"original installed executable")

    def test_corrupt_binary_fails_before_install(self):
        result = self.run_installer(body=b"tampered payload")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("FAILED", result.stdout + result.stderr)
        self.assert_unmodified()

    def test_failed_download_preserves_installed_binary(self):
        result = self.run_installer(download_error=True)
        self.assertNotEqual(result.returncode, 0)
        self.assert_unmodified()

    def test_missing_manifest_prevents_network(self):
        result = self.run_installer(manifest=self.root / "missing")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.log.exists())
        self.assert_unmodified()

    def test_missing_entry_prevents_network(self):
        self.manifest.write_text("")
        result = self.run_installer()
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.log.exists())
        self.assert_unmodified()

    def test_duplicate_entry_prevents_network(self):
        text = self.manifest.read_text()
        self.manifest.write_text(text + text.splitlines()[0] + "\n")
        result = self.run_installer()
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.log.exists())
        self.assert_unmodified()

    def test_invalid_digest_prevents_network(self):
        self.manifest.write_text("0bad  evtx_dump-v0.12.3-x86_64-unknown-linux-gnu\n")
        result = self.run_installer()
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.log.exists())
        self.assert_unmodified()

    def test_unsupported_architecture_prevents_network(self):
        result = self.run_installer(arch="armv7")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Unsupported", result.stderr)
        self.assertFalse(self.log.exists())
        self.assert_unmodified()

    def test_pinned_manifest_matches_official_release(self):
        entries = {
            filename: digest
            for digest, filename in (
                line.split() for line in CHECKSUMS.read_text().splitlines()
            )
        }
        self.assertEqual(
            entries,
            {
                f"evtx_dump-v0.12.3-{arch}-unknown-linux-gnu": digest
                for arch, digest in RELEASE_HASHES.items()
            },
        )

    def test_dockerfile_stages_manifest_and_uses_verified_installer(self):
        source = DOCKERFILE.read_text()
        self.assertIn("shared/bin/install-verified-evtx.sh", source)
        self.assertIn("Dockerfiles/checksums/evtx-v0.12.3.sha256", source)
        self.assertIn('/usr/local/bin/install-verified-evtx.sh "$EVTXARCH"', source)
        self.assertNotIn("curl -fsSL -o /usr/local/bin/evtx", source)
        self.assertLess(
            source.index("ADD --chmod=755 shared/bin/install-verified-evtx.sh"),
            source.index("RUN export EVTXARCH="),
        )


if __name__ == "__main__":
    unittest.main()
