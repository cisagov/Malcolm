"""Tests for fail-closed documentation-build yq fallback downloads."""

import hashlib
import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
INSTALLER = ROOT / "scripts/install-verified-docs-yq.sh"
DOCS_BUILD = ROOT / "scripts/documentation_build.sh"
CHECKSUMS = ROOT / "scripts/checksums/yq-v4.54.1.sha256"
DIGESTS = {
    "yq_darwin_amd64": "3a812fce205a4d67014fb71b7fa297092210e580df3d8f52dddc2cf3a599c22b",
    "yq_darwin_arm64": "fee511a181bd8b3e6b7da98842b41973bfac8cd3bcd341ed29a584620b5b2844",
    "yq_linux_amd64": "8e34fc298390875de416e6a4afcb8cabeceb25d9aa8506c1a2f9353cf702ea5f",
    "yq_linux_arm64": "189088da0c6429ec5178dfaab1a114805f6cab0b61b165ab236efedf1d57a71b",
}


class TestVerifiedDocsYq(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.binary = self.root / "yq"
        self.binary.write_bytes(b"previously installed executable")
        self.source = self.root / "download"
        self.manifest = self.root / "manifest.sha256"
        self.log = self.root / "curl.log"
        self.bin = self.root / "bin"
        self.bin.mkdir()
        curl = self.bin / "curl"
        curl.write_text(
            "#!/bin/sh\n"
            "set -eu\n"
            'printf "%s\\n" "$*" >> "$MOCK_CURL_LOG"\n'
            'if [ "$MOCK_CURL_FAIL" = "1" ]; then exit 22; fi\n'
            'while [ "$#" -gt 0 ]; do\n'
            '  if [ "$1" = "-o" ]; then shift; output="$1"; fi\n'
            "  shift\n"
            "done\n"
            'cp "$MOCK_DOWNLOAD_SOURCE" "$output"\n',
            encoding="utf-8",
        )
        curl.chmod(0o755)
        uname = self.bin / "uname"
        uname.write_text(
            "#!/bin/sh\n"
            'case "$1" in\n'
            '  -s) printf "%s\\n" "$MOCK_OS" ;;\n'
            '  -m) printf "%s\\n" "$MOCK_ARCH" ;;\n'
            "esac\n",
            encoding="utf-8",
        )
        uname.chmod(0o755)

    def run_installer(
        self,
        system="Linux",
        arch="x86_64",
        *,
        body=b"fixture yq executable",
        digest=None,
        curl_error=False,
        absent_manifest=False,
    ):
        self.source.write_bytes(body)
        asset = (
            "yq_"
            + system.lower()
            + "_"
            + ("amd64" if arch in ("x86_64", "amd64") else "arm64")
        )
        sha = hashlib.sha256(body).hexdigest() if digest is None else digest
        if not self.manifest.exists() and not absent_manifest:
            self.manifest.write_text(f"{sha}  {asset}\n", encoding="utf-8")
        env = os.environ.copy()
        env.update(
            PATH=str(self.bin) + os.pathsep + env["PATH"],
            MOCK_OS=system,
            MOCK_ARCH=arch,
            MOCK_CURL_LOG=str(self.log),
            MOCK_CURL_FAIL="1" if curl_error else "0",
            MOCK_DOWNLOAD_SOURCE=str(self.source),
        )
        result = subprocess.run(
            [
                "sh",
                str(INSTALLER),
                str(self.binary),
                str(self.manifest),
                "https://example.invalid/yq/v4.54.1",
            ],
            env=env,
            text=True,
            capture_output=True,
            timeout=15,
            check=False,
        )
        return result

    def assert_kept_original(self):
        self.assertEqual(self.binary.read_bytes(), b"previously installed executable")
        self.assertEqual(list(self.root.glob("yq.tmp.*")), [])

    def test_both_linux_architectures(self):
        for arch, asset in (
            ("x86_64", "yq_linux_amd64"),
            ("aarch64", "yq_linux_arm64"),
        ):
            with self.subTest(arch=arch):
                if self.manifest.exists():
                    self.manifest.unlink()
                result = self.run_installer(arch=arch)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn(asset, result.stderr)
                self.assertIn(asset, self.log.read_text())
                self.assertEqual(self.binary.read_bytes(), b"fixture yq executable")
                self.assertTrue(self.binary.stat().st_mode & stat.S_IXUSR)
                self.binary.write_bytes(b"previously installed executable")

    def test_darwin_intel_and_apple_silicon(self):
        for arch, asset in (
            ("x86_64", "yq_darwin_amd64"),
            ("arm64", "yq_darwin_arm64"),
        ):
            with self.subTest(arch=arch):
                if self.manifest.exists():
                    self.manifest.unlink()
                result = self.run_installer(system="Darwin", arch=arch)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn(asset, self.log.read_text())
                self.binary.write_bytes(b"previously installed executable")

    def test_bad_digest_cannot_overwrite_existing_binary(self):
        result = self.run_installer(digest="a" * 64)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("SHA256 verification failed", result.stderr)
        self.assert_kept_original()

    def test_network_failure_cannot_replace_existing_binary(self):
        result = self.run_installer(curl_error=True)
        self.assertNotEqual(result.returncode, 0)
        self.assert_kept_original()

    def test_unknown_platform_is_rejected_without_fetching(self):
        result = self.run_installer(system="FreeBSD")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Unsupported yq platform", result.stderr)
        self.assertFalse(self.log.exists())
        self.assert_kept_original()

    def test_unknown_cpu_is_rejected_without_fetching(self):
        result = self.run_installer(arch="s390x")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Unsupported yq CPU architecture", result.stderr)
        self.assertFalse(self.log.exists())
        self.assert_kept_original()

    def test_missing_manifest_is_rejected_before_fetch(self):
        result = self.run_installer(absent_manifest=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Missing yq checksum manifest", result.stderr)
        self.assertFalse(self.log.exists())
        self.assert_kept_original()

    def test_duplicate_checksums_are_rejected(self):
        line = (
            f"{hashlib.sha256(b'fixture yq executable').hexdigest()}  yq_linux_amd64\n"
        )
        self.manifest.write_text(line + line)
        result = self.run_installer()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Duplicate", result.stderr)
        self.assertFalse(self.log.exists())
        self.assert_kept_original()

    def test_short_digest_is_rejected(self):
        self.manifest.write_text("abc  yq_linux_amd64\n")
        result = self.run_installer()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Duplicate or malformed", result.stderr)
        self.assertFalse(self.log.exists())
        self.assert_kept_original()

    def test_bad_characters_in_digest_are_rejected(self):
        self.manifest.write_text("z" * 64 + "  yq_linux_amd64\n")
        result = self.run_installer()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Invalid or absent", result.stderr)
        self.assertFalse(self.log.exists())
        self.assert_kept_original()

    def test_release_manifest_pins_all_four_platforms(self):
        self.assertEqual(
            {
                name: digest
                for digest, name in (
                    line.split() for line in CHECKSUMS.read_text().splitlines()
                )
            },
            DIGESTS,
        )

    def test_docs_builder_only_fetches_when_config_overrides_requested(self):
        source = DOCS_BUILD.read_text()
        self.assertIn("install-verified-docs-yq.sh", source)
        self.assertIn(
            'if [[ -n "$REPOSITORY_NAME" || -n "$DEFAULT_BRANCH" '
            '|| -n "$SITEMAP_URL" || -n "$MALCOLM_VERSION" ]]; then',
            source,
        )
        self.assertNotIn("/releases/latest/download/", source)
        self.assertNotIn('curl -sSL -o "$YQ"', source)
        self.assertIn("command -v yq", source)


if __name__ == "__main__":
    unittest.main()
