"""Exercise the generic pinned binary installer without any network access."""

import hashlib
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[2] / "shared/bin/install-verified-binary.sh"


class TestVerifiedBinaryInstall(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.target = self.root / "installed-binary"
        self.artifact = self.root / "artifact-bytes"
        self.manifest = self.root / "manifest.sha256"
        self.request = self.root / "requested-url"
        curl_stub = self.bin / "curl"
        curl_stub.write_text(
            """#!/bin/sh
set -eu
if [ "${MOCK_CURL_FAIL:-0}" = "1" ]; then exit 22; fi
while [ "$#" -gt 0 ]; do
    case "$1" in
        -o) shift; outfile=$1 ;;
        https://*) url=$1 ;;
    esac
    shift
done
printf '%s\n' "$url" > "$MOCK_REQUESTED_URL"
cp "$MOCK_ARTIFACT" "$outfile"
""",
            encoding="utf-8",
        )
        uname_stub = self.bin / "uname"
        uname_stub.write_text(
            '#!/bin/sh\nprintf "%s\n" "$MOCK_ARCH"\n', encoding="utf-8"
        )
        curl_stub.chmod(0o755)
        uname_stub.chmod(0o755)

    def run_installer(
        self,
        *,
        arch="x86_64",
        payload=b"verified",
        manifest=None,
        artifact="yq_4.54.1_linux_{arch}",
        url="https://example.invalid/yq_linux_{arch}",
        fail_download=False,
    ):
        self.request.unlink(missing_ok=True)
        self.artifact.write_bytes(payload)
        if manifest is None:
            suffix = "amd64" if arch in ("x86_64", "amd64") else "arm64"
            digest = hashlib.sha256(payload).hexdigest()
            manifest = f"{digest}  yq_4.54.1_linux_{suffix}\n"
        self.manifest.write_text(manifest, encoding="utf-8")
        env = os.environ.copy()
        env.update(
            {
                "PATH": f"{self.bin}:{os.environ['PATH']}",
                "MOCK_ARTIFACT": str(self.artifact),
                "MOCK_ARCH": arch,
                "MOCK_REQUESTED_URL": str(self.request),
                "MOCK_CURL_FAIL": "1" if fail_download else "0",
                "VERIFIED_BINARY_MANIFEST": str(self.manifest),
            }
        )
        return subprocess.run(
            ["/bin/sh", str(SCRIPT), str(self.target), url, artifact],
            capture_output=True,
            text=True,
            check=False,
            env=env,
        )

    def test_linux_architectures_install_verified_bytes(self):
        for arch, suffix in (("x86_64", "amd64"), ("aarch64", "arm64")):
            with self.subTest(arch=arch):
                result = self.run_installer(arch=arch)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(self.target.read_bytes(), b"verified")
                self.assertTrue(self.target.stat().st_mode & 0o111)
                self.assertTrue(
                    self.request.read_text().endswith(f"yq_linux_{suffix}\n")
                )

    def test_unexpected_download_never_replaces_existing_binary(self):
        self.target.write_bytes(b"previous-version")
        expected = hashlib.sha256(b"not-the-downloaded-bytes").hexdigest()
        result = self.run_installer(manifest=f"{expected}  yq_4.54.1_linux_amd64\n")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.target.read_bytes(), b"previous-version")

    def test_missing_checksum_fails_before_download(self):
        result = self.run_installer(manifest="0" * 64 + "  yq_4.54.1_linux_arm64\n")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.request.exists())
        self.assertFalse(self.target.exists())

    def test_duplicate_checksum_keys_fail_closed(self):
        digest = hashlib.sha256(b"verified").hexdigest()
        manifest = f"{digest}  yq_4.54.1_linux_amd64\n" * 2
        result = self.run_installer(manifest=manifest)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.request.exists())

    def test_unsupported_architecture_fails_before_download(self):
        result = self.run_installer(arch="mips")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.request.exists())
        self.assertFalse(self.target.exists())

    def test_non_https_download_is_rejected(self):
        result = self.run_installer(url="http://example.invalid/yq_linux_{arch}")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.request.exists())

    def test_download_failure_preserves_previous_binary(self):
        self.target.write_bytes(b"previous-version")
        result = self.run_installer(fail_download=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.target.read_bytes(), b"previous-version")

    def test_generic_versioned_artifact_name(self):
        digest = hashlib.sha256(b"verified").hexdigest()
        result = self.run_installer(
            artifact="supercronic_0.2.49_linux_{arch}",
            url="https://example.invalid/supercronic-{arch}",
            manifest=f"{digest}  supercronic_0.2.49_linux_amd64\n",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            self.request.read_text().strip(),
            "https://example.invalid/supercronic-amd64",
        )
