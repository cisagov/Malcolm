"""Regression tests for pinned yq binary downloads in runtime Dockerfiles."""

import hashlib
import os
import re
import subprocess
import tempfile
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[4]
SCRIPT = PROJECT_ROOT / "shared/bin/install-verified-yq.sh"
CHECKSUMS = PROJECT_ROOT / "Dockerfiles/checksums/yq-v4.54.1.sha256"

DOCKERFILES_WITH_YQ = (
    "dashboards-helper",
    "filebeat",
    "filescan",
    "logstash",
    "netbox",
    "opensearch",
    "strelka-backend",
    "strelka-frontend",
    "strelka-manager",
    "suricata",
)


class TestYqPinnedDownloads(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.target = self.root / "installed-yq"
        self.artifact = self.root / "downloaded-yq"
        self.manifest = self.root / "manifest.sha256"
        self.request = self.root / "requested-url.txt"

        curl_stub = self.bin / "curl"
        curl_stub.write_text(
            "#!/bin/sh\n"
            "set -eu\n"
            "while [ \"$#\" -gt 0 ]; do\n"
            "  case \"$1\" in\n"
            "    -o) shift; outfile=$1 ;;\n"
            "    https://*) url=$1 ;;\n"
            "  esac\n"
            "  shift\n"
            "done\n"
            "printf '%s\\n' \"$url\" > \"$MOCK_REQUESTED_URL\"\n"
            "cp \"$MOCK_ARTIFACT\" \"$outfile\"\n",
            encoding="utf-8",
        )
        uname_stub = self.bin / "uname"
        uname_stub.write_text("#!/bin/sh\nprintf '%s\\n' \"$MOCK_ARCH\"\n", encoding="utf-8")
        curl_stub.chmod(0o755)
        uname_stub.chmod(0o755)

    def _invoke(self, *, arch="x86_64", artifact=b"verified", manifest=None):
        self.artifact.write_bytes(artifact)
        if manifest is None:
            name = "amd64" if arch == "x86_64" else "arm64"
            digest = hashlib.sha256(artifact).hexdigest()
            manifest = f"{digest}  yq_linux_{name}\n"
        self.manifest.write_text(manifest, encoding="utf-8")

        env = os.environ.copy()
        env.update(
            {
                "PATH": f"{self.bin}:{os.environ['PATH']}",
                "MOCK_ARTIFACT": str(self.artifact),
                "MOCK_ARCH": arch,
                "MOCK_REQUESTED_URL": str(self.request),
            }
        )
        return subprocess.run(
            [
                "/bin/sh",
                str(SCRIPT),
                str(self.target),
                "https://example.invalid/yq/v4.54.1/yq_linux_",
                str(self.manifest),
            ],
            capture_output=True,
            text=True,
            env=env,
            check=False,
        )

    def test_verified_amd64_and_arm64_artifacts_are_installed(self):
        for arch, suffix in (("x86_64", "amd64"), ("aarch64", "arm64")):
            with self.subTest(arch=arch):
                self.request.unlink(missing_ok=True)
                result = self._invoke(arch=arch)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(self.target.read_bytes(), b"verified")
                self.assertTrue(self.target.stat().st_mode & 0o111)
                self.assertTrue(self.request.read_text().endswith(f"yq_linux_{suffix}\n"))

    def test_tampered_download_does_not_replace_previous_executable(self):
        self.target.write_bytes(b"previous-version")
        digest = hashlib.sha256(b"expected-untampered").hexdigest()
        result = self._invoke(manifest=f"{digest}  yq_linux_amd64\n")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.target.read_bytes(), b"previous-version")

    def test_unsupported_architecture_fails_before_download(self):
        result = self._invoke(arch="mips")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.target.exists())
        self.assertFalse(self.request.exists())

    def test_missing_checksum_fails_before_download(self):
        result = self._invoke(manifest="0" * 64 + "  yq_linux_arm64\n")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.target.exists())
        self.assertFalse(self.request.exists())

    def test_pinned_manifest_covers_two_linux_architectures(self):
        content = CHECKSUMS.read_text(encoding="utf-8").splitlines()
        records = {}
        for line in content:
            match = re.fullmatch(r"([0-9a-f]{64})  (yq_linux_(?:amd64|arm64))", line)
            self.assertIsNotNone(match)
            self.assertNotIn(match[2], records)
            records[match[2]] = match[1]
        self.assertEqual(set(records), {"yq_linux_amd64", "yq_linux_arm64"})

    def test_all_versioned_yq_runtime_downloads_are_verified(self):
        for name in DOCKERFILES_WITH_YQ:
            with self.subTest(dockerfile=name):
                content = (PROJECT_ROOT / "Dockerfiles" / f"{name}.Dockerfile").read_text()
                self.assertIn('ENV YQ_VERSION="4.54.1"', content)
                self.assertIn(
                    "COPY --chmod=755 shared/bin/install-verified-yq.sh /usr/local/bin/",
                    content,
                )
                self.assertIn(
                    "COPY --chmod=644 Dockerfiles/checksums/yq-v4.54.1.sha256",
                    content,
                )
                self.assertEqual(
                    content.count("/usr/local/bin/install-verified-yq.sh /usr"), 1
                )
                self.assertIn("|| exit 1", content)
                self.assertNotRegex(content, r"curl .*yq .*YQ_URL")


if __name__ == "__main__":
    unittest.main()
