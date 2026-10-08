"""Verify the NetBox Docker build downloads immutable, checked sources."""

import hashlib
import re
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
SOURCE = ROOT / "Dockerfiles/netbox.Dockerfile"


def pinned_arg(content, name):
    match = re.search("^ARG " + re.escape(name) + "=([a-f0-9]+)$", content, re.MULTILINE)
    if not match:
        raise AssertionError(f"Missing build arg {name}")
    return match.group(1)


class TestNetboxSourcePins(unittest.TestCase):
    def test_both_sources_use_full_commit_sha_and_sha256(self):
        content = SOURCE.read_text(encoding="utf-8")
        dollar = chr(36)
        for prefix in ("NETBOX_DEVICETYPE_LIBRARY_IMPORT", "NETBOX_DEVICETYPE_LIBRARY"):
            with self.subTest(prefix=prefix):
                self.assertRegex(pinned_arg(content, prefix + "_COMMIT"), r"^[0-9a-f]{40}$")
                self.assertRegex(pinned_arg(content, prefix + "_SHA256"), r"^[0-9a-f]{64}$")
                self.assertIn("tar.gz/" + dollar + "{" + prefix + "_COMMIT}", content)
        self.assertNotIn("tar.gz/main", content)
        self.assertNotIn("tar.gz/master", content)

    def test_download_is_verified_before_any_tar_extraction(self):
        content = SOURCE.read_text(encoding="utf-8")
        dollar = chr(36)
        for prefix, filename in (
            ("NETBOX_DEVICETYPE_LIBRARY_IMPORT", "netbox-dt-import.tar.gz"),
            ("NETBOX_DEVICETYPE_LIBRARY", "netbox-dt-library.tar.gz"),
        ):
            with self.subTest(prefix=prefix):
                download = content.index(
                    "curl -fLsS --retry 3 -o /tmp/" + filename
                )
                hashref = content.index(dollar + "{" + prefix + "_SHA256}")
                check = content.index("sha256sum -c -", hashref)
                unpack = content.index("tar xzf /tmp/" + filename)
                self.assertLess(download, hashref)
                self.assertLess(hashref, check)
                self.assertLess(check, unpack)

    def test_checksum_is_rejected_after_tampering(self):
        with tempfile.TemporaryDirectory() as path:
            archive = Path(path) / "archive.tar.gz"
            archive.write_bytes(b"trusted")
            digest = hashlib.sha256(archive.read_bytes()).hexdigest()
            for content, allowed in ((b"trusted", True), (b"tampered", False)):
                archive.write_bytes(content)
                outcome = subprocess.run(
                    ["sh", "-c", 'printf "%s  %s\n" "$1" "$2" | sha256sum -c -',
                     "sh", digest, str(archive)],
                    capture_output=True, text=True, check=False,
                )
                self.assertEqual(outcome.returncode == 0, allowed)

    def test_expected_upstream_repositories(self):
        content = SOURCE.read_text(encoding="utf-8")
        self.assertIn("codeload.github.com/mmguero-dev/Device-Type-Library-Import", content)
        self.assertIn("codeload.github.com/netbox-community/devicetype-library", content)


if __name__ == "__main__":
    unittest.main()
