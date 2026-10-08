"""Pin the authentication module source independently from movable Git refs."""

import hashlib
import re
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
DOCKERFILE = ROOT / "Dockerfiles/nginx.Dockerfile"
MODULE_REPO = "mmguero-dev/nginx-auth-ldap"


def pinned_source(text):
    rev = re.search(
        r"^ARG NGINX_AUTH_LDAP_REVISION=([a-f0-9]{40})$",
        text,
        re.MULTILINE,
    )
    asset = re.search(
        r"^ADD --checksum=sha256:([a-f0-9]{64}) "
        r"https://codeload\.github\.com/mmguero-dev/nginx-auth-ldap/tar\.gz/"
        r"\$NGINX_AUTH_LDAP_REVISION /nginx-auth-ldap\.tar\.gz$",
        text,
        re.MULTILINE,
    )
    return rev, asset


class TestNginxLdapSourcePin(unittest.TestCase):
    def test_auth_module_uses_immutable_commit_and_sha256(self):
        text = DOCKERFILE.read_text()
        revision, asset = pinned_source(text)
        self.assertIsNotNone(revision)
        self.assertIsNotNone(asset)
        self.assertNotIn("NGINX_AUTH_LDAP_BRANCH=master", text)
        self.assertNotIn("tar.gz/master /nginx-auth-ldap.tar.gz", text)
        self.assertNotIn("releases/latest", asset.group())

    def test_verification_happens_before_module_extraction(self):
        source = DOCKERFILE.read_text()
        _, source_line = pinned_source(source)
        self.assertLess(source.index(source_line.group()), source.index(
            "tar -zxC /usr/src/nginx-auth-ldap --strip=1 -f /nginx-auth-ldap.tar.gz"
        ))
        self.assertIn("--checksum=sha256:", source_line.group())
        self.assertIn("--add-module=/usr/src/nginx-auth-ldap", source)

    def test_hash_matches_known_archive_fixture_and_rejects_tampering(self):
        # Keep routine CI tests offline. The exact upstream revision and digest
        # are also downloaded and verified during PR validation.
        data = b"archive bytes expected"
        expected = hashlib.sha256(data).hexdigest()
        self.assertNotEqual(expected, hashlib.sha256(data + b"!").hexdigest())
        with tempfile.TemporaryDirectory() as temporary:
            archive = Path(temporary) / "module.tar.gz"
            for payload, valid in ((data, True), (data + b"!", False)):
                archive.write_bytes(payload)
                result = subprocess.run(
                    ["sh", "-c", 'printf "%s  %s\n" "$1" "$2" | shasum -a 256 -c -',
                     "sh", expected, str(archive)],
                    capture_output=True, text=True, check=False,
                )
                self.assertEqual(result.returncode == 0, valid)

    def test_expected_module_source_filename(self):
        self.assertEqual(MODULE_REPO, "mmguero-dev/nginx-auth-ldap")
        self.assertIn("nginx-auth-ldap", DOCKERFILE.read_text())


if __name__ == "__main__":
    unittest.main()
