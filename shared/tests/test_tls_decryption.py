#!/usr/bin/env python3
# Copyright (c) 2026 Battelle Energy Alliance, LLC. All rights reserved.
"""Tests for Zeek's optional session-key-file decryption configuration."""

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

try:
    import yaml
except ImportError:
    yaml = None


ROOT = Path(__file__).resolve().parents[2]


class ZeekTlsDecryptionConfigTest(unittest.TestCase):

    def test_opt_in_default_and_local_site_include(self):
        env = (ROOT / "config" / "zeek.env.example").read_text()
        self.assertIn("ZEEK_TLS_KEYLOG_FILE=\n", env)
        self.assertIn("@load ./tls-decryption",
                      (ROOT / "zeek/config/local.zeek").read_text())
        policy = (ROOT / "zeek/config/tls-decryption.zeek").read_text()
        self.assertIn('getenv("ZEEK_TLS_KEYLOG_FILE") != ""', policy)
        self.assertIn("@load protocols/ssl/decryption", policy)
        self.assertIn("redef SSL::keylog_file", policy)

    def test_session_keys_excluded_from_source_control(self):
        ignore = (ROOT / ".gitignore").read_text()
        self.assertIn("/zeek/tls-secrets/", ignore)
        self.assertFalse((ROOT / "zeek/tls-secrets/sslkeylog.txt").exists())
        self.assertNotIn("CLIENT_RANDOM", (
            ROOT / "config/zeek.env.example").read_text())

    @unittest.skipIf(yaml is None, "PyYAML not installed")
    def test_compose_mounts_are_read_only_and_existing_file_only(self):
        data = yaml.safe_load(
            (ROOT / "docker-compose-zeek-tls.yml.example").read_text())
        for name in ("zeek", "zeek-live"):
            with self.subTest(service=name):
                mounts = data["services"][name]["volumes"]
                self.assertEqual(len(mounts), 1)
                mount = mounts[0]
                self.assertEqual(mount["type"], "bind")
                self.assertEqual(
                    mount["source"], "./zeek/tls-secrets/sslkeylog.txt")
                self.assertEqual(
                    mount["target"], "/run/secrets/zeek-sslkeys.txt")
                self.assertTrue(mount["read_only"])
                self.assertIs(mount["bind"]["create_host_path"], False)

    @unittest.skipUnless(shutil.which("zeek"), "Zeek not installed")
    def test_zeek_script_compiles_with_and_without_session_keys(self):
        script = ROOT / "zeek/config/tls-decryption.zeek"
        with tempfile.TemporaryDirectory() as working_directory:
            file = Path(working_directory) / "sslkeylog.txt"
            file.write_text("# Empty synthetic test key log\n")
            for path in ("", str(file)):
                with self.subTest(enabled=bool(path)):
                    env = dict(os.environ, ZEEK_TLS_KEYLOG_FILE=path)
                    result = subprocess.run(
                        ["zeek", "-a", str(script)],
                        env=env, cwd=working_directory,
                        capture_output=True, text=True, timeout=20)
                    self.assertEqual(
                        result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
