"""Regression tests for Filebeat registry parsing in the log cleanup script."""

import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import time
import types
import unittest
from contextlib import ExitStack
from unittest.mock import patch


def _load_cleanup_script():
    # The cleanup script lives in an image-specific folder and has a hyphenated name.
    # Stub only its container-only imports to run these tests without a Docker image.
    magic = types.ModuleType("magic")
    magic.from_file = lambda path, mime=False: "text/plain" if mime else "ASCII text"

    utils = types.ModuleType("malcolm_utils")

    def load_file_if_json(handle, attemptLines=False):
        try:
            return json.load(handle)
        except ValueError:
            if not attemptLines:
                return None
            handle.seek(0)
            records = []
            for line in handle:
                try:
                    records.append(json.loads(line))
                except ValueError:
                    pass
            return records or None

    def deep_get(record, keys):
        for key in keys:
            if record is None:
                return None
            record = record.get(key)
        return record

    utils.LoadFileIfJson = load_file_if_json
    utils.deep_get = deep_get
    utils.set_logging = lambda *args, **kwargs: None
    utils.get_verbosity_env_var_count = lambda *args, **kwargs: 0

    script_path = Path(__file__).resolve().parents[4] / "filebeat/scripts/clean-processed-folder.py"
    spec = importlib.util.spec_from_file_location("malcolm_filebeat_cleanup_under_test", script_path)
    module = importlib.util.module_from_spec(spec)
    with patch.dict(sys.modules, {"magic": magic, "malcolm_utils": utils}):
        spec.loader.exec_module(module)
    return module


class TestFilebeatRegistryCleanup(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cleanup = _load_cleanup_script()

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def _write_registry(self, name, content):
        path = Path(self.tmp.name) / name
        path.write_text(content, encoding="utf-8")
        return str(path)

    @staticmethod
    def _record(device=7, inode=42):
        return {"v": {"FileStateOS": {"device": device, "inode": inode}}}

    def test_single_json_object_in_compact_and_pretty_formats(self):
        for indent in (None, 2):
            with self.subTest(indent=indent):
                path = self._write_registry("registry.json", json.dumps(self._record(), indent=indent))
                self.assertEqual(self.cleanup.load_filebeat_registries([path]), [(7, 42)])

    def test_single_json_object_ending_with_newline(self):
        path = self._write_registry("registry.json", json.dumps(self._record()) + "\n")
        self.assertEqual(self.cleanup.load_filebeat_registries([path]), [(7, 42)])

    def test_array_and_ndjson_formats_are_unchanged(self):
        entries = [self._record(1, 2), self._record(3, 4)]
        formats = [json.dumps(entries), "\n".join(json.dumps(entry) for entry in entries) + "\n"]
        for content in formats:
            with self.subTest(content=content):
                path = self._write_registry("registry.json", content)
                self.assertEqual(self.cleanup.load_filebeat_registries([path]), [(1, 2), (3, 4)])

    def test_missing_and_incomplete_records(self):
        path = self._write_registry("registry.json", json.dumps([
            self._record("5", "6"), {"v": {}}, {"v": {"FileStateOS": {"device": 7}}}
        ]))
        self.assertEqual(self.cleanup.load_filebeat_registries([path]), [(5, 6)])

    def test_multiple_registries_and_missing_file(self):
        one = self._write_registry("one.json", json.dumps(self._record(10, 20)))
        two = self._write_registry("two.json", json.dumps([self._record(30, 40)]))
        self.assertEqual(
            self.cleanup.load_filebeat_registries([one, "/missing/filebeat-registry.json", two]),
            [(10, 20), (30, 40)],
        )

    def test_prune_deletes_expired_unregistered_log_but_preserves_registered_log(self):
        processed = Path(self.tmp.name) / "processed"
        processed.mkdir()
        registered = processed / "registered.log"
        expired = processed / "expired.log"
        registered.write_text("registered\n", encoding="utf-8")
        expired.write_text("expired\n", encoding="utf-8")
        old = time.time() - 3600
        os.utime(registered, (old, old))
        os.utime(expired, (old, old))
        stat = registered.stat()
        registry = self._write_registry("single.json", json.dumps(self._record(stat.st_dev, stat.st_ino)))

        with ExitStack() as stack:
            for name, value in (
                ("filebeat_registry_filenames", [registry]),
                ("zeek_processed_dir", str(processed)),
                ("zeek_live_dir", str(processed / "not-present")),
                ("zeek_current_dir", str(processed / "not-present")),
                ("suricata_dir", str(processed / "not-present")),
                ("filescan_dir", str(processed / "not-present")),
                ("clean_log_seconds", 60),
                ("clean_zip_seconds", 120),
                ("now_time", time.time()),
            ):
                stack.enter_context(patch.object(self.cleanup, name, value))
            stack.enter_context(
                patch.object(self.cleanup.subprocess, "run", return_value=types.SimpleNamespace(returncode=1))
            )
            self.cleanup.prune_files()

        self.assertTrue(registered.exists())
        self.assertFalse(expired.exists())


if __name__ == "__main__":
    unittest.main()
