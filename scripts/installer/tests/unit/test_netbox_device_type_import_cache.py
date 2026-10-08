"""Regression tests for NetBox's persistent device library import marker."""

import importlib.util
import tempfile
import unittest
from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

ROOT = Path(__file__).resolve().parents[4]
INIT = ROOT / "netbox/control-scripts/netbox_init.py"
CACHE = ROOT / "netbox/control-scripts/device_type_import_cache.py"
spec = importlib.util.spec_from_file_location("device_type_import_cache", CACHE)
cache = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cache)


def import_function(process):
    return lambda args, python, nb: cache.import_device_type_library(
        args, python, nb, process, lambda _: nullcontext()
    )


class Tags:
    def __init__(self):
        self.markers = set()
        self.created = []

    def get(self, *, slug):
        return SimpleNamespace(slug=slug) if slug in self.markers else None

    def create(self, data):
        self.created.append(data)
        self.markers.add(data["slug"])


class DeviceLibraryCacheTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.path = Path(temp.name)
        (self.path / "repo/device-types/cisco").mkdir(parents=True)
        (self.path / "repo/module-types/arista").mkdir(parents=True)
        (self.path / "repo/device-types/cisco/model.yaml").write_text("model: 1\n")
        (self.path / "repo/module-types/arista/module.yml").write_text("module: 1\n")
        self.tags = Tags()
        self.nb = SimpleNamespace(extras=SimpleNamespace(tags=self.tags))
        self.args = SimpleNamespace(
            library_dir=str(self.path),
            library_vendors="",
            force_library_import=False,
            netbox_url="http://netbox.invalid",
            netbox_token="dummy",
        )

    def test_fingerprint_detects_changes_and_vendor_scope(self):
        first = cache.library_fingerprint(self.path)
        self.assertEqual(first, cache.library_fingerprint(self.path))
        self.assertTrue(first.startswith(cache.MARKER_PREFIX))
        self.assertNotEqual(first, cache.library_fingerprint(self.path, ("cisco",)))
        (self.path / "repo/device-types/cisco/model.yaml").write_text("model: 2\n")
        self.assertNotEqual(first, cache.library_fingerprint(self.path))

    def test_missing_or_empty_library_is_not_cached(self):
        self.assertIsNone(cache.library_fingerprint(self.path / "missing"))
        with tempfile.TemporaryDirectory() as empty:
            (Path(empty) / "repo").mkdir()
            self.assertIsNone(cache.library_fingerprint(empty))

    def test_vendor_normalization(self):
        self.assertEqual(cache.selected_vendors(" Cisco,Arista,cisco "), ("arista", "cisco"))
        self.assertEqual(cache.selected_vendors(""), ())

    def test_first_import_creates_marker_and_second_is_skipped(self):
        process = Mock(return_value=(0, ["3 device types created"]))
        run = import_function(process)
        self.assertTrue(run(self.args, "/venv/python", self.nb))
        self.assertTrue(run(self.args, "/venv/python", self.nb))
        process.assert_called_once()
        self.assertEqual(len(self.tags.created), 1)

    def test_changed_library_causes_another_import(self):
        process = Mock(return_value=(0, ["3 device types created"]))
        run = import_function(process)
        self.assertTrue(run(self.args, "/venv/python", self.nb))
        (self.path / "repo/device-types/cisco/model.yaml").write_text("model: 3\n")
        self.assertTrue(run(self.args, "/venv/python", self.nb))
        self.assertEqual(process.call_count, 2)
        self.assertEqual(len(self.tags.created), 2)

    def test_vendor_filter_is_passed_to_upstream(self):
        self.args.library_vendors = "Cisco,arista,cisco"
        process = Mock(return_value=(0, ["3 device types created"]))
        self.assertTrue(import_function(process)(self.args, "/venv/python", self.nb))
        self.assertEqual(process.call_args.args[0][-3:], ["--vendors", "arista", "cisco"])

    def test_force_import_bypasses_existing_marker(self):
        process = Mock(return_value=(0, ["3 device types created"]))
        run = import_function(process)
        self.assertTrue(run(self.args, "/venv/python", self.nb))
        self.args.force_library_import = True
        self.assertTrue(run(self.args, "/venv/python", self.nb))
        self.assertEqual(process.call_count, 2)

    def test_partial_and_failed_imports_are_never_marked_complete(self):
        cases = [
            (1, ["failed"]),
            (0, ["2 device types FAILED to create or update"]),
            (0, ["1 device types partially updated"]),
            (0, ["1 modules failed to create or update"]),
            (0, ["1 rack types failed"]),
            (0, []),
        ]
        for status, lines in cases:
            with self.subTest(status=status, lines=lines):
                self.tags = Tags()
                self.nb.extras.tags = self.tags
                run = import_function(Mock(return_value=(status, lines)))
                self.assertFalse(run(self.args, "/venv/python", self.nb))
                self.assertFalse(self.tags.markers)

    def test_marker_lookup_failure_falls_back_to_import(self):
        self.nb.extras.tags.get = Mock(side_effect=RuntimeError("unavailable"))
        process = Mock(return_value=(0, ["3 device types created"]))
        self.assertTrue(import_function(process)(self.args, "/venv/python", self.nb))
        process.assert_called_once()

    def test_marker_write_failure_keeps_import_retryable(self):
        self.nb.extras.tags.create = Mock(side_effect=RuntimeError("not allowed"))
        process = Mock(return_value=(0, ["3 device types created"]))
        run = import_function(process)
        self.assertTrue(run(self.args, "/venv/python", self.nb))
        self.assertTrue(run(self.args, "/venv/python", self.nb))
        self.assertEqual(process.call_count, 2)


if __name__ == "__main__":
    unittest.main()
