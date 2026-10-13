"""Regression tests for NetBox's persistent device library import marker."""

import tempfile
import unittest
from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import device_type_import_cache as cache


def import_function(process):
    return lambda args, python, nb: cache.import_device_type_library(
        args, python, nb, process, lambda _: nullcontext()
    )


class TagRecord:
    def __init__(self, tags, slug):
        self.tags = tags
        self.slug = slug

    def delete(self):
        if self.tags.fail_delete == self.slug:
            raise RuntimeError("Deletion unavailable")
        self.tags.markers.remove(self.slug)
        return True


class Tags:
    def __init__(self):
        self.markers = set()
        self.created = []
        self.fail_delete = None

    def get(self, *, slug):
        return SimpleNamespace(slug=slug) if slug in self.markers else None

    def create(self, data):
        # NetBox rejects a tag whose slug already exists
        if data["slug"] in self.markers:
            raise RuntimeError(f"tag with slug {data['slug']} already exists")
        self.created.append(data)
        self.markers.add(data["slug"])

    def filter(self, **kwargs):
        assert kwargs == {"q": cache.MARKER_PREFIX}
        return [TagRecord(self, slug) for slug in sorted(self.markers)]


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
        self.assertEqual(
            cache.selected_vendors(" Cisco,Arista,cisco "), ("arista", "cisco")
        )
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

    def test_equivalent_vendor_spellings_have_one_fingerprint(self):
        spelled = cache.selected_vendors("Hewlett Packard Enterprise,cisco")
        slugged = cache.selected_vendors("hewlett-packard-enterprise,CISCO")
        self.assertEqual(spelled, slugged)
        self.assertEqual(spelled, ("cisco", "hewlett-packard-enterprise"))
        self.assertEqual(
            cache.library_fingerprint(self.path, spelled),
            cache.library_fingerprint(self.path, slugged),
        )

    def test_old_marker_tags_are_removed_after_successful_import(self):
        old = cache.MARKER_PREFIX + "old-library"
        unrelated = "operator-maintained"
        self.tags.markers.update({old, unrelated})
        process = Mock(return_value=(0, ["3 device types created"]))
        self.assertTrue(import_function(process)(self.args, "/venv/python", self.nb))
        marker = cache.library_fingerprint(self.path)
        self.assertEqual(self.tags.markers, {marker, unrelated})
        process.assert_called_once()

    def test_marker_cleanup_error_is_nonfatal(self):
        old = cache.MARKER_PREFIX + "old-library"
        self.tags.markers.add(old)
        self.tags.fail_delete = old
        process = Mock(return_value=(0, ["3 device types created"]))
        run = import_function(process)
        with self.assertLogs(cache.logger, level="WARNING") as warnings:
            self.assertTrue(run(self.args, "/venv/python", self.nb))
        self.assertTrue(any("Could not remove" in x for x in warnings.output))
        self.assertIn(old, self.tags.markers)
        self.assertTrue(run(self.args, "/venv/python", self.nb))
        process.assert_called_once()

    def test_marker_lookup_after_creation_can_fail_without_losing_success(self):
        process = Mock(return_value=(0, ["3 device types created"]))
        self.tags.filter = Mock(side_effect=RuntimeError("Search unavailable"))
        with self.assertLogs(cache.logger, level="WARNING") as warnings:
            self.assertTrue(
                import_function(process)(self.args, "/venv/python", self.nb)
            )
        self.assertTrue(any("Could not enumerate" in x for x in warnings.output))
        self.assertIn(cache.library_fingerprint(self.path), self.tags.markers)

    def test_vendor_filter_is_passed_to_upstream(self):
        self.args.library_vendors = "Cisco,arista,cisco"
        process = Mock(return_value=(0, ["3 device types created"]))
        self.assertTrue(import_function(process)(self.args, "/venv/python", self.nb))
        self.assertEqual(
            process.call_args.args[0][-3:], ["--vendors", "arista", "cisco"]
        )

    def test_force_import_bypasses_existing_marker(self):
        process = Mock(return_value=(0, ["3 device types created"]))
        run = import_function(process)
        self.assertTrue(run(self.args, "/venv/python", self.nb))
        self.args.force_library_import = True
        self.assertTrue(run(self.args, "/venv/python", self.nb))
        self.assertEqual(process.call_count, 2)

    def test_force_import_with_existing_marker_keeps_it_and_cleans_up(self):
        # Forcing a reimport of an unchanged library means the marker already
        # exists; recording completion must not try to create it again (which
        # NetBox rejects), and stale markers must still be cleaned up.
        marker = cache.library_fingerprint(self.path)
        old = cache.MARKER_PREFIX + "old-library"
        self.tags.markers.update({marker, old})
        self.args.force_library_import = True
        process = Mock(return_value=(0, ["3 device types created"]))
        with self.assertNoLogs(cache.logger, level="WARNING"):
            self.assertTrue(import_function(process)(self.args, "/venv/python", self.nb))
        process.assert_called_once()
        self.assertEqual(self.tags.created, [])
        self.assertEqual(self.tags.markers, {marker})

    def test_record_completion_is_idempotent(self):
        marker = cache.library_fingerprint(self.path)
        cache.record_completion(self.nb, marker)
        cache.record_completion(self.nb, marker)
        self.assertEqual(len(self.tags.created), 1)
        self.assertEqual(self.tags.markers, {marker})

    def test_partial_and_failed_imports_are_never_marked_complete(self):
        cases = [
            (1, ["failed"]),
            (0, ["2 device types FAILED to create or update (see error log above)"]),
            (0, ["1 device types partially updated"]),
            (0, ["1 modules failed to create or update"]),
            (0, ["1 modules partially updated"]),
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
