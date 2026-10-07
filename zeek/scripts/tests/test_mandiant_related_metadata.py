"""Regression coverage for Mandiant campaign/report enrichment in Zeek TSV."""

import importlib.util
import io
import sys
import types
import unittest
from pathlib import Path
from unittest.mock import patch

import mandiant_threatintel


def load_module():
    """Load the real mapper and printer with only image-specific utils stubbed."""
    utils = types.ModuleType("malcolm_utils")
    utils.base64_decode_if_prefixed = lambda value: value
    utils.get_iterable = lambda value: value
    utils.LoadStrIfJson = lambda value, **kwargs: value
    utils.LoadFileIfJson = lambda value, **kwargs: value
    utils.isprivateip = lambda value: False

    path = Path(__file__).resolve().parents[1] / "zeek_threat_feed_utils.py"
    spec = importlib.util.spec_from_file_location("zeek_threat_feed_utils_metadata_test", path)
    module = importlib.util.module_from_spec(spec)
    with patch.dict(sys.modules, {"malcolm_utils": utils}):
        spec.loader.exec_module(module)
    return module


class NoNetworkClient:
    class Indicators:
        @staticmethod
        def get_raw(*args, **kwargs):
            raise AssertionError("Unexpected lazy Mandiant network request")


class TestMandiantRelatedMetadata(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module = load_module()

    def _indicator(self, indicator_class=mandiant_threatintel.FQDNIndicator, **extra):
        response = {
            "id": "fqdn--synthetic-test",
            "value": "example.test",
            "mscore": 75,
            "sources": [],
            "misp": {},
            "first_seen": "2026-01-01T00:00:00Z",
            "last_seen": "2026-01-02T00:00:00Z",
        }
        response.update(extra)
        return indicator_class.from_json_response(response, NoNetworkClient())

    def test_escaped_sorted_deduplicated_campaigns_and_reports(self):
        indicator = self._indicator(
            campaigns=[
                {"name": "UNC,42", "id": "camp-1"},
                {"name": "UNC7"},
                {"name": "UNC,42"},
                {"id": "camp-only-id"},
                {},
            ],
            reports=[
                {"report_id": "23-123"},
                {"id": "23-abc", "title": "Analysis"},
                {"report_id": "23-123"},
                {"title": "Report, Other"},
                "",
            ],
        )
        record = self.module.map_mandiant_indicator_to_zeek(
            indicator, skip_attr_map={"campaigns": False, "reports": False}
        )[0]
        self.assertEqual(record["meta.campaigns"], r"UNC\x2c42\x7cUNC7\x7ccamp-only-id")
        self.assertEqual(record["meta.reports"], r"23-123\x7c23-abc\x7cReport\x2c Other")

    def test_configured_exclusions_are_respected(self):
        indicator = self._indicator(
            campaigns=[{"name": "UNC1234"}], reports=[{"report_id": "24-001"}]
        )
        for skips, expected in (
            ({"campaigns": True, "reports": True}, (False, False)),
            ({"campaigns": False, "reports": True}, (True, False)),
            ({"campaigns": True, "reports": False}, (False, True)),
        ):
            with self.subTest(skips=skips):
                record = self.module.map_mandiant_indicator_to_zeek(
                    indicator, skip_attr_map=skips
                )[0]
                self.assertEqual("meta.campaigns" in record, expected[0])
                self.assertEqual("meta.reports" in record, expected[1])

    def test_absent_properties_do_not_trigger_lazy_api_fetch(self):
        indicator = self._indicator()
        records = self.module.map_mandiant_indicator_to_zeek(indicator)
        self.assertEqual(len(records), 1)
        self.assertNotIn("meta.campaigns", records[0])
        self.assertNotIn("meta.reports", records[0])

    def test_md5_hash_expansion_preserves_related_metadata(self):
        indicator = self._indicator(
            indicator_class=mandiant_threatintel.MD5Indicator,
            id="md5--test",
            value="ab" * 16,
            associated_hashes=[
                {"value": "cd" * 20, "id": "sha1--test"},
                {"value": "ef" * 32, "id": "sha256--test"},
            ],
            campaigns=[{"name": "UNC9000"}],
            reports=[{"report_id": "25-0007"}],
        )
        rows = self.module.map_mandiant_indicator_to_zeek(indicator)
        self.assertEqual(len(rows), 2)
        for row in rows:
            self.assertEqual(row["meta.campaigns"], "UNC9000")
            self.assertEqual(row["meta.reports"], "25-0007")

    def test_extended_printer_emits_both_columns(self):
        indicator = self._indicator(
            campaigns=[{"name": "UNC42"}], reports=[{"report_id": "24-5678"}]
        )
        output = io.StringIO()
        printer = self.module.FeedParserZeekPrinter(
            extended=True, notice=False, cif=False, file=output
        )
        self.assertTrue(printer.ProcessMandiant(indicator))
        header, data = output.getvalue().splitlines()
        fields = header.split("\t")[1:]
        row = dict(zip(fields, data.split("\t"), strict=True))
        self.assertEqual(row["meta.campaigns"], "UNC42")
        self.assertEqual(row["meta.reports"], "24-5678")


if __name__ == "__main__":
    unittest.main()
