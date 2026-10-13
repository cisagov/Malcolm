"""Regression tests for Mandiant campaign/report Zeek metadata."""

import io
import unittest

import mandiant_threatintel
import zeek_threat_feed_utils as intel


class NoNetworkClient:
    class Indicators:
        @staticmethod
        def get_raw(*args, **kwargs):
            raise AssertionError("Unexpected lazy Mandiant network request")


class TestMandiantRelatedMetadata(unittest.TestCase):
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
                {"name": "UNC|Ops"},
                {"id": "camp-only-id"},
                {},
            ],
            reports=[
                {"report_id": "23-123"},
                {"report_id": "24|002"},
                {"id": "23-abc", "title": "Analysis"},
                {"report_id": "23-123"},
                {"title": "Report, Other"},
                "",
            ],
        )
        record = intel.map_mandiant_indicator_to_zeek(
            indicator, skip_attr_map={"campaigns": False, "reports": False}
        )[0]
        self.assertEqual(record["meta.campaigns"], r"UNC\x2c42\x7cUNC7\x7cUNC\x7cOps")
        self.assertEqual(record["meta.reports"], r"23-123\x7c24\x7c002")

    def test_no_fallback_from_missing_fields_or_scalar_entries(self):
        indicator = self._indicator(
            campaigns=[{"id": "camp-only"}, "free-text", {}, None, {"name": "UNC100"}],
            reports=[{"id": "report-only", "title": "Other"}, "plain-text", {"report_id": "24-100"}],
            category=["threat"],
        )
        (record,) = intel.map_mandiant_indicator_to_zeek(indicator, skip_attr_map={"category": False})
        self.assertEqual(record["meta.campaigns"], "UNC100")
        self.assertEqual(record["meta.reports"], "24-100")
        self.assertEqual(record["meta.category"], "threat")

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
                record = intel.map_mandiant_indicator_to_zeek(
                    indicator, skip_attr_map=skips
                )[0]
                self.assertEqual("meta.campaigns" in record, expected[0])
                self.assertEqual("meta.reports" in record, expected[1])

    def test_absent_properties_do_not_trigger_lazy_api_fetch(self):
        indicator = self._indicator()
        records = intel.map_mandiant_indicator_to_zeek(indicator)
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
        rows = intel.map_mandiant_indicator_to_zeek(indicator)
        self.assertEqual(len(rows), 2)
        for row in rows:
            self.assertEqual(row["meta.campaigns"], "UNC9000")
            self.assertEqual(row["meta.reports"], "25-0007")

    def test_extended_printer_emits_both_columns(self):
        indicator = self._indicator(
            campaigns=[{"name": "UNC42"}], reports=[{"report_id": "24-5678"}]
        )
        output = io.StringIO()
        printer = intel.FeedParserZeekPrinter(
            extended=True, notice=False, cif=False, file=output
        )
        self.assertTrue(printer.ProcessMandiant(indicator))
        header, data = output.getvalue().splitlines()
        fields = header.split("\t")[1:]
        row = dict(zip(fields, data.split("\t"), strict=True))
        self.assertEqual(row["meta.campaigns"], "UNC42")
        self.assertEqual(row["meta.reports"], "24-5678")
