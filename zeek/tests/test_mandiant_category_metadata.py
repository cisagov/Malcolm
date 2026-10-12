"""Mandiant indicator category enrichment for Zeek intel output."""

import importlib
import sys
from datetime import datetime, timezone
from io import StringIO
from pathlib import Path
from unittest.mock import Mock

import mandiant_threatintel
import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "zeek" / "scripts"))
intel = importlib.import_module("zeek_threat_feed_utils")


def indicator(category, sources=None):
    """Construct a real SDK indicator without contacting Mandiant."""
    fields = {
        "id": "indicator-test-1",
        "type": "fqdn",
        "value": "example.test",
        "mscore": 85,
        "first_seen": "2026-10-01T00:00:00Z",
        "last_seen": "2026-10-02T00:00:00Z",
        "misp": {},
        "sources": sources if sources is not None else [],
    }
    if category is not None:
        fields["category"] = category
    return mandiant_threatintel.FQDNIndicator.from_json_response(
        fields, client=None
    )


@pytest.mark.parametrize(
    ("category", "expected"),
    [
        ("backdoor", "backdoor"),
        (["ransomware", "phishing"], r"phishing\x7cransomware"),
        ("spear,phishing", r"spear\x2cphishing"),
        ("", "-"),
        ([], "-"),
    ],
)
def test_direct_mandiant_category_reaches_zeek_metadata(category, expected):
    (result,) = intel.map_mandiant_indicator_to_zeek(
        indicator(category), skip_attr_map={"category": False}
    )
    assert result[intel.ZEEK_INTEL_META_CATEGORY] == expected
    assert result[intel.ZEEK_INTEL_INDICATOR] == "example.test"


def test_source_categories_remain_available_without_direct_category():
    (result,) = intel.map_mandiant_indicator_to_zeek(
        indicator(None, [{"source_name": "Mandiant", "category": ["malware"]}])
    )
    assert result[intel.ZEEK_INTEL_META_CATEGORY] == "malware"


def test_direct_category_combines_without_duplicates_with_source_categories():
    (result,) = intel.map_mandiant_indicator_to_zeek(
        indicator(
            ["ransomware", "phishing"],
            [{"source_name": "Mandiant", "category": ["phishing"]}],
        ),
        skip_attr_map={"category": False},
    )
    assert result[intel.ZEEK_INTEL_META_CATEGORY] == r"phishing\x7cransomware"


def test_disabled_category_does_not_emit_unrequested_direct_enrichment():
    (result,) = intel.map_mandiant_indicator_to_zeek(
        indicator(["ransomware"]), skip_attr_map={"category": True}
    )
    assert result[intel.ZEEK_INTEL_META_CATEGORY] == "-"


@pytest.mark.parametrize("requested", [False, True])
def test_mandiant_client_gets_requested_category_flag(monkeypatch, requested):
    client = Mock()
    client.Indicators.get_list.return_value = []
    factory = Mock(return_value=client)
    monkeypatch.setattr(intel.mandiant_threatintel, "ThreatIntelClient", factory)

    intel.UpdateFromMandiant(
        connInfo={"api_key": "example", "include_category": requested},
        since=datetime(2026, 10, 1, tzinfo=timezone.utc),
        nowTime=datetime(2026, 10, 7, tzinfo=timezone.utc),
        sslVerify=True,
        zeekPrinter=Mock(),
        logger=None,
        successCount=Mock(),
        workerId=1,
    )

    assert client.Indicators.get_list.call_args.kwargs["include_category"] is requested


def test_default_category_enrichment_remains_enabled(monkeypatch):
    client = Mock()
    client.Indicators.get_list.return_value = []
    monkeypatch.setattr(
        intel.mandiant_threatintel,
        "ThreatIntelClient",
        Mock(return_value=client),
    )
    intel.UpdateFromMandiant(
        connInfo={"api_key": "example"},
        since=datetime(2026, 10, 1, tzinfo=timezone.utc),
        nowTime=datetime(2026, 10, 7, tzinfo=timezone.utc),
        sslVerify=True,
        zeekPrinter=Mock(),
        logger=None,
        successCount=Mock(),
        workerId=1,
    )
    assert client.Indicators.get_list.call_args.kwargs["include_category"] is True


def test_extended_zeek_output_includes_category_without_extra_columns():
    output = StringIO()
    printer = intel.FeedParserZeekPrinter(
        extended=True, notice=False, cif=False, file=output
    )

    assert printer.ProcessMandiant(
        indicator(["phishing", "ransomware"]), skip_attr_map={"category": False}
    )

    lines = output.getvalue().splitlines()
    assert len(lines) == 2
    fields = lines[0].split("\t")[1:]
    values = lines[1].split("\t")
    assert len(fields) == len(values)
    assert values[fields.index("meta.category")] == r"phishing\x7cransomware"


def test_md5_hash_fanout_preserves_category():
    response = {
        "id": "indicator-test-md5",
        "type": "md5",
        "value": "0123456789abcdef0123456789abcdef",
        "mscore": 90,
        "first_seen": "2026-10-01T00:00:00Z",
        "last_seen": "2026-10-02T00:00:00Z",
        "sources": [],
        "misp": {},
        "category": ["malware"],
        "associated_hashes": [
            {"value": "a" * 64, "id": "associated-hash-1"},
            {"value": "b" * 40, "id": "associated-hash-2"},
        ],
    }
    indicator_obj = mandiant_threatintel.MD5Indicator.from_json_response(
        response, client=None
    )
    rows = intel.map_mandiant_indicator_to_zeek(
        indicator_obj, skip_attr_map={"category": False}
    )
    assert len(rows) == 2
    assert {row[intel.ZEEK_INTEL_INDICATOR] for row in rows} == {
        "a" * 64, "b" * 40
    }
    assert all(
        row[intel.ZEEK_INTEL_META_CATEGORY] == "malware" for row in rows
    )
