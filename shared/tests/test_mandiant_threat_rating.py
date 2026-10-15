"""Regressions for opt-in Mandiant threat rating in Zeek intel exports."""

from datetime import datetime, timezone
from io import StringIO
from unittest.mock import Mock

import mandiant_threatintel
import pytest

import zeek_threat_feed_utils as intel


class NoNetworkClient:
    class Indicators:
        @staticmethod
        def get_raw(*args, **kwargs):
            raise AssertionError('Indicator field access triggered a network request')


def make_indicator(rating=None, *, present=True, cls=mandiant_threatintel.FQDNIndicator):
    payload = {
        'id': 'indicator--test',
        'type': 'md5' if cls is mandiant_threatintel.MD5Indicator else 'fqdn',
        'value': 'a' * 32 if cls is mandiant_threatintel.MD5Indicator else 'sample.example.test',
        'mscore': 78,
        'first_seen': '2026-01-01T00:00:00Z',
        'last_seen': '2026-01-02T00:00:00Z',
        'sources': [],
        'misp': {},
    }
    if present:
        payload['threat_rating'] = rating
    if cls is mandiant_threatintel.MD5Indicator:
        payload['associated_hashes'] = [
            {'id': 'sha1', 'value': 'b' * 40},
            {'id': 'sha256', 'value': 'c' * 64},
        ]
    return cls.from_json_response(payload, NoNetworkClient())


@pytest.mark.parametrize('score', [0, 1, 3.5, 48, 100])
def test_valid_threat_rating_is_distinct_from_mscore(score):
    (row,) = intel.map_mandiant_indicator_to_zeek(
        make_indicator({'threat_score': score}), skip_attr_map={'threat_rating': False}
    )
    assert row[intel.ZEEK_INTEL_META_THREAT_SCORE] == str(score)
    assert row[intel.ZEEK_INTEL_META_CONFIDENCE] == '78'
    assert row[intel.ZEEK_INTEL_CIF_CONFIDENCE] == '8'


@pytest.mark.parametrize('rating', [
    {}, None, '88', [80], {'threat_score': None}, {'threat_score': True},
    {'threat_score': '85'}, {'threat_score': -1}, {'threat_score': 101},
    {'threat_score': float('nan')}, {'threat_score': float('inf')},
])
def test_invalid_or_missing_threat_rating_is_omitted(rating):
    (row,) = intel.map_mandiant_indicator_to_zeek(
        make_indicator(rating), skip_attr_map={'threat_rating': False}
    )
    assert intel.ZEEK_INTEL_META_THREAT_SCORE not in row
    assert row[intel.ZEEK_INTEL_META_CONFIDENCE] == '78'


def test_absent_rating_does_not_initiate_lazy_sdk_fetch():
    (row,) = intel.map_mandiant_indicator_to_zeek(
        make_indicator(present=False), skip_attr_map={'threat_rating': False}
    )
    assert intel.ZEEK_INTEL_META_THREAT_SCORE not in row


def test_explicitly_disabled_rating_is_not_exported():
    (row,) = intel.map_mandiant_indicator_to_zeek(
        make_indicator({'threat_score': 94}), skip_attr_map={'threat_rating': True}
    )
    assert intel.ZEEK_INTEL_META_THREAT_SCORE not in row


def test_md5_hash_expansion_keeps_rating():
    rows = intel.map_mandiant_indicator_to_zeek(
        make_indicator({'threat_score': 91}, cls=mandiant_threatintel.MD5Indicator),
        skip_attr_map={'threat_rating': False},
    )
    assert len(rows) == 2
    assert {r[intel.ZEEK_INTEL_INDICATOR] for r in rows} == {'b' * 40, 'c' * 64}
    assert {r[intel.ZEEK_INTEL_META_THREAT_SCORE] for r in rows} == {'91'}


def test_extended_printer_emits_score_in_correct_column():
    output = StringIO()
    printer = intel.FeedParserZeekPrinter(extended=True, notice=False, cif=False, file=output)
    assert printer.ProcessMandiant(
        make_indicator({'threat_score': 86}), skip_attr_map={'threat_rating': False}
    )
    header, data = output.getvalue().splitlines()
    fields, values = header.split('\t')[1:], data.split('\t')
    assert len(fields) == len(values)
    assert values[fields.index('meta.threat_score')] == '86'
    assert values[fields.index('meta.confidence')] == '78'


@pytest.mark.parametrize('enabled', [True, False])
def test_fetch_config_forwards_include_threat_rating(monkeypatch, enabled):
    client = Mock()
    client.Indicators.get_list.return_value = []
    monkeypatch.setattr(intel.mandiant_threatintel, 'ThreatIntelClient', Mock(return_value=client))
    intel.UpdateFromMandiant(
        connInfo={'api_key': 'fixture', 'include_threat_rating': enabled},
        since=datetime(2026, 10, 1, tzinfo=timezone.utc),
        nowTime=datetime(2026, 10, 8, tzinfo=timezone.utc),
        sslVerify=True, zeekPrinter=Mock(), logger=None, successCount=Mock(), workerId=1,
    )
    assert client.Indicators.get_list.call_args.kwargs['include_threat_rating'] is enabled
