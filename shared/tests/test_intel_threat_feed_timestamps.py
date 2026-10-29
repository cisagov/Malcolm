"""Threat intelligence timestamps must not depend on the importing host timezone."""

from contextlib import contextmanager
from datetime import datetime, timezone
import io
import os
import time

import mandiant_threatintel
from pymisp import MISPAttribute
import pytest
from stix2.v20 import Bundle as Bundle20, Indicator as Indicator20
from stix2.v21 import Bundle as Bundle21, Indicator as Indicator21

import zeek_threat_feed_utils as feed


@contextmanager
def local_timezone(value):
    original = os.environ.get('TZ')
    os.environ['TZ'] = value
    time.tzset()
    try:
        yield
    finally:
        if original is None:
            os.environ.pop('TZ', None)
        else:
            os.environ['TZ'] = original
        time.tzset()


def stix_indicator(version):
    cls = Indicator20 if version == '2.0' else Indicator21
    args = dict(
        pattern="[domain-name:value = 'sample.example']",
        created='2026-07-02T03:04:05.125Z',
        modified='2026-07-03T04:05:06.750Z',
        valid_from='2026-07-02T03:04:05Z',
        labels=['malicious-activity'],
    )
    if version == '2.1':
        args['pattern_type'] = 'stix'
    return cls(**args)


def mapped_indicator(provider):
    if provider in ('2.0', '2.1'):
        indicator = stix_indicator(provider)
        return feed.map_stix_indicator_to_zeek(indicator)[0], indicator.created, indicator.modified
    if provider == 'misp':
        timestamp = datetime(2026, 7, 2, 3, 4, 5, tzinfo=timezone.utc)
        attribute = MISPAttribute()
        attribute.from_dict(type='domain', value='sample.example', timestamp=int(timestamp.timestamp()))
        return feed.map_misp_attribute_to_zeek(attribute)[0], timestamp, timestamp
    indicator = mandiant_threatintel.FQDNIndicator(
        None,
        response={
            'id': 'fqdn--sample.example',
            'value': 'sample.example',
            'first_seen': '2026-07-02T03:04:05.125Z',
            'last_seen': '2026-07-03T04:05:06.750Z',
            'mscore': 50,
            'sources': [],
            'misp': {},
        },
    )
    return feed.map_mandiant_indicator_to_zeek(indicator)[0], indicator.first_seen, indicator.last_seen


@pytest.mark.skipif(not hasattr(time, 'tzset'), reason='requires process-local TZ support')
@pytest.mark.parametrize('zone', ['UTC0', 'EST5EDT,M3.2.0,M11.1.0', 'JST-9'])
@pytest.mark.parametrize('provider', ['2.0', '2.1', 'misp', 'mandiant'])
def test_mapping_preserves_the_actual_instants(provider, zone):
    with local_timezone(zone):
        row, first, last = mapped_indicator(provider)
        assert float(row[feed.ZEEK_INTEL_META_FIRSTSEEN]) == first.timestamp()
        assert float(row[feed.ZEEK_INTEL_META_LASTSEEN]) == last.timestamp()
        assert row[feed.ZEEK_INTEL_CIF_FIRSTSEEN] == row[feed.ZEEK_INTEL_META_FIRSTSEEN]
        assert row[feed.ZEEK_INTEL_CIF_LASTSEEN] == row[feed.ZEEK_INTEL_META_LASTSEEN]
        assert row[feed.ZEEK_INTEL_INDICATOR] == 'sample.example'
        assert row[feed.ZEEK_INTEL_INDICATOR_TYPE] == 'Intel::DOMAIN'


@pytest.mark.parametrize('version', ['2.0', '2.1'])
def test_serialized_bundle_preserves_fractional_seconds_in_emitted_zeek_rows(version):
    indicator = stix_indicator(version)
    bundle = (Bundle20 if version == '2.0' else Bundle21)(objects=[indicator])
    output = io.StringIO()
    printer = feed.FeedParserZeekPrinter(extended=True, notice=False, cif=True, file=output)
    assert printer.ProcessSTIX(bundle.serialize(), version=version)
    header, line = output.getvalue().splitlines()
    row = dict(zip(header.split('\t')[1:], line.split('\t')))
    assert float(row[feed.ZEEK_INTEL_META_FIRSTSEEN]) == indicator.created.timestamp()
    assert float(row[feed.ZEEK_INTEL_META_LASTSEEN]) == indicator.modified.timestamp()
    assert row[feed.ZEEK_INTEL_META_FIRSTSEEN] == row[feed.ZEEK_INTEL_CIF_FIRSTSEEN]


def test_since_filter_still_uses_the_original_indicator_datetime():
    indicator = stix_indicator('2.1')
    bundle = Bundle21(objects=[indicator])
    output = io.StringIO()
    printer = feed.FeedParserZeekPrinter(
        extended=True, notice=False, cif=False, since=datetime(2026, 7, 4, tzinfo=timezone.utc), file=output
    )
    printer.ProcessSTIX(bundle.serialize(), version='2.1')
    assert output.getvalue() == ''
