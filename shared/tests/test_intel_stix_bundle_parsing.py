"""ProcessSTIX accepts bundles, TAXII 2.1 envelopes, and single objects, and one bad object doesn't sink the rest."""

import io
import json

import pytest

for _module in ('antlr4', 'stix2', 'stix2patterns', 'pymisp', 'taxii2client', 'mandiant_threatintel', 'vt'):
    pytest.importorskip(_module)

from stix2.v20 import Bundle as Bundle20, Indicator as Indicator20
from stix2.v21 import Indicator as Indicator21

import zeek_threat_feed_utils as feeds


def indicator_dict(value='a.example', name=None):
    options = dict(
        pattern=f"[domain-name:value = '{value}']",
        pattern_type='stix',
        valid_from='2026-01-01T00:00:00Z',
    )
    obj = json.loads(Indicator21(**options).serialize())
    if name is not None:
        # set after serializing, so the stix2 constructor can't drop or reject an empty string
        obj['name'] = name
    return obj


def run(to_parse, version=None):
    output = io.StringIO()
    printer = feeds.FeedParserZeekPrinter(extended=False, notice=False, cif=False, file=output)
    result = printer.ProcessSTIX(to_parse, version=version)
    lines = output.getvalue().splitlines()
    rows = []
    if lines:
        header = lines[0].split('\t')[1:]
        rows = [dict(zip(header, line.split('\t'))) for line in lines[1:]]
    return result, rows


def test_malformed_non_indicator_object_does_not_discard_the_bundle():
    bad_report = {
        'type': 'report',
        'spec_version': '2.1',
        'id': 'report--6b1f1a5e-6d4a-4a8e-9a55-2a3f0b1c9d01',
        'created': '2026-01-01T00:00:00.000Z',
        'modified': '2026-01-01T00:00:00.000Z',
        'name': 'broken report',
        'published': '2026-01-01T00:00:00Z',
        'object_refs': [None],
    }
    bundle = {
        'type': 'bundle',
        'id': 'bundle--0f9a8c43-1d55-4f6e-8b0e-6c1b5f2a7e11',
        'objects': [bad_report, indicator_dict('a.example')],
    }
    result, rows = run(bundle, version='2.1')
    assert result
    assert [row['indicator'] for row in rows] == ['a.example']


def test_malformed_indicator_is_skipped_and_the_rest_kept():
    broken = indicator_dict('broken.example')
    broken['pattern'] = "[domain-name:value = "
    bundle = {
        'type': 'bundle',
        'id': 'bundle--3c2e1d0f-9b8a-4c7d-8e6f-5a4b3c2d1e0f',
        'objects': [broken, indicator_dict('a.example')],
    }
    result, rows = run(bundle, version='2.1')
    assert result
    assert [row['indicator'] for row in rows] == ['a.example']


def test_taxii21_envelope_is_parsed():
    envelope = {'more': False, 'objects': [indicator_dict('a.example'), indicator_dict('b.example')]}
    result, rows = run(envelope, version='2.1')
    assert result
    assert [row['indicator'] for row in rows] == ['a.example', 'b.example']


@pytest.mark.parametrize('envelope', [{}, {'more': False}, {'more': False, 'objects': []}])
def test_empty_taxii21_envelope_is_quietly_empty(envelope):
    result, rows = run(envelope, version='2.1')
    assert not result
    assert rows == []


def test_single_indicator_object_is_parsed():
    result, rows = run(indicator_dict('a.example'), version='2.1')
    assert result
    assert [row['indicator'] for row in rows] == ['a.example']


def test_stix20_bundle_passes_its_spec_version_to_the_objects():
    indicator = Indicator20(
        pattern="[domain-name:value = 'a.example']",
        valid_from='2026-01-01T00:00:00Z',
        labels=['malicious-activity'],
    )
    bundle = json.loads(Bundle20(objects=[indicator]).serialize())
    assert bundle.get('spec_version') == '2.0'
    result, rows = run(bundle)  # no version given; it has to come from the bundle
    assert result
    assert [row['indicator'] for row in rows] == ['a.example']


def test_empty_name_does_not_produce_a_leading_separator():
    reduced = json.loads(
        Indicator21(
            pattern="[file:name = 'update.exe' AND file:hashes.MD5 = '0123456789abcdef0123456789abcdef']",
            pattern_type='stix',
            valid_from='2026-01-01T00:00:00Z',
        ).serialize()
    )
    reduced['name'] = ''
    result, rows = run(reduced, version='2.1')
    assert result
    assert rows[0]['meta.desc'].startswith(feeds.STIX_REDUCED_PATTERN_NOTE)

    result, rows = run(indicator_dict('a.example', name=''), version='2.1')
    assert rows[0]['meta.desc'] == '-'
