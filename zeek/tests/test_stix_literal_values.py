"""Point indicator values must decode STIX quoting without Python escapes."""

import io
from pathlib import Path
import sys

import pytest
import stix2.v20 as v20
import stix2.v21 as v21

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts'))
sys.path.insert(0, str(ROOT / 'zeek' / 'scripts'))

import zeek_threat_feed_utils as feeds  # noqa: E402 - standalone source path

BACKSLASH = chr(92)
QUOTE = chr(39)
VALUES = [
    'ordinary.exe',
    "O'Reilly.exe",
    "'leading.exe",
    "trailing.exe'",
    QUOTE,
    QUOTE * 2,
    BACKSLASH,
    BACKSLASH.join(['C:', 'temp', 'payload.exe']),
    'literal' + BACKSLASH + 'n-not-a-newline.exe',
    'literal' + BACKSLASH + 'x41-not-a-hex-escape.exe',
    'C:' + BACKSLASH + "folder" + BACKSLASH + "O'Reilly.exe",
    "café-東京-'payload'.exe",
]


def quote(value):
    return QUOTE + value.replace(BACKSLASH, BACKSLASH * 2).replace(QUOTE, BACKSLASH + QUOTE) + QUOTE


def make_indicator(version, module, pattern):
    options = dict(
        pattern=pattern,
        valid_from='2026-01-01T00:00:00Z',
        created='2026-01-01T00:00:00Z',
        modified='2026-01-01T00:00:00Z',
    )
    if version == '2.0':
        options['labels'] = ['malicious-activity']
    else:
        options['pattern_type'] = 'stix'
    return module.Indicator(**options)


@pytest.fixture(params=[('2.0', v20), ('2.1', v21)])
def stix(request):
    return request.param


@pytest.mark.parametrize('value', VALUES)
def test_values_survive_point_extraction_and_public_mapping(stix, value):
    version, module = stix
    pattern = '[file:name = ' + quote(value) + ']'
    indicator = make_indicator(version, module, pattern)
    assert feeds.split_stix_object_path_and_value(module.Indicator, pattern) == [('file:name', value)]
    rows = feeds.map_stix_indicator_to_zeek(indicator)
    assert [row[feeds.ZEEK_INTEL_INDICATOR] for row in rows] == [value]
    assert rows[0][feeds.ZEEK_INTEL_INDICATOR_TYPE] == 'Intel::FILE_NAME'


def test_or_alternatives_are_decoded_independently(stix):
    version, module = stix
    values = ["first's.exe", 'C:' + BACKSLASH + 'second.exe']
    pattern = '[' + ' OR '.join('file:name = ' + quote(value) for value in values) + ']'
    rows = feeds.map_stix_indicator_to_zeek(make_indicator(version, module, pattern))
    assert [row[feeds.ZEEK_INTEL_INDICATOR] for row in rows] == values


def test_serialized_bundle_keeps_apostrophes_in_emitted_names(stix):
    version, module = stix
    value = "trailing-name'"
    indicator = make_indicator(version, module, '[file:name = ' + quote(value) + ']')
    output = io.StringIO()
    printer = feeds.FeedParserZeekPrinter(extended=False, notice=False, cif=False, file=output)
    assert printer.ProcessSTIX(module.Bundle(objects=[indicator]).serialize(), version=version)
    rows = [line.split(chr(9)) for line in output.getvalue().splitlines() if not line.startswith('#')]
    assert [row[0] for row in rows] == [value]
