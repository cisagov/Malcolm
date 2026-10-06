"""Only independent positive equalities can become Zeek point indicators."""

import importlib
import io
from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts'))
sys.path.insert(0, str(ROOT / 'zeek' / 'scripts'))
import zeek_threat_feed_utils as feeds


@pytest.fixture(params=['2.0', '2.1'])
def stix_version(request):
    return request.param, importlib.import_module('stix2.v' + request.param.replace('.', ''))


def indicator(version, module, pattern):
    options = {'pattern': pattern, 'valid_from': '2026-01-01T00:00:00Z', 'labels': ['malicious-activity']}
    if version == '2.1':
        options['pattern_type'] = 'stix'
    return module.Indicator(**options)


@pytest.mark.parametrize(
    'pattern,expected',
    [
        ("[domain-name:value = 'a.example']", ['a.example']),
        ("[domain-name:value = 'a.example' OR domain-name:value = 'b.example']", ['a.example', 'b.example']),
        (
            "[(domain-name:value = 'a.example' OR domain-name:value = 'b.example') OR domain-name:value = 'c.example']",
            ['a.example', 'b.example', 'c.example'],
        ),
        ("[file:name = 'AND']", ['AND']),
        ("[file:name = 'x AND y' OR file:name = 'OR NOT AND']", ['x AND y', 'OR NOT AND']),
        (
            "[file:hashes.MD5 = '0123456789abcdef0123456789abcdef' OR file:hashes.'SHA-1' = '0123456789abcdef0123456789abcdef01234567']",
            ['0123456789abcdef0123456789abcdef', '0123456789abcdef0123456789abcdef01234567'],
        ),
    ],
)
def test_positive_singletons_and_or_alternatives_remain_supported(stix_version, pattern, expected):
    version, module = stix_version
    assert feeds.is_stix_point_equality_ioc(module.Indicator, pattern)
    assert [value for _, value in feeds.split_stix_object_path_and_value(module.Indicator, pattern)] == expected
    rows = feeds.map_stix_indicator_to_zeek(indicator(version, module, pattern))
    assert [row['indicator'] for row in rows] == expected


@pytest.mark.parametrize(
    'pattern',
    [
        "[file:name = 'update.exe' AND file:hashes.MD5 = '0123456789abcdef0123456789abcdef']",
        "[domain-name:value = 'a.example' AND domain-name:value = 'b.example']",
        "[domain-name:value = 'a.example' OR (domain-name:value = 'b.example' AND domain-name:value = 'c.example')]",
        "[(domain-name:value = 'a.example' AND domain-name:value = 'b.example') OR domain-name:value = 'c.example']",
        "[domain-name:value = 'a.example' OR domain-name:value != 'b.example']",
        "[domain-name:value = 'a.example' OR domain-name:value NOT = 'b.example']",
        "[domain-name:value = 'a.example' OR domain-name:value LIKE '%.example']",
        "[file:name = 'update.exe' OR file:size > 100]",
        "[domain-name:value = 'a.example'] AND [domain-name:value = 'b.example']",
        "[domain-name:value = 'a.example'] REPEATS 2 TIMES",
    ],
)
def test_compound_or_non_equality_patterns_are_rejected_as_a_whole(stix_version, pattern):
    version, module = stix_version
    assert not feeds.is_stix_point_equality_ioc(module.Indicator, pattern)
    assert feeds.split_stix_object_path_and_value(module.Indicator, pattern) is None
    assert feeds.map_stix_indicator_to_zeek(indicator(version, module, pattern)) is None


def test_malformed_patterns_keep_existing_rejection(stix_version):
    _, module = stix_version
    assert not feeds.is_stix_point_equality_ioc(module.Indicator, "[domain-name:value = ")


def test_serialized_bundle_does_not_emit_partial_matches(stix_version):
    version, module = stix_version
    valid = indicator(version, module, "[domain-name:value = 'allowed.example']")
    rejected = indicator(
        version, module, "[file:name = 'update.exe' AND file:hashes.MD5 = '0123456789abcdef0123456789abcdef']"
    )
    bundle = module.Bundle(objects=[rejected, valid])
    output = io.StringIO()
    printer = feeds.FeedParserZeekPrinter(extended=False, notice=False, cif=False, file=output)
    printer.ProcessSTIX(bundle.serialize(), version=version)
    data = [line for line in output.getvalue().splitlines() if not line.startswith('#')]
    assert len(data) == 1
    assert data[0].startswith('allowed.example\tIntel::DOMAIN\t')
