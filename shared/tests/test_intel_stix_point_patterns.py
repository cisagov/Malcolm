"""STIX patterns become the Zeek point indicators that can match independently, and nothing broader."""

import importlib
import io

import pytest

for _module in ('antlr4', 'stix2', 'stix2patterns', 'pymisp', 'taxii2client', 'mandiant_threatintel', 'vt'):
    pytest.importorskip(_module)

import zeek_threat_feed_utils as feeds

MD5 = '0123456789abcdef0123456789abcdef'
SHA1 = '0123456789abcdef0123456789abcdef01234567'
SHA256 = '0123456789abcdef' * 4


@pytest.fixture(params=['2.0', '2.1'])
def stix_version(request):
    return request.param, importlib.import_module('stix2.v' + request.param.replace('.', ''))


def indicator(version, module, pattern):
    options = {'pattern': pattern, 'valid_from': '2026-01-01T00:00:00Z', 'labels': ['malicious-activity']}
    if version == '2.1':
        options['pattern_type'] = 'stix'
    return module.Indicator(**options)


def emitted_values(module, pattern):
    pairs = feeds.split_stix_object_path_and_value(module.Indicator, pattern)
    return None if pairs is None else [value for _, value in pairs]


@pytest.mark.parametrize(
    'pattern,expected',
    [
        ("[domain-name:value = 'a.example']", ['a.example']),
        ("[domain-name:value = 'a.example' OR domain-name:value = 'b.example']", ['a.example', 'b.example']),
        (
            "[(domain-name:value = 'a.example' OR domain-name:value = 'b.example') OR domain-name:value = 'c.example']",
            ['a.example', 'b.example', 'c.example'],
        ),
        ("[domain-name:value IN ('a.example', 'b.example')]", ['a.example', 'b.example']),
        ("[file:name = 'AND']", ['AND']),
        ("[file:name = 'x AND y' OR file:name = 'OR NOT AND']", ['x AND y', 'OR NOT AND']),
        ("[file:name = 'it\\'s.exe']", ["it's.exe"]),
        (f"[file:hashes.MD5 = '{MD5}' OR file:hashes.'SHA-1' = '{SHA1}']", [MD5, SHA1]),
        # every conjunct is a hash of the same file, so nothing is lost
        (f"[file:hashes.MD5 = '{MD5}' AND file:hashes.'SHA-256' = '{SHA256}']", [MD5, SHA256]),
        ("[domain-name:value = 'a.example'] OR [ipv4-addr:value = '93.184.216.34']", ['a.example', '93.184.216.34']),
        # the address-type test on a network-traffic reference is implied by the value
        (
            "[network-traffic:dst_ref.type = 'ipv4-addr' AND network-traffic:dst_ref.value = '93.184.216.34']",
            ['93.184.216.34'],
        ),
        (
            "[(network-traffic:src_ref.type = 'ipv6-addr' AND network-traffic:src_ref.value = '2606:2800:220:1::1')]",
            ['2606:2800:220:1::1'],
        ),
    ],
)
def test_exactly_representable_patterns(stix_version, pattern, expected):
    version, module = stix_version
    assert feeds.is_stix_point_equality_ioc(module.Indicator, pattern)
    assert emitted_values(module, pattern) == expected
    rows = feeds.map_stix_indicator_to_zeek(indicator(version, module, pattern))
    assert [row['indicator'] for row in rows] == expected
    assert not any(feeds.STIX_REDUCED_PATTERN_NOTE in row['meta.desc'] for row in rows)


@pytest.mark.parametrize(
    'pattern,expected',
    [
        # OR branches Zeek can't express are dropped; the rest still match exactly
        ("[domain-name:value = 'a.example' OR (domain-name:value = 'b.example' AND domain-name:value = 'c.example')]", ['a.example']),
        ("[(domain-name:value = 'a.example' AND domain-name:value = 'b.example') OR domain-name:value = 'c.example']", ['c.example']),
        ("[domain-name:value = 'a.example' OR domain-name:value != 'b.example']", ['a.example']),
        ("[domain-name:value = 'a.example' OR domain-name:value NOT = 'b.example']", ['a.example']),
        ("[domain-name:value = 'a.example' OR domain-name:value LIKE '%.example']", ['a.example']),
        ("[file:name = 'update.exe' OR file:size > 100]", ['update.exe']),
    ],
)
def test_unrepresentable_or_branches_are_dropped(stix_version, pattern, expected):
    version, module = stix_version
    assert not feeds.is_stix_point_equality_ioc(module.Indicator, pattern)
    assert emitted_values(module, pattern) == expected
    rows = feeds.map_stix_indicator_to_zeek(indicator(version, module, pattern))
    assert [row['indicator'] for row in rows] == expected
    assert not any(feeds.STIX_REDUCED_PATTERN_NOTE in row['meta.desc'] for row in rows)


@pytest.mark.parametrize(
    'pattern',
    [
        f"[file:name = 'update.exe' AND file:hashes.MD5 = '{MD5}']",
        f"[file:hashes.MD5 = '{MD5}' AND file:size > 100]",
        f"[(file:name = 'a.exe' OR file:name = 'b.exe') AND file:hashes.MD5 = '{MD5}']",
    ],
)
def test_hash_conjunctions_reduce_to_the_hash_and_say_so(stix_version, pattern):
    version, module = stix_version
    assert not feeds.is_stix_point_equality_ioc(module.Indicator, pattern)
    assert emitted_values(module, pattern) == [MD5]
    obj = indicator(version, module, pattern)
    rows = feeds.map_stix_indicator_to_zeek(obj)
    assert [row['indicator'] for row in rows] == [MD5]
    assert rows[0]['indicator_type'] == 'Intel::FILE_HASH'
    assert f'{feeds.STIX_REDUCED_PATTERN_NOTE} ({obj.id})' in rows[0]['meta.desc']


@pytest.mark.parametrize(
    'pattern',
    [
        "[domain-name:value = 'a.example' AND domain-name:value = 'b.example']",
        "[file:name = 'update.exe' AND file:size > 100]",
        "[domain-name:value NOT IN ('a.example', 'b.example')]",
        "[domain-name:value = 'a.example'] AND [domain-name:value = 'b.example']",
        f"[file:hashes.MD5 = '{MD5}'] AND [domain-name:value = 'a.example']",
        "[domain-name:value = 'a.example'] FOLLOWEDBY [domain-name:value = 'b.example']",
        "[domain-name:value = 'a.example'] REPEATS 2 TIMES",
        # an IP without its port would match every port
        "[network-traffic:dst_ref.type = 'ipv4-addr' AND network-traffic:dst_ref.value = '93.184.216.34' AND network-traffic:dst_port = 443]",
        # declared type contradicts the value, so it can never match
        "[network-traffic:dst_ref.type = 'ipv6-addr' AND network-traffic:dst_ref.value = '93.184.216.34']",
    ],
)
def test_patterns_with_nothing_representable_are_rejected(stix_version, pattern):
    version, module = stix_version
    assert not feeds.is_stix_point_equality_ioc(module.Indicator, pattern)
    assert feeds.split_stix_object_path_and_value(module.Indicator, pattern) is None
    assert feeds.map_stix_indicator_to_zeek(indicator(version, module, pattern)) is None


def test_quoted_and_unquoted_hash_paths_map_alike(stix_version):
    version, module = stix_version
    ssdeep = '3:a+JraNvsgzsVqSwHq9:tJuOgzsko'
    for path, value in (
        ("file:hashes.SSDEEP", ssdeep),
        ("file:hashes.'SSDEEP'", ssdeep),
        ("file:hashes.'SHA-256'", SHA256),
    ):
        rows = feeds.map_stix_indicator_to_zeek(indicator(version, module, f"[{path} = '{value}']"))
        assert [row['indicator_type'] for row in rows] == ['Intel::FILE_HASH']


def test_malformed_patterns_keep_existing_rejection(stix_version):
    _, module = stix_version
    assert not feeds.is_stix_point_equality_ioc(module.Indicator, "[domain-name:value = ")
    assert feeds.split_stix_object_path_and_value(module.Indicator, "[domain-name:value = ") is None


def test_dnf_explosion_is_capped(stix_version):
    _, module = stix_version
    group = "(file:name = 'a' OR file:name = 'b')"
    pattern = '[' + ' AND '.join([group] * 9) + ']'  # 2**9 clauses
    iocs, dropped = feeds.stix_pattern_point_iocs(module.Indicator, pattern)
    assert iocs == ()
    assert dropped and 'clauses after normalization' in dropped[0]


def test_serialized_bundle_does_not_emit_partial_matches(stix_version):
    version, module = stix_version
    valid = indicator(version, module, "[domain-name:value = 'allowed.example']")
    rejected = indicator(version, module, "[domain-name:value = 'a.example' AND domain-name:value = 'b.example']")
    bundle = module.Bundle(objects=[rejected, valid])
    output = io.StringIO()
    printer = feeds.FeedParserZeekPrinter(extended=False, notice=False, cif=False, file=output)
    printer.ProcessSTIX(bundle.serialize(), version=version)
    data = [line for line in output.getvalue().splitlines() if not line.startswith('#')]
    assert len(data) == 1
    assert data[0].startswith('allowed.example\tIntel::DOMAIN\t')
