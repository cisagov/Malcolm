"""Regression tests for filescan's timestamp normalization, ECS value types and grouping helpers."""

import os
import time
import uuid
from datetime import datetime, timedelta, timezone, UTC

import pytest

from filescan import ecs, model, utils


@pytest.fixture(params=['UTC', 'America/Denver', 'Asia/Tokyo'])
def host_timezone(request):
    if not hasattr(time, 'tzset'):
        pytest.skip('Requires time.tzset')
    original = os.environ.get('TZ')
    os.environ['TZ'] = request.param
    time.tzset()
    try:
        yield
    finally:
        if original is None:
            os.environ.pop('TZ', None)
        else:
            os.environ['TZ'] = original
        time.tzset()


NOON_UTC = datetime(2026, 1, 2, 12, 0, 0, tzinfo=UTC)

###################################################################################################
# _ensure_utc


@pytest.mark.parametrize(
    'value',
    [
        '2026-01-02T12:00:00',
        '2026-01-02T12:00:00Z',
        '2026-01-02T12:00:00+00:00',
        '2026-01-02T05:00:00-07:00',
        '2026-01-02T21:00:00+09:00',
        datetime(2026, 1, 2, 12, 0, 0),
        NOON_UTC,
        datetime(2026, 1, 2, 7, 0, 0, tzinfo=timezone(timedelta(hours=-5))),
    ],
)
def test_ensure_utc_is_independent_of_host_timezone(host_timezone, value):
    result = model._ensure_utc(value)
    assert result == NOON_UTC
    assert result.utcoffset() == timedelta(0)


def test_ensure_utc_none_is_now(host_timezone):
    before = datetime.now(UTC)
    result = model._ensure_utc(None)
    after = datetime.now(UTC)
    assert before <= result <= after
    assert result.utcoffset() == timedelta(0)


def test_ensure_utc_rejects_garbage():
    with pytest.raises(ValueError):
        model._ensure_utc('not a timestamp')


###################################################################################################
# UTCDatetime fields on scan messages


def test_message_time_from_naive_string_is_utc(host_timezone):
    begin = model.ScanBegin(id=uuid.uuid4(), name='strelka', time='2026-01-02T12:00:00')
    assert begin.time == NOON_UTC


def test_message_time_serializes_with_offset_and_round_trips(host_timezone):
    begin = model.ScanBegin(id=uuid.uuid4(), name='strelka', time=NOON_UTC)
    dumped = begin.model_dump(mode='json')
    assert dumped['time'] == '2026-01-02T12:00:00+00:00'
    assert model.ScanBegin.model_validate_json(begin.model_dump_json()) == begin


def test_message_time_defaults_to_now_in_utc():
    before = datetime.now(UTC)
    begin = model.ScanBegin(id=uuid.uuid4(), name='strelka')
    after = datetime.now(UTC)
    assert before <= begin.time <= after
    assert begin.time.utcoffset() == timedelta(0)


def test_scan_begin_derived_messages_keep_id_name_and_time(host_timezone):
    begin = model.ScanBegin(id=uuid.uuid4(), name='strelka')
    naive_noon = datetime(2026, 1, 2, 12, 0, 0)

    result = begin.get_result({'ok': True}, time=naive_noon)
    assert (result.id, result.name, result.time, result.result, result.error) == (
        begin.id,
        'strelka',
        NOON_UTC,
        {'ok': True},
        None,
    )
    assert begin.get_result(error=RuntimeError('boom')).error == 'boom'

    end = begin.get_end(time=naive_noon)
    timeout = begin.get_timeout(time=naive_noon)
    assert (end.id, end.name, end.time) == (begin.id, 'strelka', NOON_UTC)
    assert (timeout.id, timeout.name, timeout.time) == (begin.id, 'strelka', NOON_UTC)
    assert begin._key == end._key == timeout._key == f'{begin.id}:strelka'


###################################################################################################
# ECS octal and array types


@pytest.mark.parametrize(
    'value, expected',
    [
        ('755', 0o755),
        ('0755', 0o755),
        ('0', 0),
        ('', 0),
        (None, 0),
        (0, 0),
        (0o644, 0o644),
    ],
)
def test_octal_validate(value, expected):
    assert ecs._OctalInteger._validate(value) == expected


@pytest.mark.parametrize('value', ['8', '9', 'rwx', '0x1f'])
def test_octal_validate_rejects_non_octal_strings(value):
    with pytest.raises(ValueError):
        ecs._OctalInteger._validate(value)


@pytest.mark.parametrize('value, expected', [(0o755, '755'), (0o644, '644'), (0, '0'), (0o4755, '4755')])
def test_octal_serialize(value, expected):
    assert ecs._OctalInteger._serialize(value) == expected


@pytest.mark.parametrize('text', ['755', '644', '4755', '1777', '0'])
def test_octal_round_trip(text):
    assert ecs._OctalInteger._serialize(ecs._OctalInteger._validate(text)) == text


@pytest.mark.parametrize(
    'value, expected',
    [
        (None, []),
        ([], []),
        ([1, 2], [1, 2]),
        ('x', ['x']),
        (0, [0]),
        ({'a': 1}, [{'a': 1}]),
    ],
)
def test_array_make_list(value, expected):
    assert ecs.Array._make_list(value) == expected


def test_array_behaves_like_a_sequence():
    arr = ecs.Array(['a', 'b'])
    assert len(arr) == 2
    assert list(arr) == ['a', 'b']
    assert arr[1] == 'b'
    assert arr.in_record is True
    assert ecs.Array._to_list(arr) == ['a', 'b']
    assert repr(arr) == "['a', 'b']"


def test_array_missing_sentinel():
    assert ecs.Array.MISSING.in_record is False
    assert len(ecs.Array.MISSING) == 0


###################################################################################################
# utils.group_items


def test_group_items_without_groups():
    items = ['apple', 'avocado', 'banana', 'cherry', 'cranberry']
    assert dict(utils.group_items(items, key=lambda s: s[0])) == {
        'a': ['apple', 'avocado'],
        'b': ['banana'],
        'c': ['cherry', 'cranberry'],
    }


def test_group_items_with_wildcard_groups():
    items = [('strelka', 'begin'), ('strelka', 'end'), ('yara', 'begin'), ('yara', 'result')]
    grouped = dict(utils.group_items(items, key=lambda item: item, groups=[('strelka', ...), (..., 'begin'), ('x', ...)]))
    assert grouped == {
        ('strelka', ...): [('strelka', 'begin'), ('strelka', 'end')],
        (..., 'begin'): [('strelka', 'begin'), ('yara', 'begin')],
        ('x', ...): [],
    }


def test_group_items_preserves_requested_group_order():
    groups = [3, 1, 2]
    assert [g for g, _ in utils.group_items([1, 2, 3], key=lambda x: (x,), groups=[(g,) for g in groups])] == [
        (3,),
        (1,),
        (2,),
    ]


@pytest.mark.parametrize(
    'a, b, expected',
    [
        (('a', 'b'), ('a', 'b'), True),
        (('a', 'b'), ('a', ...), True),
        (('a', 'b'), (..., ...), True),
        (('a', 'b'), ('a', 'c'), False),
        ('a', 'a', False),
        (('a',), 'a', False),
    ],
)
def test_match_item(a, b, expected):
    assert utils.match_item(a, b) is expected
