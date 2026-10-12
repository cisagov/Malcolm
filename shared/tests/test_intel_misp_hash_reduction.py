"""MISP context values (file names alongside hashes, to_ids=False attributes) don't become intel items of their own."""

import io

import pytest

for _module in ('antlr4', 'stix2', 'stix2patterns', 'pymisp', 'taxii2client', 'mandiant_threatintel', 'vt'):
    pytest.importorskip(_module)

from pymisp import MISPAttribute, MISPEvent, MISPObject

import zeek_threat_feed_utils as feeds

MD5 = '0123456789abcdef0123456789abcdef'
SHA1 = '0123456789abcdef0123456789abcdef01234567'
TS = 1782961445  # 2026-07-02T03:04:05Z


def attribute(attr_type, value, to_ids=True):
    attr = MISPAttribute()
    attr.from_dict(type=attr_type, value=value, category='Payload delivery', timestamp=TS, to_ids=to_ids)
    return attr


def printed_rows(event, printer_default=feeds.MISP_REQUIRE_TO_IDS_DEFAULT, **process_kwargs):
    output = io.StringIO()
    printer = feeds.FeedParserZeekPrinter(
        extended=False, notice=False, cif=False, file=output, misp_require_to_ids=printer_default
    )
    assert printer.ProcessMISP(event.to_dict(), **process_kwargs)
    lines = output.getvalue().splitlines()
    if not lines:
        return []
    header = lines[0].split('\t')[1:]
    return [dict(zip(header, line.split('\t'))) for line in lines[1:]]


@pytest.mark.parametrize('hash_type,hash_value', [('md5', MD5), ('sha1', SHA1)])
def test_composite_filename_hash_emits_only_the_hash(hash_type, hash_value):
    rows = feeds.map_misp_attribute_to_zeek(
        attribute(f'filename|{hash_type}', f'update.exe|{hash_value}'), description='Event info'
    )
    assert [(row['indicator'], row['indicator_type']) for row in rows] == [(hash_value, 'Intel::FILE_HASH')]
    assert rows[0]['meta.desc'] == f'Event info. {feeds.MISP_REDUCED_COMPOSITE_NOTE} filename|{hash_type} (filename: update.exe)'


def test_composite_file_name_containing_a_pipe_keeps_the_hash_intact():
    rows = feeds.map_misp_attribute_to_zeek(attribute('filename|md5', f'a|b.exe|{MD5}'))
    assert [row['indicator'] for row in rows] == [MD5]
    assert 'filename: a|b.exe' in rows[0]['meta.desc']


def test_standalone_filename_attribute_is_unchanged():
    rows = feeds.map_misp_attribute_to_zeek(attribute('filename', 'update.exe'), description='Event info')
    assert [(row['indicator'], row['indicator_type'], row['meta.desc']) for row in rows] == [
        ('update.exe', 'Intel::FILE_NAME', 'Event info')
    ]


def test_file_object_with_hashes_emits_only_hashes():
    event = MISPEvent()
    event.info = 'Event info'
    event.add_attribute(type='domain', value='evil.example', category='Network activity', timestamp=TS, to_ids=True)
    obj = MISPObject('file')
    obj.add_attribute('filename', value='update.exe', category='Payload delivery', timestamp=TS, to_ids=True)
    obj.add_attribute('md5', value=MD5, category='Payload delivery', timestamp=TS, to_ids=True)
    obj.add_attribute('sha1', value=SHA1, category='Payload delivery', timestamp=TS, to_ids=True)
    event.add_object(obj)

    rows = printed_rows(event)
    assert [row['indicator'] for row in rows] == ['evil.example', MD5, SHA1]
    assert feeds.MISP_REDUCED_OBJECT_NOTE not in rows[0]['meta.desc']
    for row in rows[1:]:
        assert f'{feeds.MISP_REDUCED_OBJECT_NOTE} file ({obj.uuid})' in row['meta.desc']


def test_file_object_without_a_hash_keeps_its_file_name():
    event = MISPEvent()
    event.info = 'Event info'
    obj = MISPObject('file')
    obj.add_attribute('filename', value='update.exe', category='Payload delivery', timestamp=TS, to_ids=True)
    event.add_object(obj)

    rows = printed_rows(event)
    assert [(row['indicator'], row['indicator_type']) for row in rows] == [('update.exe', 'Intel::FILE_NAME')]
    assert feeds.MISP_REDUCED_OBJECT_NOTE not in rows[0]['meta.desc']


def context_event():
    event = MISPEvent()
    event.info = 'Event info'
    event.add_attribute(type='url', value='evil.example/payload', category='Network activity', timestamp=TS, to_ids=True)
    event.add_attribute(type='ip-dst', value='93.184.216.34', category='Network activity', timestamp=TS, to_ids=False)
    event.add_attribute(type='filename', value='update.exe', category='Payload delivery', timestamp=TS, to_ids=False)
    return event


def test_context_attributes_are_skipped_by_default():
    rows = printed_rows(context_event())
    assert [row['indicator'] for row in rows] == ['evil.example/payload']


def test_printer_default_can_keep_context_attributes():
    rows = printed_rows(context_event(), printer_default=False)
    assert [row['indicator'] for row in rows] == ['evil.example/payload', '93.184.216.34', 'update.exe']


@pytest.mark.parametrize('printer_default,per_feed,expected', [(True, False, 3), (False, True, 1)])
def test_per_feed_setting_overrides_the_printer_default(printer_default, per_feed, expected):
    rows = printed_rows(context_event(), printer_default=printer_default, require_to_ids=per_feed)
    assert len(rows) == expected


def test_context_hash_does_not_suppress_the_objects_detection_attributes():
    event = MISPEvent()
    event.info = 'Event info'
    obj = MISPObject('file')
    obj.add_attribute('filename', value='/tmp/.applock', category='Payload delivery', timestamp=TS, to_ids=True)
    obj.add_attribute('md5', value=MD5, category='Payload delivery', timestamp=TS, to_ids=False)
    event.add_object(obj)

    rows = printed_rows(event)
    assert [(row['indicator'], row['indicator_type']) for row in rows] == [('/tmp/.applock', 'Intel::FILE_NAME')]
    assert feeds.MISP_REDUCED_OBJECT_NOTE not in rows[0]['meta.desc']
