"""A one-entry Filebeat registry must not abort log cleanup."""

import importlib.util
import json
import os
from pathlib import Path
from unittest.mock import Mock

import pytest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('cleanup_registry', ROOT / 'filebeat/scripts/clean-processed-folder.py')
cleanup = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cleanup)


def record(device, inode):
    return {'k': 'filebeat::logs::fixture', 'v': {'FileStateOS': {'device': device, 'inode': inode}}}


@pytest.mark.parametrize('layout', ['object', 'line', 'pretty', 'array', 'jsonl'])
@pytest.mark.parametrize('as_strings', [False, True])
def test_registry_shapes_return_the_same_file_identity(tmp_path, layout, as_strings):
    value = record('7' if as_strings else 7, '42' if as_strings else 42)
    contents = {
        'object': json.dumps(value),
        'line': json.dumps(value) + '\n',
        'pretty': json.dumps(value, indent=2),
        'array': json.dumps([value]),
        'jsonl': json.dumps({'op': 'set'}) + '\n' + json.dumps(value) + '\n',
    }[layout]
    path = tmp_path / 'registry.json'
    path.write_text(contents)
    assert cleanup.load_filebeat_registries([str(path)]) == [(7, 42)]


def test_multiple_registries_combine_single_and_multi_record_files(tmp_path):
    first = tmp_path / 'first.json'
    second = tmp_path / 'second.json'
    first.write_text(json.dumps(record(7, 42)))
    second.write_text(json.dumps([record(8, 43), record(8, 44)]))
    assert cleanup.load_filebeat_registries([str(first), str(second)]) == [(7, 42), (8, 43), (8, 44)]


@pytest.mark.parametrize('value', [{'op': 'set'}, {'v': {'FileStateOS': {'device': 7}}}, {}])
def test_records_without_a_complete_file_identity_are_ignored(tmp_path, value):
    path = tmp_path / 'registry.json'
    path.write_text(json.dumps(value))
    assert cleanup.load_filebeat_registries([str(path)]) == []


def test_empty_and_missing_registry_files_keep_existing_behavior(tmp_path):
    path = tmp_path / 'empty.json'
    path.write_text('')
    assert cleanup.load_filebeat_registries([str(path), str(tmp_path / 'missing.json')]) == []


@pytest.mark.parametrize('layout', ['object', 'array'])
def test_real_cleanup_protects_registered_log_and_removes_only_expired_unregistered_log(tmp_path, monkeypatch, layout):
    processed = tmp_path / 'processed'
    processed.mkdir()
    protected = processed / 'protected.log'
    expired = processed / 'expired.log'
    for path in [protected, expired]:
        path.write_text('Example plaintext log record for isolated cleanup test.\n')
        os.utime(path, (1760000000, 1760000000))
    st = protected.stat()
    value = record(st.st_dev, st.st_ino)
    registry = tmp_path / 'registry.json'
    registry.write_text(json.dumps(value if layout == 'object' else [value]))
    for name, value in {
        'now_time': 1760010000,
        'clean_log_seconds': 60,
        'clean_zip_seconds': 120,
        'filebeat_registry_filenames': [str(registry)],
        'zeek_processed_dir': str(processed),
        'zeek_live_dir': str(tmp_path / 'live'),
        'zeek_current_dir': str(tmp_path / 'current'),
        'suricata_dir': str(tmp_path / 'suricata'),
        'filescan_dir': str(tmp_path / 'filescan'),
    }.items():
        monkeypatch.setattr(cleanup, name, value)
    fuser = Mock(return_value=Mock(returncode=1))
    monkeypatch.setattr(cleanup.subprocess, 'run', fuser)
    cleanup.prune_files()
    assert protected.exists()
    assert not expired.exists()
    fuser.assert_called_once()
    assert fuser.call_args.args[0] == ['fuser', '-s', str(expired)]
