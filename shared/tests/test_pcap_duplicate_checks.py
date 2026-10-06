"""PCAP duplicate checks are independent of optional startup health waiting."""

import json
from pathlib import Path
import struct
import sys
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts'))
sys.path.insert(0, str(ROOT / 'shared' / 'bin'))

import pcap_watcher  # noqa: E402 - standalone scripts require their source paths


@pytest.fixture
def watcher_factory(monkeypatch, tmp_path):
    """Use real watcher logic without opening database or publisher sockets."""
    client = Mock()
    client.cluster.health.return_value = {'status': 'green'}
    database = Mock(return_value=client)
    publisher = Mock()
    context = Mock()
    context.socket.return_value = publisher
    query = Mock()
    query.filter.return_value = query
    query.query.return_value = query
    search = Mock(return_value=query)
    for name, value in {
        'DatabaseClass': database,
        'DatabaseInitArgs': {},
        'SearchClass': search,
        'ConnectionError': ConnectionError,
        'ConnectionTimeout': TimeoutError,
        'AuthenticationException': PermissionError,
        'shuttingDown': [False],
    }.items():
        monkeypatch.setattr(pcap_watcher, name, value)
    monkeypatch.setattr(pcap_watcher.zmq, 'Context', Mock(return_value=context))
    monkeypatch.setattr(pcap_watcher.time, 'sleep', lambda unused: None)

    def create(wait=False, enabled=True, connected=True):
        options = SimpleNamespace(
            opensearchUrl='https://search.example' if enabled else '',
            opensearchMode='opensearch-local',
            opensearchWaitForHealth=wait,
            baseDir=str(tmp_path),
            nodeName='fixture',
            minBytes=24,
            maxBytes=2048,
            includeAbsolutePath=False,
        )
        monkeypatch.setattr(pcap_watcher, 'args', options)
        if not connected:
            database.side_effect = ConnectionRefusedError('offline fixture')
        watcher = pcap_watcher.EventWatcher(logger=Mock())
        return SimpleNamespace(
            watcher=watcher, client=client, publisher=publisher, search=search, query=query, database=database
        )

    return create


@pytest.fixture
def pcap_path(tmp_path):
    """Generate only a valid PCAP global header, using real file recognition."""
    path = tmp_path / 'fixture.pcap'
    path.write_bytes(struct.pack('<IHHIIII', 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    return path


@pytest.mark.parametrize('wait', [False, True])
def test_connected_database_enables_duplicate_checks(watcher_factory, wait):
    """Keep database use enabled in both supported startup modes."""
    state = watcher_factory(wait=wait)
    assert state.watcher.useOpenSearch
    assert state.watcher.openSearchClient is state.client
    index_waits = [call for call in state.client.cluster.health.call_args_list if 'index' in call.kwargs]
    assert len(index_waits) == int(wait)


@pytest.mark.parametrize('wait', [False, True])
@pytest.mark.parametrize('duplicate', [False, True])
def test_duplicate_file_is_not_republished(watcher_factory, pcap_path, wait, duplicate):
    """Use the existing duplicate result before publishing a capture."""
    state = watcher_factory(wait=wait)
    state.query.execute.return_value = [Mock(to_dict=Mock(return_value={'filesize': 24}))] if duplicate else []
    state.watcher.processFile(str(pcap_path))
    state.search.assert_called_once_with(using=state.client, index=pcap_watcher.ARKIME_FILES_INDEX)
    state.query.execute.assert_called_once_with()
    if duplicate:
        state.publisher.send_string.assert_not_called()
    else:
        state.publisher.send_string.assert_called_once()
        value = json.loads(state.publisher.send_string.call_args.args[0])
        assert value['name'] == 'fixture.pcap'
        assert value['size'] == 24


@pytest.mark.parametrize('prior_size', [None, 25])
def test_nonmatching_file_size_is_still_published(watcher_factory, pcap_path, prior_size):
    """A different size or absent size does not establish a duplicate."""
    state = watcher_factory()
    record = {} if prior_size is None else {'filesize': prior_size}
    state.query.execute.return_value = [Mock(to_dict=Mock(return_value=record))]
    state.watcher.processFile(str(pcap_path))
    state.query.execute.assert_called_once()
    state.publisher.send_string.assert_called_once()


@pytest.mark.parametrize('enabled,connected', [(False, True), (True, False)])
def test_unconfigured_or_unavailable_database_keeps_offline_behavior(watcher_factory, pcap_path, enabled, connected):
    """Preserve no-database processing when connection is unavailable."""
    state = watcher_factory(enabled=enabled, connected=connected)
    assert not state.watcher.useOpenSearch
    state.watcher.processFile(str(pcap_path))
    state.search.assert_not_called()
    state.publisher.send_string.assert_called_once()


def test_rejected_file_does_not_query_or_publish(watcher_factory, tmp_path):
    """Noncapture files remain outside the duplicate and publishing paths."""
    state = watcher_factory()
    path = tmp_path / 'not-a-capture.txt'
    path.write_text('This is a text file, not a packet capture.')
    state.watcher.processFile(str(path))
    state.search.assert_not_called()
    state.publisher.send_string.assert_not_called()
