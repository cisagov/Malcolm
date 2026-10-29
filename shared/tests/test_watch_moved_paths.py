"""A file moved within a watched tree should be queued only at its new path."""

from pathlib import Path
from unittest.mock import Mock

import pytest
from watchdog.events import FileClosedEvent, FileCreatedEvent, FileModifiedEvent, FileMovedEvent

import watch_common


@pytest.fixture(params=[False, True], ids=['native-events', 'polling'])
def handler(request):
    return watch_common.FileOperationEventHandler(logger=Mock(), polling=request.param)


@pytest.mark.parametrize('initial_event', [FileCreatedEvent, FileModifiedEvent, FileClosedEvent])
def test_move_between_watched_subdirectories_retires_source(handler, tmp_path, initial_event):
    source = tmp_path / 'incoming' / 'capture.pcap'
    target = tmp_path / 'ready' / 'capture.pcap'
    source.parent.mkdir()
    target.parent.mkdir()
    source.write_bytes(b'capture data')
    handler.on_any_event(initial_event(str(source)))

    source.rename(target)
    handler.on_any_event(FileMovedEvent(str(source), str(target)))

    with handler.deck as deck:
        queued = dict(deck)
    assert str(source) not in queued
    assert list(queued) == [str(target)]
    assert queued[str(target)][-1].operation == 'moved'
    assert queued[str(target)][-1].size == target.stat().st_size
    assert str(source) not in handler.modDeck
    assert str(target) not in handler.modDeck
    handler.logger.error.assert_not_called()


def test_same_directory_rename_still_retires_source(handler, tmp_path):
    source = tmp_path / 'upload.tmp'
    target = tmp_path / 'upload.pcap'
    source.write_bytes(b'capture data')
    handler.on_any_event(FileCreatedEvent(str(source)))
    source.rename(target)
    handler.on_any_event(FileMovedEvent(str(source), str(target)))

    with handler.deck as deck:
        queued = dict(deck)
    assert list(queued) == [str(target)]
    handler.logger.error.assert_not_called()


def test_move_from_untracked_directory_preserves_other_queued_files(handler, tmp_path):
    source = tmp_path / 'outside.pcap'
    target = tmp_path / 'ready' / 'capture.pcap'
    other = tmp_path / 'other.pcap'
    target.parent.mkdir()
    source.write_bytes(b'incoming')
    other.write_bytes(b'other capture')
    handler.on_any_event(FileCreatedEvent(str(other)))
    source.rename(target)
    handler.on_any_event(FileMovedEvent(str(source), str(target)))

    with handler.deck as deck:
        queued = dict(deck)
    assert set(queued) == {str(other), str(target)}
    handler.logger.error.assert_not_called()


def test_worker_processes_only_the_existing_destination(handler, tmp_path, monkeypatch):
    source = tmp_path / 'incoming' / 'upload.pcap'
    target = tmp_path / 'ready' / 'upload.pcap'
    source.parent.mkdir()
    target.parent.mkdir()
    source.write_bytes(b'capture data')
    handler.on_any_event(FileCreatedEvent(str(source)))
    source.rename(target)
    handler.on_any_event(FileMovedEvent(str(source), str(target)))

    processed = []
    observer = Mock()
    observer.is_alive.side_effect = [True, False]
    monkeypatch.setattr(watch_common.time, 'sleep', lambda _: None)
    watch_common.ProcessFileEventWorker(
        [handler, observer, processed.append, {}, 0, watch_common.AtomicInt(), [False], handler.logger]
    )

    assert processed == [str(target)]
    assert all(Path(path).is_file() for path in processed)
    with handler.deck as deck:
        queued = dict(deck)
    assert not queued
