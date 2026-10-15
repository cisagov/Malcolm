"""Offline watchdog event-regression tests for Malcolm file processing."""

from unittest.mock import Mock

import pytest
from watchdog.events import (
    DirCreatedEvent,
    FileClosedEvent,
    FileCreatedEvent,
    FileDeletedEvent,
    FileModifiedEvent,
    FileMovedEvent,
    FileOpenedEvent,
)

import watch_common


@pytest.fixture
def handler(monkeypatch):
    monkeypatch.setattr(watch_common.time, 'time', lambda: 12345)
    logger = Mock()
    return watch_common.FileOperationEventHandler(logger=logger, polling=False)


def events(handler, name):
    with handler.deck as deck:
        return list(deck.get(str(name), []))


def test_directory_events_are_ignored(handler, tmp_path):
    handler.on_any_event(DirCreatedEvent(str(tmp_path)))
    with handler.deck as deck:
        assert not deck
    assert not handler.modDeck


def test_created_file_enters_main_deck(handler, tmp_path):
    path = tmp_path / 'capture.pcap'
    path.write_bytes(b'hello')
    handler.on_any_event(FileCreatedEvent(str(path)))
    assert events(handler, path) == [watch_common.OperationEvent(12345, 'created', 5)]
    assert not handler.modDeck


def test_same_event_is_coalesced_and_updated(handler, monkeypatch, tmp_path):
    path = tmp_path / 'capture.pcap'
    path.write_bytes(b'hello')
    handler.on_any_event(FileCreatedEvent(str(path)))
    monkeypatch.setattr(watch_common.time, 'time', lambda: 12346)
    handler.on_any_event(FileCreatedEvent(str(path)))
    assert events(handler, path) == [watch_common.OperationEvent(12346, 'created', 5)]


def test_equal_size_modification_does_not_refresh_main_deck(handler, monkeypatch, tmp_path):
    path = tmp_path / 'capture.pcap'
    path.write_bytes(b'abc')
    handler.on_any_event(FileCreatedEvent(str(path)))
    monkeypatch.setattr(watch_common.time, 'time', lambda: 12346)
    handler.on_any_event(FileModifiedEvent(str(path)))
    assert events(handler, path) == [watch_common.OperationEvent(12345, 'created', 3)]


def test_modified_with_new_size_appends_to_main_deck(handler, tmp_path):
    path = tmp_path / 'capture.pcap'
    path.write_bytes(b'a')
    handler.on_any_event(FileCreatedEvent(str(path)))
    path.write_bytes(b'ab')
    handler.on_any_event(FileModifiedEvent(str(path)))
    assert [entry.operation for entry in events(handler, path)] == ['created', 'modified']
    assert events(handler, path)[-1].size == 2


def test_open_first_is_staged_then_real_size_change_promotes(handler, tmp_path):
    path = tmp_path / 'capture.pcap'
    path.write_bytes(b'abc')
    handler.on_any_event(FileOpenedEvent(str(path)))
    assert str(path) in handler.modDeck
    assert not events(handler, path)
    handler.on_any_event(FileModifiedEvent(str(path)))
    assert not events(handler, path)
    assert handler.modDeck[str(path)][-1].operation == 'modified'
    path.write_bytes(b'abcdef')
    handler.on_any_event(FileModifiedEvent(str(path)))
    assert str(path) not in handler.modDeck
    assert [entry.operation for entry in events(handler, path)] == ['opened', 'modified', 'modified']
    assert events(handler, path)[-1].size == 6


def test_first_modified_is_staged_until_size_changes(handler, tmp_path):
    path = tmp_path / 'capture.pcap'
    path.write_bytes(b'xyz')
    handler.on_any_event(FileModifiedEvent(str(path)))
    handler.on_any_event(FileModifiedEvent(str(path)))
    assert len(handler.modDeck[str(path)]) == 1
    assert not events(handler, path)
    path.write_bytes(b'xyzq')
    handler.on_any_event(FileModifiedEvent(str(path)))
    assert len(events(handler, path)) == 2
    assert events(handler, path)[-1].size == 4


def test_file_closed_event_prompts_immediate_priority(handler, tmp_path):
    first = tmp_path / 'first.pcap'
    second = tmp_path / 'second.pcap'
    first.write_bytes(b'hello')
    second.write_bytes(b'bye')
    handler.on_any_event(FileCreatedEvent(str(first)))
    handler.on_any_event(FileCreatedEvent(str(second)))
    handler.on_any_event(FileClosedEvent(str(second)))
    with handler.deck as deck:
        assert list(deck)[0] == str(second)
        assert deck[str(second)][-1].timestamp == 0


def test_delete_removes_tracked_file(handler, tmp_path):
    path = tmp_path / 'capture.pcap'
    path.write_bytes(b'hello')
    handler.on_any_event(FileCreatedEvent(str(path)))
    path.unlink()
    handler.on_any_event(FileDeletedEvent(str(path)))
    assert not events(handler, path)
    assert str(path) not in handler.modDeck


def test_delete_removes_staged_file(handler, tmp_path):
    path = tmp_path / 'capture.pcap'
    path.write_bytes(b'hello')
    handler.on_any_event(FileOpenedEvent(str(path)))
    path.unlink()
    handler.on_any_event(FileDeletedEvent(str(path)))
    assert str(path) not in handler.modDeck
    assert not events(handler, path)


def test_rename_within_watched_directory_drops_source(handler, tmp_path):
    source = tmp_path / 'old.pcap'
    target = tmp_path / 'new.pcap'
    source.write_bytes(b'hello')
    handler.on_any_event(FileCreatedEvent(str(source)))
    source.rename(target)
    handler.on_any_event(FileMovedEvent(str(source), str(target)))
    assert not events(handler, source)
    assert events(handler, target)[-1].operation == 'moved'


def test_move_between_watched_directories_drops_stale_source(handler, tmp_path):
    source_dir = tmp_path / 'source'
    target_dir = tmp_path / 'target'
    source_dir.mkdir()
    target_dir.mkdir()
    source = source_dir / 'capture.pcap'
    target = target_dir / source.name
    source.write_bytes(b'hello')
    handler.on_any_event(FileCreatedEvent(str(source)))
    source.rename(target)
    handler.on_any_event(FileMovedEvent(str(source), str(target)))
    assert not events(handler, source)  # Old path must not be processed as a separate file
    assert events(handler, target)[-1].operation == 'moved'


def test_move_clears_old_staging_entry_across_directories(handler, tmp_path):
    source_dir = tmp_path / 'source'
    target_dir = tmp_path / 'target'
    source_dir.mkdir()
    target_dir.mkdir()
    source = source_dir / 'capture.pcap'
    target = target_dir / 'capture.pcap'
    source.write_bytes(b'hello')
    handler.on_any_event(FileOpenedEvent(str(source)))
    source.rename(target)
    handler.on_any_event(FileMovedEvent(str(source), str(target)))
    assert str(source) not in handler.modDeck
    assert events(handler, target)[-1].operation == 'moved'


def test_missing_file_size_is_zero_without_exception(handler, tmp_path):
    path = tmp_path / 'disappeared.pcap'
    handler.on_any_event(FileCreatedEvent(str(path)))
    assert events(handler, path)[-1].size == 0
    handler.logger.error.assert_not_called()


def test_unrelated_move_does_not_clear_other_files(handler, tmp_path):
    existing = tmp_path / 'existing.pcap'
    existing.write_bytes(b'x')
    handler.on_any_event(FileCreatedEvent(str(existing)))
    source = tmp_path / 'unseen.pcap'
    target = tmp_path / 'new.pcap'
    target.write_bytes(b'z')
    handler.on_any_event(FileMovedEvent(str(source), str(target)))
    assert events(handler, existing)[-1].operation == 'created'
    assert events(handler, target)[-1].operation == 'moved'


def test_moved_event_with_no_destination_does_not_record_an_invalid_path(handler, tmp_path):
    source = tmp_path / 'moved-out.pcap'
    source.write_bytes(b'hello')
    handler.on_any_event(FileMovedEvent(str(source), None))
    with handler.deck as deck:
        assert not deck
    assert not handler.modDeck
    handler.logger.error.assert_not_called()
