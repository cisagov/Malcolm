"""Read-only access to a watched file must not change how the watcher tracks it.

watchdog 5+ reports IN_OPEN and IN_CLOSE_NOWRITE as FileOpenedEvent and FileClosedNoWriteEvent.
Reads by the watcher itself (libmagic) and by downstream processors (Arkime, Zeek, Suricata)
used to put a processed file back into the deck with a history that could never be processed,
which kept it there until deletion and caused a later same-name upload to be silently dropped.

These tests drive the real FileOperationEventHandler and ProcessFileEventWorker with synthetic
events and a fake clock, so no inotify watch, sleep or thread is involved.
"""

import logging
from unittest.mock import Mock

import pytest
from watchdog.events import (
    FileClosedEvent,
    FileClosedNoWriteEvent,
    FileCreatedEvent,
    FileModifiedEvent,
    FileOpenedEvent,
)

import watch_common
from malcolm_utils import AtomicInt

ASSUME_CLOSED_SEC = 10
# worker sleeps grow 0.5, 1.5, 2.5, ... capped at 5, so 8 sleeps carry the clock well past the quiet period
SLEEPS_PAST_QUIET_PERIOD = 8


class FakeClock:
    """Stands in for the time module in watch_common; sleep() advances the clock and spends a budget.

    The worker calls the file processor while holding the deck lock, so events a processor causes
    can't be delivered from inside it. In production the observer thread delivers them once the lock
    is released; here they're queued with later() and delivered on the worker's next sleep, which
    happens outside the lock.
    """

    def __init__(self):
        self.now = 1_800_000_000.0
        self.budget = 0
        self.shutdown = [False]
        self.pending = []

    def later(self, callback):
        self.pending.append(callback)

    def time(self):
        return self.now

    def sleep(self, seconds):
        self.now += seconds
        while self.pending:
            self.pending.pop(0)()
        self.budget -= 1
        if self.budget <= 0:
            self.shutdown[0] = True


@pytest.fixture
def clock(monkeypatch):
    fake = FakeClock()
    monkeypatch.setattr(watch_common, 'time', fake)
    return fake


@pytest.fixture
def handler(clock):
    return watch_common.FileOperationEventHandler(logger=logging.getLogger(__name__), polling=False)


@pytest.fixture
def capture(tmp_path):
    path = tmp_path / 'fixture.pcap'
    path.write_bytes(b'\0' * 100)
    return str(path)


def read(handler, path):
    """What any reader (libmagic, capture-offline, zeek) looks like to inotify."""
    handler.on_any_event(FileOpenedEvent(path))
    handler.on_any_event(FileClosedNoWriteEvent(path))


def run_worker(handler, clock, processor, sleeps=SLEEPS_PAST_QUIET_PERIOD):
    clock.budget = sleeps
    clock.shutdown[0] = False
    observer = Mock()
    observer.is_alive.return_value = True
    watch_common.ProcessFileEventWorker(
        [handler, observer, processor, {}, ASSUME_CLOSED_SEC, AtomicInt(value=0), clock.shutdown, None]
    )


def tracked(handler):
    return set(handler.deck.keys()) | set(handler.modDeck.keys())


def test_processing_reads_do_not_requeue_the_file(handler, clock, capture):
    """The watcher's own reads of a file it just processed must leave nothing behind."""
    processed = []

    def processor(path, **kwargs):
        processed.append(path)
        clock.later(lambda: read(handler, path))

    handler.on_any_event(FileCreatedEvent(capture))
    run_worker(handler, clock, processor)
    assert processed == [capture]
    assert tracked(handler) == set()


def test_downstream_reads_do_not_requeue_the_file(handler, clock, capture):
    """Processors reading a published file must not put it back into the deck."""
    handler.on_any_event(FileCreatedEvent(capture))
    run_worker(handler, clock, lambda path, **kwargs: None)
    for _ in range(3):
        read(handler, capture)
    assert tracked(handler) == set()


def test_same_name_upload_is_processed_again(handler, clock, capture):
    """A file moved in over an already processed one, after it has been read, is still processed."""
    processed = []

    def processor(path, **kwargs):
        processed.append(path)
        clock.later(lambda: read(handler, path))

    handler.on_any_event(FileCreatedEvent(capture))
    run_worker(handler, clock, processor)
    read(handler, capture)

    handler.on_any_event(FileCreatedEvent(capture))
    run_worker(handler, clock, processor)
    assert processed == [capture, capture]
    assert tracked(handler) == set()


def test_read_before_processing_does_not_block_moved_in_file(handler, clock, capture):
    """A moved-in file that something reads during its quiet period is still processed."""
    processed = []
    handler.on_any_event(FileCreatedEvent(capture))
    read(handler, capture)
    run_worker(handler, clock, lambda path, **kwargs: processed.append(path))
    assert processed == [capture]


def test_file_written_in_place_is_processed_on_close(handler, clock, tmp_path):
    """Control: a file written in place still waits for its close-write and is processed then."""
    path = tmp_path / 'written.pcap'
    path.write_bytes(b'')
    capture = str(path)
    processed = []

    handler.on_any_event(FileCreatedEvent(capture))
    for size in (100, 200):
        path.write_bytes(b'\0' * size)
        handler.on_any_event(FileModifiedEvent(capture))
    read(handler, capture)

    run_worker(handler, clock, lambda path, **kwargs: processed.append(path))
    assert processed == []

    handler.on_any_event(FileClosedEvent(capture))
    run_worker(handler, clock, lambda path, **kwargs: processed.append(path), sleeps=2)
    assert processed == [capture]


def test_open_writer_with_nothing_written_is_not_processed(handler, clock, tmp_path):
    """A file created in place and held open before its first write (tcpdump -w buffering its header) waits for its close."""
    path = tmp_path / 'live.pcap'
    path.write_bytes(b'')
    capture = str(path)
    processed = []

    handler.on_any_event(FileCreatedEvent(capture))
    handler.on_any_event(FileOpenedEvent(capture))
    run_worker(handler, clock, lambda path, **kwargs: processed.append(path))
    assert processed == []

    path.write_bytes(b'\0' * 100)
    handler.on_any_event(FileModifiedEvent(capture))
    handler.on_any_event(FileClosedEvent(capture))
    run_worker(handler, clock, lambda path, **kwargs: processed.append(path), sleeps=2)
    assert processed == [capture]


def test_reader_closing_does_not_release_an_open_writer(handler, clock, tmp_path):
    """Overlapping opens are counted separately, so a reader's close can't cancel the writer's open."""
    path = tmp_path / 'live.pcap'
    path.write_bytes(b'')
    capture = str(path)
    processed = []

    handler.on_any_event(FileCreatedEvent(capture))
    handler.on_any_event(FileOpenedEvent(capture))  # writer
    read(handler, capture)  # reader opens and closes while the writer holds it
    handler.on_any_event(FileOpenedEvent(capture))  # second reader opens...
    handler.on_any_event(FileOpenedEvent(capture))  # ...and a third, before either closes
    handler.on_any_event(FileClosedNoWriteEvent(capture))
    handler.on_any_event(FileClosedNoWriteEvent(capture))
    run_worker(handler, clock, lambda path, **kwargs: processed.append(path))
    assert processed == []

    handler.on_any_event(FileClosedEvent(capture))
    run_worker(handler, clock, lambda path, **kwargs: processed.append(path), sleeps=2)
    assert processed == [capture]


def test_overlapping_readers_leave_nothing_behind(handler, clock, capture):
    """Concurrent readers of a processed file (e.g., Arkime and Zeek at once) are all retracted."""
    handler.on_any_event(FileCreatedEvent(capture))
    run_worker(handler, clock, lambda path, **kwargs: None)
    for _ in range(3):
        handler.on_any_event(FileOpenedEvent(capture))
    for _ in range(3):
        handler.on_any_event(FileClosedNoWriteEvent(capture))
    assert tracked(handler) == set()
