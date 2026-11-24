"""watch_common recovers from an inotify queue overflow instead of losing files.

watchdog 7.1.1 sends EventsLostEvent to each watch once the kernel's inotify queue has overflowed
and the watches are repaired. Before, an overflow passed silently, and a file whose close-write
was among the dropped events stayed in the deck until it was deleted, while a file whose events
were all dropped was never seen. FileOperationEventHandler.on_events_lost now marks tracked files
so ProcessFileEventWorker processes them after the quiet period, and rescans the watched directory
for files it never heard about.

Like test_watch_common_read_events.py, these drive the real handler and worker with synthetic
events and a fake clock. The clock starts at the real time because the rescan_changed_only cutoff
compares it with real file ctimes, which can't be set.
"""

import os
import time
from unittest.mock import Mock

import pytest
from watchdog.events import EventsLostEvent, FileClosedEvent, FileCreatedEvent, FileModifiedEvent, FileOpenedEvent

import watch_common
from malcolm_utils import AtomicInt

ASSUME_CLOSED_SEC = 10
# worker sleeps grow 0.5, 1.5, 2.5, ... capped at 5, so 8 sleeps carry the clock well past the quiet period
SLEEPS_PAST_QUIET_PERIOD = 8


class FakeClock:
    """Stands in for the time module in watch_common; sleep() advances the clock and spends a budget."""

    def __init__(self):
        self.now = float(int(time.time()))
        self.budget = 0
        self.shutdown = [False]

    def time(self):
        return self.now

    def sleep(self, seconds):
        self.now += seconds
        self.budget -= 1
        if self.budget <= 0:
            self.shutdown[0] = True


@pytest.fixture
def clock(monkeypatch):
    fake = FakeClock()
    monkeypatch.setattr(watch_common, 'time', fake)
    return fake


@pytest.fixture
def watched(tmp_path):
    path = tmp_path / 'watched'
    path.mkdir()
    return path


def make_handler(**kwargs):
    return watch_common.FileOperationEventHandler(logger=Mock(), polling=False, **kwargs)


@pytest.fixture
def handler(clock):
    return make_handler()


def run_worker(handler, clock, sleeps=SLEEPS_PAST_QUIET_PERIOD):
    processed = []
    clock.budget = sleeps
    clock.shutdown[0] = False
    observer = Mock()
    observer.is_alive.return_value = True
    watch_common.ProcessFileEventWorker(
        [
            handler,
            observer,
            lambda path, **kwargs: processed.append(path),
            {},
            ASSUME_CLOSED_SEC,
            AtomicInt(value=0),
            clock.shutdown,
            None,
        ]
    )
    return processed


def lose_events(handler, directory):
    # through dispatch, so the base class routes it to on_any_event and then on_events_lost
    handler.dispatch(EventsLostEvent(str(directory), is_directory=True))


def tracked(handler):
    return set(handler.deck.keys()) | set(handler.modDeck.keys())


def history(handler, path):
    # a copy of the file's history, taken under the deck lock
    with handler.deck as deck:
        return list(deck[str(path)])


def write_in_place(handler, path, size=100):
    """A file created and written in the watched directory, still waiting for its close-write."""
    path.write_bytes(b'')
    handler.on_any_event(FileCreatedEvent(str(path)))
    path.write_bytes(b'\0' * size)
    handler.on_any_event(FileModifiedEvent(str(path)))


def test_file_whose_close_was_lost_is_processed_after_quiet_period(handler, clock, watched):
    capture = watched / 'written.pcap'
    write_in_place(handler, capture)
    # the close-write is dropped in the overflow, so without recovery the file waits forever
    assert run_worker(handler, clock) == []

    lose_events(handler, watched)

    assert run_worker(handler, clock) == [str(capture)]
    assert tracked(handler) == set()
    handler.logger.warning.assert_called_once()


def test_staged_file_whose_writes_were_lost_is_processed(handler, clock, watched):
    capture = watched / 'staged.pcap'
    capture.write_bytes(b'')
    handler.on_any_event(FileOpenedEvent(str(capture)))
    assert str(capture) in handler.modDeck
    # its writes and close-write are dropped
    capture.write_bytes(b'\0' * 100)
    assert run_worker(handler, clock) == []

    lose_events(handler, watched)

    assert str(capture) not in handler.modDeck
    assert run_worker(handler, clock) == [str(capture)]


def test_file_with_every_event_lost_is_found_by_rescan(handler, clock, watched):
    capture = watched / 'unseen.pcap'
    capture.write_bytes(b'\0' * 100)

    lose_events(handler, watched)

    assert tracked(handler) == {str(capture)}
    assert run_worker(handler, clock) == [str(capture)]


def test_writer_still_going_after_the_loss_waits_for_its_close(handler, clock, watched):
    capture = watched / 'live.pcap'
    write_in_place(handler, capture)
    lose_events(handler, watched)

    # the repaired watch reports more writes, so the file is back to waiting for a close-write
    capture.write_bytes(b'\0' * 200)
    handler.on_any_event(FileModifiedEvent(str(capture)))
    assert run_worker(handler, clock) == []

    handler.on_any_event(FileClosedEvent(str(capture)))
    assert run_worker(handler, clock, sleeps=2) == [str(capture)]


def test_closed_file_stays_ready_to_process(handler, clock, watched):
    capture = watched / 'closed.pcap'
    write_in_place(handler, capture)
    handler.on_any_event(FileClosedEvent(str(capture)))

    lose_events(handler, watched)

    assert history(handler, capture)[-1].operation == 'closed'
    assert history(handler, capture)[-1].timestamp == 0
    assert run_worker(handler, clock, sleeps=2) == [str(capture)]


def test_tracked_file_that_no_longer_exists_is_dropped(handler, clock, watched):
    capture = watched / 'gone.pcap'
    write_in_place(handler, capture)
    # its delete (or move out of the tree) is dropped
    capture.unlink()

    lose_events(handler, watched)

    assert tracked(handler) == set()


def test_repeated_report_of_the_same_overflow_marks_once(handler, clock, watched):
    capture = watched / 'written.pcap'
    write_in_place(handler, capture)

    lose_events(handler, watched)
    lose_events(handler, watched)

    operations = [op.operation for op in history(handler, capture)]
    assert operations.count(watch_common.EVENT_TYPE_EVENTS_LOST) == 1


@pytest.mark.parametrize('recursive', [False, True], ids=['non-recursive', 'recursive'])
def test_files_outside_the_reported_watch_are_untouched(clock, tmp_path, watched, recursive):
    handler = make_handler(recursive=recursive)
    other = tmp_path / 'other'
    other.mkdir()
    elsewhere = other / 'written.pcap'
    write_in_place(handler, elsewhere)

    lose_events(handler, watched)

    assert history(handler, elsewhere)[-1].operation == 'modified'
    assert run_worker(handler, clock) == []


def test_non_recursive_report_leaves_subdirectory_files_alone(handler, clock, watched):
    # pcap_watcher --recursive-directory schedules several directories non-recursively, and one
    # can sit inside another; each gets its own report, so this one mustn't touch the other's files
    nested = watched / 'sub' / 'written.pcap'
    nested.parent.mkdir()
    write_in_place(handler, nested)

    lose_events(handler, watched)

    assert history(handler, nested)[-1].operation == 'modified'


@pytest.mark.parametrize('recursive', [False, True], ids=['non-recursive', 'recursive'])
def test_rescan_depth_follows_the_watch(clock, watched, recursive):
    handler = make_handler(recursive=recursive)
    nested = watched / 'sub' / 'nested.pcap'
    nested.parent.mkdir()
    nested.write_bytes(b'\0' * 100)
    top = watched / 'top.pcap'
    top.write_bytes(b'\0' * 100)

    lose_events(handler, watched)

    expected = {str(top), str(nested)} if recursive else {str(top)}
    assert tracked(handler) == expected


def test_changed_only_rescan_skips_files_untouched_since_the_last_event(clock, watched):
    # pcap_watcher: processed captures stay in the directory and must not be queued again
    processed = watched / 'processed.pcap'
    processed.write_bytes(b'\0' * 100)
    clock.now += 10 * watch_common.RESCAN_SLACK_SEC
    handler = make_handler(rescan_changed_only=True)
    arrived = watched / 'arrived.pcap'
    arrived.write_bytes(b'\0' * 100)
    os.utime(arrived, (clock.now, clock.now))

    lose_events(handler, watched)

    assert tracked(handler) == {str(arrived)}


def test_changed_only_rescan_counts_ctime_for_files_moved_in(clock, tmp_path, watched):
    # a rename keeps a file's old mtime, but its ctime is current
    handler = make_handler(rescan_changed_only=True)
    source = tmp_path / 'upload.pcap'
    source.write_bytes(b'\0' * 100)
    ancient = clock.now - 100 * watch_common.RESCAN_SLACK_SEC
    os.utime(source, (ancient, ancient))
    moved_in = watched / 'upload.pcap'
    source.rename(moved_in)
    assert moved_in.stat().st_mtime < clock.now - watch_common.RESCAN_SLACK_SEC

    lose_events(handler, watched)

    assert tracked(handler) == {str(moved_in)}


def test_events_lost_for_a_file_watch_queues_nothing(handler, clock, watched):
    capture = watched / 'watched-file.pcap'
    capture.write_bytes(b'\0' * 100)

    handler.dispatch(EventsLostEvent(str(capture), is_directory=False))

    assert tracked(handler) == set()
