"""filescan's async watchdog adapter must survive event types it has no handler for.

AsyncFileSystemEventHandler.dispatch used to look up on_<event_type> with a bare getattr. watchdog
adds event types over time (attrib in 7.0, events_lost in 7.1.1), and a missing handler raised
AttributeError back through the BlockingPortal onto the observer's dispatcher thread. That thread
only catches queue.Empty, so one unexpected event stopped the observer for good.
"""

import importlib.util
import threading
from dataclasses import dataclass

import pytest
from anyio.from_thread import start_blocking_portal
from watchdog.events import EventsLostEvent, FileCreatedEvent, FileSystemEvent
from watchdog.observers.polling import PollingObserver

from filescan.watch import AsyncFileSystemEventHandler


@dataclass(unsafe_hash=True)
class FutureEvent(FileSystemEvent):
    """Stands in for an event type a later watchdog release might add."""

    event_type = 'from_the_future'


class Recorder(AsyncFileSystemEventHandler):
    def __init__(self):
        self.seen = []
        self.created = threading.Event()

    async def on_any_event(self, event, /):
        self.seen.append(('any', event))

    async def on_created(self, event, /):
        self.seen.append(('created', event))
        self.created.set()


class LostRecorder(Recorder):
    async def on_events_lost(self, event, /):
        self.seen.append(('events_lost', event))


@pytest.fixture(params=['asyncio', 'trio'])
def portal(request):
    if request.param == 'trio' and importlib.util.find_spec('trio') is None:
        pytest.skip('optional Trio backend is not installed')
    with start_blocking_portal(backend=request.param) as portal:
        yield portal


def test_unknown_event_type_reaches_on_any_event_without_raising(portal):
    adapter = Recorder(portal=portal)
    event = FutureEvent('/watched/file')

    adapter.dispatch(event)

    assert adapter.seen == [('any', event)]


def test_known_event_types_still_route_to_their_handler(portal):
    adapter = Recorder(portal=portal)
    event = FileCreatedEvent('/watched/file')

    adapter.dispatch(event)

    assert adapter.seen == [('any', event), ('created', event)]


def test_events_lost_is_a_noop_by_default(portal, tmp_path):
    adapter = Recorder(portal=portal)
    event = EventsLostEvent(str(tmp_path), is_directory=True)

    adapter.dispatch(event)

    assert adapter.seen == [('any', event)]


def test_events_lost_routes_to_an_overriding_handler(portal, tmp_path):
    adapter = LostRecorder(portal=portal)
    event = EventsLostEvent(str(tmp_path), is_directory=True)

    adapter.dispatch(event)

    assert adapter.seen == [('any', event), ('events_lost', event)]


def test_observer_keeps_dispatching_after_an_unknown_event(portal, tmp_path):
    # Drive a real observer's dispatcher thread: the unknown event goes in first, and the
    # created event behind it is only delivered if the thread survived the first one.
    adapter = Recorder(portal=portal)
    observer = PollingObserver(timeout=0.1)
    watch = observer.schedule(adapter, str(tmp_path), recursive=False)
    observer.start()
    try:
        unknown = FutureEvent(str(tmp_path / 'unknown'))
        created = FileCreatedEvent(str(tmp_path / 'created'))
        observer.event_queue.put((unknown, watch))
        observer.event_queue.put((created, watch))

        assert adapter.created.wait(timeout=5), 'observer stopped dispatching after the unknown event'
        assert observer.is_alive()
        assert [kind for kind, event in adapter.seen if event in (unknown, created)] == ['any', 'any', 'created']
    finally:
        observer.stop()
        observer.join(5)
