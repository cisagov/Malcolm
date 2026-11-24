"""filescan_watcher reports an inotify queue overflow instead of losing it silently.

watchdog 7.1.1 emits EventsLostEvent when the kernel's inotify queue overflows. A watch only gets it
if its event_filter lists it, and for a directory watch it arrives with is_directory=True, which
FileEventHandler.dispatch used to drop along with every other directory event. The handler only
logs it; nothing is rescanned.

The filescan_watcher fixture (conftest.py) loads bin/filescan_watcher as a module.
"""

import importlib.util
import threading
import types
from unittest.mock import Mock

import pytest
from anyio.from_thread import start_blocking_portal
from watchdog.events import DirCreatedEvent, EventsLostEvent
from watchdog.observers.polling import PollingObserver

@pytest.fixture(params=['asyncio', 'trio'])
def portal(request):
    if request.param == 'trio' and importlib.util.find_spec('trio') is None:
        pytest.skip('optional Trio backend is not installed')
    with start_blocking_portal(backend=request.param) as portal:
        yield portal


@pytest.fixture
def log(filescan_watcher, monkeypatch):
    logged = threading.Event()
    log = Mock()
    log.warning.side_effect = lambda *args, **kwargs: logged.set()
    log.logged = logged
    monkeypatch.setattr(filescan_watcher, 'log', log)
    return log


@pytest.fixture
def handler(filescan_watcher, portal):
    return filescan_watcher.FileEventHandler(options=types.SimpleNamespace(path_maps={}), redis=None, portal=portal)


def test_events_lost_on_a_directory_watch_is_logged(handler, log, tmp_path):
    handler.dispatch(EventsLostEvent(str(tmp_path), is_directory=True))

    log.warning.assert_called_once()
    assert str(tmp_path) in log.warning.call_args.args
    assert handler._FileEventHandler__pending == {}


def test_other_directory_events_are_still_dropped(handler, log, tmp_path):
    handler.dispatch(DirCreatedEvent(str(tmp_path / 'subdir')))

    log.warning.assert_not_called()
    assert handler._FileEventHandler__pending == {}


def test_directory_watch_filter_delivers_events_lost(filescan_watcher, handler, log, tmp_path):
    # schedule with the script's own filter and push the event through a real emitter, which
    # drops anything the filter doesn't list before it reaches the observer
    observer = PollingObserver(timeout=0.1)
    event_filter = list(filescan_watcher.DIRECTORY_WATCH_EVENTS)
    observer.schedule(handler, str(tmp_path), recursive=False, event_filter=event_filter)
    observer.start()
    try:
        emitter = next(iter(observer.emitters))
        emitter.queue_event(EventsLostEvent(str(tmp_path), is_directory=True))

        assert log.logged.wait(timeout=5), 'EventsLostEvent never reached the handler'
        assert str(tmp_path) in log.warning.call_args.args
    finally:
        observer.stop()
        observer.join(5)
