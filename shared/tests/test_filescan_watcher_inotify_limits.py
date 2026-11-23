"""filescan_watcher moves inotify watches to polling when an inotify resource limit is hit.

watchdog raises OSError(EMFILE) from schedule() at the user's inotify instance limit and
OSError(ENOSPC) from start() at the watch limit. start_dir_observers logs the sysctl to raise and
schedules those watches on the polling observer instead of letting supervisord restart the watcher
into the same limit. The filescan_watcher fixture (conftest.py) loads bin/filescan_watcher.
"""

import errno
import os
import types
from pathlib import Path
from unittest.mock import Mock

import pytest


def make_fake_observer_class(created, fail_in=None, error=errno.ENOSPC):
    def fail(step):
        if fail_in == step:
            raise OSError(error, os.strerror(error))

    class FakeObserver:
        def __init__(self):
            self.scheduled, self.started, self.stopped = [], False, False
            created.append(self)
            fail('init')

        def schedule(self, handler, path, *, recursive=False, event_filter=None):
            fail('schedule')
            self.scheduled.append((path, recursive, event_filter))

        def start(self):
            fail('start')
            self.started = True

        def stop(self):
            self.stopped = True

    return FakeObserver


@pytest.fixture
def observers(filescan_watcher, monkeypatch):
    """Install recording fakes for both observer classes; call with how the inotify one fails."""
    created = {'inotify': [], 'polling': []}

    def install(fail_in=None, error=errno.ENOSPC):
        monkeypatch.setattr(
            filescan_watcher, 'Observer', make_fake_observer_class(created['inotify'], fail_in, error)
        )
        monkeypatch.setattr(filescan_watcher, 'PollingObserver', make_fake_observer_class(created['polling']))
        return created

    return install


@pytest.fixture
def log(filescan_watcher, monkeypatch):
    log = Mock()
    monkeypatch.setattr(filescan_watcher, 'log', log)
    return log


def watch(path, strategy, recursive=True):
    return types.SimpleNamespace(path=Path(path), strategy=strategy, recursive=recursive)


@pytest.mark.parametrize(
    ('fail_in', 'error', 'sysctl'),
    [
        ('schedule', errno.EMFILE, 'fs.inotify.max_user_instances'),
        ('start', errno.ENOSPC, 'fs.inotify.max_user_watches'),
    ],
)
def test_inotify_limit_moves_watches_to_polling(filescan_watcher, observers, log, fail_in, error, sysctl):
    created = observers(fail_in=fail_in, error=error)
    watches = [watch('/data/extracted', 'inotify'), watch('/mnt/share', 'polling', recursive=False)]
    handler, dir_observers = Mock(), {}

    filescan_watcher.start_dir_observers(handler, watches, dir_observers)

    inotify, polling = created['inotify'][0], created['polling'][0]
    assert inotify.stopped
    assert dir_observers == {'polling': polling}
    assert polling.started
    event_filter = list(filescan_watcher.DIRECTORY_WATCH_EVENTS)
    assert sorted(polling.scheduled) == [
        ('/data/extracted', True, event_filter),
        ('/mnt/share', False, event_filter),
    ]
    log.critical.assert_called_once()
    assert sysctl in log.critical.call_args.args
    assert '/data/extracted' in log.critical.call_args.args[2]


def test_other_os_errors_still_raise(filescan_watcher, observers, log):
    created = observers(fail_in='start', error=errno.EACCES)
    dir_observers = {}

    with pytest.raises(OSError) as raised:
        filescan_watcher.start_dir_observers(Mock(), [watch('/data/extracted', 'inotify')], dir_observers)

    assert raised.value.errno == errno.EACCES
    assert created['inotify'][0].stopped
    assert created['polling'] == []
    assert dir_observers == {}


def test_each_strategy_gets_its_own_observer_when_inotify_starts(filescan_watcher, observers, log):
    created = observers()
    watches = [watch('/data/extracted', 'inotify'), watch('/mnt/share', 'polling')]
    dir_observers = {}

    filescan_watcher.start_dir_observers(Mock(), watches, dir_observers)

    inotify, polling = created['inotify'][0], created['polling'][0]
    assert dir_observers == {'inotify': inotify, 'polling': polling}
    assert inotify.started and polling.started
    assert [path for path, _, _ in inotify.scheduled] == ['/data/extracted']
    assert [path for path, _, _ in polling.scheduled] == ['/mnt/share']
    log.critical.assert_not_called()


def test_no_watches_builds_no_observers(filescan_watcher, observers, log):
    created = observers()
    dir_observers = {}

    filescan_watcher.start_dir_observers(Mock(), [], dir_observers)

    assert created == {'inotify': [], 'polling': []}
    assert dir_observers == {}
    log.info.assert_not_called()
