"""watch_common falls back to polling when an inotify resource limit stops the inotify observer.

watchdog raises OSError(ENOSPC) when the user's inotify watch limit is reached and OSError(EMFILE)
at the instance limit. As of 7.1.1 the instance limit comes from schedule() and the watch limit
from start() for watches scheduled before it; older versions raise from construction or start().
Uncaught, either one takes the watcher down, and its container restarts into the same limit.
StartObserver logs the sysctl to raise and watches the same directories by polling instead.
"""

import errno
import os
import sys
from unittest.mock import Mock

import pytest
from watchdog.observers.polling import PollingObserver

import watch_common


@pytest.fixture
def fake_inotify(monkeypatch):
    """Replace watch_common.Observer with a recording fake that can fail at a chosen step."""
    created = []

    def install(fail_in=None, error=errno.ENOSPC):
        def fail(step):
            if fail_in == step:
                raise OSError(error, os.strerror(error))

        class FakeObserver:
            def __init__(self):
                self.scheduled, self.started, self.stopped = [], False, False
                created.append(self)
                fail('init')

            def schedule(self, handler, path, recursive=False):
                fail('schedule')
                self.scheduled.append((path, recursive))

            def start(self):
                fail('start')
                self.started = True

            def stop(self):
                self.stopped = True

        monkeypatch.setattr(watch_common, 'Observer', FakeObserver)
        return created

    return install


@pytest.fixture
def handler():
    return watch_common.FileOperationEventHandler(logger=Mock(), polling=False)


@pytest.fixture
def directories(tmp_path):
    dirs = [tmp_path / 'one', tmp_path / 'two']
    for directory in dirs:
        directory.mkdir()
    return [str(directory) for directory in dirs]


@pytest.fixture
def started():
    observers = []
    yield observers
    for observer in observers:
        observer.stop()
        observer.join(5)


def watched_paths(observer):
    return {emitter.watch.path for emitter in observer.emitters}


@pytest.mark.parametrize(
    ('fail_in', 'error', 'sysctl'),
    [
        ('schedule', errno.EMFILE, 'fs.inotify.max_user_instances'),
        ('start', errno.ENOSPC, 'fs.inotify.max_user_watches'),
        ('init', errno.EMFILE, 'fs.inotify.max_user_instances'),
    ],
)
def test_inotify_limit_falls_back_to_polling(fake_inotify, handler, directories, started, fail_in, error, sysctl):
    created = fake_inotify(fail_in=fail_in, error=error)
    logger = Mock()

    observer = watch_common.StartObserver(handler, directories, False, True, logger)
    started.append(observer)

    assert isinstance(observer, PollingObserver)
    assert observer.is_alive()
    assert watched_paths(observer) == set(directories)
    assert all(emitter.watch.is_recursive for emitter in observer.emitters)
    # the worker switches to the quiet-period rule, since no close events will arrive
    assert handler.polling is True
    if fail_in != 'init':
        assert created[0].stopped
    logger.critical.assert_called_once()
    assert sysctl in logger.critical.call_args.args[0]


def test_other_os_errors_still_raise(fake_inotify, handler, directories):
    created = fake_inotify(fail_in='start', error=errno.EACCES)

    with pytest.raises(OSError) as raised:
        watch_common.StartObserver(handler, directories, False, False, Mock())

    assert raised.value.errno == errno.EACCES
    assert created[0].stopped
    assert handler.polling is False


def test_inotify_observer_is_used_when_it_starts(fake_inotify, handler, directories):
    created = fake_inotify()
    logger = Mock()

    observer = watch_common.StartObserver(handler, directories, False, False, logger)

    assert observer is created[0]
    assert observer.started and not observer.stopped
    assert observer.scheduled == [(directory, False) for directory in directories]
    assert handler.polling is False
    logger.critical.assert_not_called()


def test_polling_requested_never_builds_an_inotify_observer(fake_inotify, handler, directories, started):
    created = fake_inotify()

    observer = watch_common.StartObserver(handler, directories, True, False, Mock())
    started.append(observer)

    assert created == []
    assert isinstance(observer, PollingObserver)
    assert watched_paths(observer) == set(directories)


@pytest.mark.skipif(not sys.platform.startswith('linux'), reason='inotify is Linux-only')
def test_real_watch_limit_from_watchdog_falls_back(monkeypatch, handler, directories, started):
    # Make the kernel's watch limit fire inside watchdog itself, the way watchdog's own tests do,
    # so the real start() failure and cleanup path is exercised rather than a fake.
    inotify_c = pytest.importorskip('watchdog.observers.inotify_c')
    inotify_fd_class = getattr(inotify_c, 'InotifyFD', None)
    if inotify_fd_class is None:
        pytest.skip('needs the shared InotifyFD reader from watchdog 7.1+')

    def add_callback_at_limit(self, path, *args, **kwargs):
        raise OSError(errno.ENOSPC, os.strerror(errno.ENOSPC), path)

    monkeypatch.setattr(inotify_fd_class, 'add_callback', add_callback_at_limit)
    logger = Mock()

    observer = watch_common.StartObserver(handler, directories, False, False, logger)
    started.append(observer)

    assert isinstance(observer, PollingObserver)
    assert watched_paths(observer) == set(directories)
    assert handler.polling is True
    assert 'fs.inotify.max_user_watches' in logger.critical.call_args.args[0]
