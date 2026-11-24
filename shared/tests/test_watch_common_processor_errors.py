"""A file processor that raises must not drop the file silently or stop the worker.

ProcessFileEventWorker calls the processor while holding the deck lock. ContextLockedOrderedDict
used to suppress any exception raised there whenever other files were still queued, so the failing
file vanished with no log line and the rest of that pass was skipped; with nothing else queued, the
exception escaped and took the watcher down. Now the worker logs the failure, with its traceback,
and carries on with the queue.
"""

from unittest.mock import Mock

from watchdog.events import FileClosedEvent

import watch_common
from malcolm_utils import AtomicInt


def test_processor_exception_is_logged_and_the_worker_continues(tmp_path, monkeypatch):
    handler = watch_common.FileOperationEventHandler(logger=Mock(), polling=False)
    good, bad = tmp_path / 'good.pcap', tmp_path / 'bad.pcap'
    # a close-write puts a file at the front of the deck, so bad (closed last) is processed first
    for path in (good, bad):
        path.write_bytes(b'\0' * 100)
        handler.on_any_event(FileClosedEvent(str(path)))

    processed = []

    def processor(path, **kwargs):
        if path == str(bad):
            raise RuntimeError('processor failed')
        processed.append(path)

    observer = Mock()
    observer.is_alive.side_effect = [True, False]
    logger = Mock()
    monkeypatch.setattr(watch_common.time, 'sleep', lambda _: None)

    watch_common.ProcessFileEventWorker(
        [handler, observer, processor, {}, 0, AtomicInt(value=0), [False], logger]
    )

    assert processed == [str(good)]
    logger.exception.assert_called_once()
    assert str(bad) in logger.exception.call_args.args[0]
    with handler.deck as deck:
        queued = dict(deck)
    assert queued == {}
