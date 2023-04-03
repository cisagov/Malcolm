#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import time

from malcolm_utils import AtomicInt, ContextLockedOrderedDict, same_file_or_dir

from watchdog.events import (
    FileSystemEventHandler,
    FileSystemEvent,
    FileSystemMovedEvent,
    FileMovedEvent,
    DirMovedEvent,
    FileModifiedEvent,
    DirModifiedEvent,
    FileCreatedEvent,
    FileClosedEvent,
    FileOpenedEvent,
    DirCreatedEvent,
    FileDeletedEvent,
    DirDeletedEvent,
)

from multiprocessing.pool import ThreadPool
from watchdog.utils import WatchdogShutdown
from watchdog.observers import Observer
from watchdog.observers.polling import PollingObserver


###################################################################################################
class FileOperationEventHandler(FileSystemEventHandler):
    def __init__(
        self,
        logger,
        polling,
        *args,
        **kwargs,
    ):
        super().__init__(*args, **kwargs)
        self.polling = polling
        # items at the first (idx=0) of this OrderedDict are the
        # oldest, items at the last (idx=len-1) are the newest
        self.deck = ContextLockedOrderedDict()
        self.logger = logger
        self.updateTime()

    def done(self):
        return True

    def updateTime(self):
        self.nowTime = int(time.time())

    def on_any_event(self, event):
        if not event.is_directory:
            self.updateTime()
            if self.logger:
                self.logger.debug(f"{self.nowTime}: {event.event_type} {event.src_path}")

    def on_created(self, event):
        self.on_modified(event)

    def on_modified(self, event):
        # we only care about "created" and "modified" events if polling,
        # otherwise "on_closed" will take care of us
        if not event.is_directory and self.polling:
            with self.deck as d:
                d[event.src_path] = self.nowTime
                d.move_to_end(event.src_path, last=True)

    def on_moved(self, event):
        if not event.is_directory:
            if isinstance(event, FileSystemMovedEvent) and same_file_or_dir(
                os.path.dirname(event.src_path), os.path.dirname(event.dest_path)
            ):
                # a file was simply renamed in the watched directory (not moved
                # from some other directory) so just update the filename
                with self.deck as d:
                    d.pop(event.src_path, self.nowTime)
                    d[event.dest_path] = self.nowTime
                    d.move_to_end(event.dest_path, last=True)
            else:
                # the file was moved from somewhere else, treat it as a create
                self.on_created(event)

    def on_closed(self, event):
        # on_closed is only going to come from inotify events, not polling
        # so we know we're good to go. set its time to expire immediately in the worker
        if not event.is_directory:
            with self.deck as d:
                d[event.src_path] = 0
                d.move_to_end(event.src_path, last=False)

    def on_deleted(self, event):
        # if a file is deleted I guess we don't need to track it any more
        if not event.is_directory:
            with self.deck as d:
                d.pop(event.src_path, self.nowTime)


###################################################################################################
def ProcessFileEventWorker(workerArgs):
    handler, observer, fileProcessor, assumeClosedSec, workerThreadCount, shutDown, logger = (
        workerArgs[0],
        workerArgs[1],
        workerArgs[2],
        workerArgs[3],
        workerArgs[4],
        workerArgs[5],
        workerArgs[6],
    )

    with workerThreadCount as workerId:
        if logger is not None:
            logger.debug(f"[{workerId}]:started")

        while (not shutDown[0]) and observer.is_alive():
            time.sleep(1)
            nowTime = int(time.time())
            with handler.deck as d:
                for fileName, eventTime in list(d.items()):
                    if nowTime < eventTime + assumeClosedSec:
                        # we can break because the list is ordered
                        break
                    else:
                        del d[fileName]
                        if fileProcessor is not None:
                            fileProcessor(fileName)
                        logger.debug(f"processed {fileName} at {(nowTime-eventTime) if (eventTime > 0) else 0} seconds")

        time.sleep(1)
        if logger is not None:
            logger.debug(f"[{workerId}]: finished")


def WatchAndProcessDirectory(
    directories,
    polling,
    fileProcessor,
    assumeClosedSec,
    shuttingDown,
    logger,
):
    observer = PollingObserver() if polling else Observer()
    handler = FileOperationEventHandler(
        logger=logger,
        polling=polling,
    )
    for directory in directories:
        if logger:
            logger.debug(f"Scheduling {directory}")
        observer.schedule(handler, directory, recursive=True)

    observer.start()
    try:
        workerThreadCount = AtomicInt(value=0)
        ThreadPool(
            1,
            ProcessFileEventWorker(
                [
                    handler,
                    observer,
                    fileProcessor,
                    assumeClosedSec,
                    workerThreadCount,
                    shuttingDown,
                    logger,
                ],
            ),
        )

        while (not shuttingDown[0]) and observer.is_alive():
            observer.join(1)

        if shuttingDown[0]:
            raise WatchdogShutdown()

    except WatchdogShutdown:
        observer.unschedule_all()

    finally:
        observer.stop()
        observer.join()

    while workerThreadCount.value() > 0:
        time.sleep(1)
