#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import json
import logging
import time

from malcolm_utils import AtomicInt, ContextLockedOrderedDict

from watchdog.events import (
    FileSystemEventHandler,
    FileMovedEvent,
    FileModifiedEvent,
    FileCreatedEvent,
    FileClosedEvent,
    FileOpenedEvent,
    FileDeletedEvent,
)

from multiprocessing.pool import ThreadPool
from threading import get_native_id
from watchdog.utils import WatchdogShutdownError
from watchdog.observers import Observer
from watchdog.observers.polling import PollingObserver
from collections import namedtuple, OrderedDict

ASSUME_CLOSED_SEC_DEFAULT = 10

OperationEvent = namedtuple("OperationEvent", ["timestamp", "operation", "size"], rename=False)


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
        self.logger = logger if logger else logging
        self.workerPid = get_native_id()
        self.updateTime()
        # self.deck is a dictionary mapping filenames to a list of OperationEvent of length n,
        #   with [0] being the oldest timestamp/operation and [n-1] being the newest
        #   timestamp/operation.
        # In self.deck itself, items at the first (idx=0) of this OrderedDict are the
        #   oldest, items at the last (idx=len-1) are the newest.
        self.deck = ContextLockedOrderedDict()
        # because of the pain in the butt that is the fact that we get the modify events
        #   on attributes-only changes (see below where I set fSize), if events show up
        #   for files and we've ONLY seen open and/or attribute-only modify events (i.e.,
        #   the size doesn't change) then we're just going to hold on to them here in
        #   self.modDeck until we promote them to self.deck for processing.
        #   Once gorakhargosh/watchdog#800 is pulled (resolving gorakhargosh/watchdog#260)
        #   we can get rid of this complication and just ignore attribute-only events.
        self.modDeck = OrderedDict()

    def done(self):
        return True

    def updateTime(self):
        self.nowTime = int(time.time())

    def _append_or_refresh(self, entries, operation):
        """Coalesce consecutive operations of the same kind on a file."""
        last = entries[-1] if entries else None
        if last and last.operation == operation.operation:
            if operation.timestamp > last.timestamp or operation.size != last.size:
                entries[-1] = operation
        else:
            entries.append(operation)

    def _track_existing(self, deck, filename, event, operation):
        """Update the primary queue, ignoring metadata-only modifications."""
        entries = deck[filename]
        if (
            isinstance(event, FileModifiedEvent)
            and operation.size > 0
            and entries
            and operation.size == entries[-1].size
        ):
            return True
        self._append_or_refresh(entries, operation)
        return False

    def _track_staged(self, deck, filename, event, operation):
        """Promote a provisional open/modify sequence once content changes."""
        staged = self.modDeck[filename]
        previous_modify_sizes = [op.size for op in staged if op.operation == 'modified']
        promote = (
            not isinstance(event, (FileOpenedEvent, FileModifiedEvent))
            or (
                isinstance(event, FileModifiedEvent)
                and bool(previous_modify_sizes)
                and operation.size > 0
                and operation.size != previous_modify_sizes[-1]
            )
        )
        if promote:
            self.logger.debug(f"𝦸\t{event.event_type: <10}\t{filename}\t{self.workerPid}")
            deck[filename] = self.modDeck.pop(filename)
            deck[filename].append(operation)
            return deck

        # Keep staging updates in modDeck, not the primary queue: otherwise
        # an open followed by a same-sized modify used to raise KeyError.
        self._append_or_refresh(staged, operation)
        return self.modDeck

    def _insert_first(self, deck, filename, event, operation):
        """Stage unconfirmed opens/modifies; queue other events immediately."""
        target = self.modDeck if isinstance(event, (FileOpenedEvent, FileModifiedEvent)) else deck
        target[filename] = [operation]
        return target

    def _prioritize_or_remove(self, deck, target, filename, event):
        """Order processable events and discard deleted paths from both queues."""
        if isinstance(event, (FileModifiedEvent, FileClosedEvent, FileCreatedEvent, FileMovedEvent)):
            # Close events use timestamp zero, moving them to the front.
            target.move_to_end(filename, last=target[filename][-1].timestamp > 0)
            return filename, False
        if isinstance(event, FileDeletedEvent):
            deck.pop(filename, None)
            self.modDeck.pop(filename, None)
            return None, False
        return filename, True

    def _record_event(self, filename, old_filename, event, operation):
        with self.deck as deck:
            try:
                if old_filename:
                    # Moves can cross watched subdirectories: discard stale
                    # source entries in both queues before queuing destination.
                    deck.pop(old_filename, None)
                    self.modDeck.pop(old_filename, None)

                if filename in deck:
                    target = deck
                    noop = self._track_existing(deck, filename, event, operation)
                elif filename in self.modDeck:
                    target = self._track_staged(deck, filename, event, operation)
                    noop = False
                else:
                    target = self._insert_first(deck, filename, event, operation)
                    noop = False

                if not noop:
                    filename, noop = self._prioritize_or_remove(deck, target, filename, event)
                if noop:
                    self.logger.debug(f"🗑\t{event.event_type: <10}\t{filename}\t{self.workerPid}")
                elif filename:
                    if filename in deck:
                        self.logger.debug(f"➊\t{filename}\t{json.dumps(deck[filename])}\t{self.workerPid}")
                    if filename in self.modDeck:
                        self.logger.debug(f"➋\t{filename}\t{json.dumps(self.modDeck[filename])}\t{self.workerPid}")
            except Exception as error:
                self.logger.error(f"⨳\t{filename}\t{error}\t{self.workerPid}")

    def on_any_event(self, event):
        """Convert a watchdog notification into a bounded file history entry."""
        if event.is_directory:
            return
        self.updateTime()
        if isinstance(event, FileMovedEvent):
            filename, old_filename = event.dest_path, event.src_path
            self.logger.debug(
                f"↦\t{event.event_type: >10}\t{event.src_path} {event.dest_path}\t{self.workerPid}"
            )
        else:
            filename, old_filename = event.src_path, None
            self.logger.debug(f"🗲\t{event.event_type: <10}\t{filename}\t{self.workerPid}")

        # Watchdog can emit metadata-only modify events. The queue uses file
        # size to ignore no-content-change modifications when possible.
        if not filename:
            return
        try:
            file_size = os.path.getsize(filename)
        except Exception:
            # Preserve the existing tolerance for disappearing/inaccessible
            # entries and platform-specific watchdog path irregularities.
            file_size = 0
        # Closed file notifications from inotify may be processed immediately.
        operation = OperationEvent(0 if isinstance(event, FileClosedEvent) else self.nowTime, event.event_type, file_size)
        self._record_event(filename, old_filename, event, operation)


###################################################################################################
def ProcessFileEventWorker(workerArgs):
    (
        handler,
        observer,
        fileProcessor,
        fileProcessorKwargs,
        assumeClosedSec,
        workerThreadCount,
        shutDown,
        logger,
    ) = (
        workerArgs[0],
        workerArgs[1],
        workerArgs[2],
        workerArgs[3],
        workerArgs[4],
        workerArgs[5],
        workerArgs[6],
        workerArgs[7],
    )
    if not logger:
        logger = logging

    with workerThreadCount as workerId:
        workerPid = get_native_id()
        logger.info(f"۞\tstarted\t[{workerPid}:{workerId}]")

        sleepInterval = 0.5
        while (not shutDown[0]) and observer.is_alive():
            time.sleep(sleepInterval)
            sleepInterval = min(sleepInterval + 1.0, 5.0)

            nowTime = int(time.time())

            with handler.deck as d:
                for fileName, fileHistory in list(d.items()):
                    logger.debug(f"⏿ checking {fileName}\t{json.dumps(fileHistory)}\t[{workerPid}:{workerId}]")

                    if len(fileHistory) > 0:
                        if nowTime < fileHistory[-1].timestamp + assumeClosedSec:
                            # we can break because the list is ordered
                            logger.debug(
                                f"⎊\tbreaking early because {nowTime} < {fileHistory[-1].timestamp + assumeClosedSec}\t[{workerPid}:{workerId}]"
                            )
                            break

                        elif (
                            # - If we're polling, rely on the timestamp comparison done above and process this file
                            handler.polling
                            # - If we're not polling, but we have a timestamp == 0, then we had a FileClosedEvent and can be processed
                            or (fileHistory[-1].timestamp == 0)
                            # - If we're not polling, and the item has expired (timestamp comparison done above) and the only items
                            #     in this item's history are "created" or "moved" then this was atomically moved in from another directory
                            #     on the same filesystem and should be processed now
                            or (
                                not any(
                                    set([x.operation for x in fileHistory if x.operation not in ('created', 'moved')])
                                )
                            )
                        ):
                            del d[fileName]
                            if fileProcessor is not None:
                                extraArgs = (
                                    fileProcessorKwargs
                                    if fileProcessorKwargs and isinstance(fileProcessorKwargs, dict)
                                    else {}
                                )
                                fileProcessor(
                                    fileName,
                                    **extraArgs,
                                )
                            logger.info(
                                f"🖄\tprocessed\t{fileName} at {(nowTime-fileHistory[-1].timestamp) if (fileHistory[-1].timestamp > 0) else 0} seconds\t[{workerPid}:{workerId}]"
                            )
                            sleepInterval = 0.5

        time.sleep(1)
        logger.info(f"⛒\tfinished\t[{workerPid}:{workerId}]")


def WatchAndProcessDirectory(
    directories,
    polling,
    recursive,
    fileProcessor,
    fileProcessorKwargs,
    assumeClosedSec,
    shuttingDown,
    logger,
):
    observer = PollingObserver() if polling else Observer()
    loggerToUse = logger if logger else logging
    handler = FileOperationEventHandler(
        logger=loggerToUse,
        polling=polling,
    )
    for directory in directories:
        loggerToUse.info(f"🗐\tScheduling {directory}")
        observer.schedule(handler, directory, recursive=recursive)

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
                    fileProcessorKwargs,
                    assumeClosedSec,
                    workerThreadCount,
                    shuttingDown,
                    loggerToUse,
                ],
            ),
        )

        while (not shuttingDown[0]) and observer.is_alive():
            observer.join(1)

        if shuttingDown[0]:
            raise WatchdogShutdownError()

    except WatchdogShutdownError:
        observer.unschedule_all()

    finally:
        observer.stop()
        observer.join()

    while workerThreadCount.value() > 0:
        time.sleep(1)
