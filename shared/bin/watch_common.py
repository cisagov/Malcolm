#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import errno
import os
import json
import logging
import time

from malcolm_utils import AtomicInt, ContextLockedOrderedDict

from watchdog.events import (
    EVENT_TYPE_OPENED,
    FileClosedEvent,
    FileClosedNoWriteEvent,
    FileCreatedEvent,
    FileDeletedEvent,
    FileModifiedEvent,
    FileMovedEvent,
    FileOpenedEvent,
    FileSystemEventHandler,
)

try:
    from watchdog.events import DirAttribEvent, FileAttribEvent

    ATTRIB_EVENT_TYPES = (FileAttribEvent, DirAttribEvent)
except ImportError:
    # watchdog < 7 (e.g., the filebeat image on Python 3.9) has no attrib events and reports
    #   metadata-only changes as FileModifiedEvent, which the size comparison below handles
    ATTRIB_EVENT_TYPES = ()

from multiprocessing.pool import ThreadPool
from threading import get_native_id
from watchdog.utils import WatchdogShutdownError
from watchdog.observers import Observer
from watchdog.observers.polling import PollingObserver
from collections import namedtuple, OrderedDict

ASSUME_CLOSED_SEC_DEFAULT = 10

# inotify resource limits, by the errno watchdog raises when one is hit: ENOSPC when the user's
#   watch limit is reached, EMFILE when the user's instance limit is
INOTIFY_LIMIT_SYSCTLS = {
    errno.ENOSPC: 'fs.inotify.max_user_watches',
    errno.EMFILE: 'fs.inotify.max_user_instances',
}

OperationEvent = namedtuple("OperationEvent", ["timestamp", "operation", "size"], rename=False)

# watchdog 7.1.1+ sends an EventsLostEvent (event_type "events_lost") to each watch after the kernel's
#   inotify queue overflows. FileOperationEventHandler.on_events_lost records it in a file's history
#   as this synthetic operation; watchdog < 7.1.1 never sends it.
EVENT_TYPE_EVENTS_LOST = "events_lost"

# with rescan_changed_only, files whose mtime and ctime both predate the last event seen before the
#   overflow, by more than this, are left out of the rescan. The slack allows for events being
#   dispatched some time after the kernel queued them.
RESCAN_SLACK_SEC = 300


###################################################################################################
class FileOperationEventHandler(FileSystemEventHandler):
    def __init__(
        self,
        logger,
        polling,
        *args,
        recursive=False,
        rescan_changed_only=False,
        **kwargs,
    ):
        super().__init__(*args, **kwargs)
        self.polling = polling
        # whether the watches are recursive, so an overflow rescan knows how deep to look
        self.recursive = recursive
        # files processed in place stay in the watched directory (pcap_watcher), so an overflow
        #   rescan should only queue files changed since the last event seen before it
        self.rescanChangedOnly = rescan_changed_only
        self.logger = logger if logger else logging
        self.workerPid = get_native_id()
        self.updateTime()
        # self.deck is a dictionary mapping filenames to a list of OperationEvent of length n,
        #   with [0] being the oldest timestamp/operation and [n-1] being the newest
        #   timestamp/operation.
        # In self.deck itself, items at the first (idx=0) of this OrderedDict are the
        #   oldest, items at the last (idx=len-1) are the newest.
        self.deck = ContextLockedOrderedDict()
        # Files we've only seen opened, or modified without a size change, wait in
        #   self.modDeck until something shows they're being written, and are then
        #   promoted to self.deck for processing. Under inotify, watchdog 7+ reports
        #   metadata-only changes as attrib events (dropped in on_any_event), so a
        #   modified event means a real write. The polling observer still reports a
        #   utime as "modified" because the mtime changed, which is why the size
        #   comparison below stays.
        self.modDeck = OrderedDict()

    def done(self):
        return True

    def updateTime(self):
        self.nowTime = int(time.time())

    def cancel_read_open(self, event):
        # IN_CLOSE_NOWRITE means the matching IN_OPEN was a read-only open, which can't change the
        #   file's contents. Retract one recorded "opened" so the reader's visit doesn't count as
        #   activity: a file nobody else is tracking drops out of the decks entirely, while an
        #   "opened" left behind by a writer that still holds the file keeps it waiting for its close.
        #   This never promotes or appends; a close with no recorded open is ignored.
        if event.is_directory:
            return
        fName = event.src_path
        with self.deck as d:
            for deck in (d, self.modDeck):
                history = deck.get(fName)
                if history is None:
                    continue
                for idx in range(len(history) - 1, -1, -1):
                    if history[idx].operation == EVENT_TYPE_OPENED:
                        del history[idx]
                        break
                if not history:
                    deck.pop(fName, None)
                self.logger.debug(
                    f"⊖\t{event.event_type: <10}\t{fName}\t{json.dumps(deck.get(fName, []))}\t{self.workerPid}"
                )
                break

    def _append_or_refresh(self, entries, operation):
        """Coalesce repeated operations while preserving each outstanding open."""
        last = entries[-1] if entries else None
        if last and last.operation == operation.operation and operation.operation != EVENT_TYPE_OPENED:
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
        if staged and staged[-1].operation == operation.operation and operation.operation != EVENT_TYPE_OPENED:
            staged[-1] = operation
        else:
            staged.append(operation)
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
        # Watchdog 7+ reports metadata changes and lost-event notifications separately.
        if isinstance(event, ATTRIB_EVENT_TYPES) or event.event_type == EVENT_TYPE_EVENTS_LOST:
            return
        if isinstance(event, FileClosedNoWriteEvent):
            self.cancel_read_open(event)
            return
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
            # Unmatched moves out of the watched tree have no destination to
            # queue, but any history for the source must still be retired.
            if old_filename:
                with self.deck as deck:
                    deck.pop(old_filename, None)
                    self.modDeck.pop(old_filename, None)
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

    def on_events_lost(self, event):
        # watchdog 7.1.1+, inotify: the kernel queue overflowed and some events under event.src_path
        #   (the watched directory) were dropped. watchdog has already repaired the watches, so new
        #   events are flowing again. Three things could be missing:
        #   - a tracked file's close-write: without it a file written in place waits in the deck
        #     forever. Each tracked file gets an "events_lost" operation, which ProcessFileEventWorker
        #     treats like polling: processed after assumeClosedSec with no further events. A file
        #     whose writer is still going gets new events, which take it back to waiting for a close.
        #   - a write to a file staged in modDeck: staged files are promoted on the same terms.
        #   - every event for a file: the directory is rescanned and untracked files are queued as
        #     created, which are processed after the quiet period too.
        #   Tracked files that no longer exist (a lost delete or move-out) are dropped.
        if not event.is_directory:
            return
        root = os.path.normpath(os.fsdecode(event.src_path))
        rootPrefix = os.path.join(root, '')
        self.logger.warning(f"⚠\tevents lost for {root}, recovering\t{self.workerPid}")

        def underRoot(fName):
            if not fName.startswith(rootPrefix):
                return False
            return self.recursive or (os.path.dirname(fName) == root)

        def currentSize(fName):
            try:
                return os.path.getsize(fName)
            except Exception:
                return 0

        lostTime = int(time.time())
        changedSince = (self.nowTime - RESCAN_SLACK_SEC) if self.rescanChangedOnly else None

        tracked = set()
        with self.deck as d:
            # this runs on the observer's dispatcher thread, which an escaping exception would stop,
            #   so catch and log it instead, as on_any_event does
            try:
                for fName in [f for f in self.modDeck if underRoot(f)]:
                    d[fName] = self.modDeck.pop(fName)
                for fName in [f for f in d if underRoot(f)]:
                    history = d[fName]
                    if not os.path.isfile(fName):
                        del d[fName]
                    elif history and (history[-1].timestamp == 0):
                        # already closed and at the front of the deck, ready to process
                        continue
                    elif history and (history[-1].operation == EVENT_TYPE_EVENTS_LOST):
                        # another watch's report of the same overflow
                        history[-1] = OperationEvent(lostTime, EVENT_TYPE_EVENTS_LOST, currentSize(fName))
                        d.move_to_end(fName)
                    else:
                        history.append(OperationEvent(lostTime, EVENT_TYPE_EVENTS_LOST, currentSize(fName)))
                        d.move_to_end(fName)
            except Exception as e:
                self.logger.error(f"⚠\tmarking files under {root} failed: {e}\t{self.workerPid}")
            tracked = set(d) | set(self.modDeck)

        # on_any_event takes the deck lock itself, so queue rescanned files after releasing it
        try:
            if self.recursive:
                found = (os.path.join(dirPath, f) for dirPath, _, files in os.walk(root) for f in files)
            else:
                found = (entry.path for entry in os.scandir(root) if entry.is_file())
            queued = 0
            for fName in found:
                if (fName in tracked) or (not os.path.isfile(fName)):
                    continue
                if changedSince is not None:
                    try:
                        st = os.stat(fName)
                    except OSError:
                        continue
                    # a rename keeps the mtime but updates the ctime
                    if max(st.st_mtime, st.st_ctime) < changedSince:
                        continue
                self.on_any_event(FileCreatedEvent(fName))
                queued += 1
            self.logger.info(f"⚠\trescanned {root}, queued {queued} untracked file(s)\t{self.workerPid}")
        except OSError as e:
            self.logger.error(f"⚠\trescan of {root} failed: {e}\t{self.workerPid}")


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
                            # - If events were lost (see FileOperationEventHandler.on_events_lost) and the item has expired
                            #     with nothing since, its close may have been among them, so treat it as polling does
                            or (fileHistory[-1].operation == EVENT_TYPE_EVENTS_LOST)
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
                                try:
                                    fileProcessor(
                                        fileName,
                                        **extraArgs,
                                    )
                                except Exception as e:
                                    # the file has already left the deck; log it and keep the worker
                                    #   going for the rest of the queue
                                    logger.exception(f"⨳\tprocessing {fileName} failed: {e}\t[{workerPid}:{workerId}]")
                                    continue
                            logger.info(
                                f"🖄\tprocessed\t{fileName} at {(nowTime-fileHistory[-1].timestamp) if (fileHistory[-1].timestamp > 0) else 0} seconds\t[{workerPid}:{workerId}]"
                            )
                            sleepInterval = 0.5

        time.sleep(1)
        logger.info(f"⛒\tfinished\t[{workerPid}:{workerId}]")


def StartObserver(
    handler,
    directories,
    polling,
    recursive,
    logger,
):
    # Schedule handler on each directory and start the observer, returning it. If an inotify
    #   resource limit stops the inotify observer from scheduling or starting, log it and watch
    #   the same directories with a PollingObserver instead of failing. watchdog raises the
    #   instance limit (EMFILE) from schedule() as of 7.1.1 and the watch limit (ENOSPC) from
    #   start() for watches scheduled before it; older versions raise them from construction
    #   or start(), so all three are covered.
    loggerToUse = logger if logger else logging
    if not polling:
        observer = None
        try:
            observer = Observer()
            for directory in directories:
                loggerToUse.info(f"🗐\tScheduling {directory}")
                observer.schedule(handler, directory, recursive=recursive)
            observer.start()
            return observer
        except OSError as e:
            if observer is not None:
                # never started, so this only stops its emitters and releases its inotify instance
                observer.stop()
            if e.errno not in INOTIFY_LIMIT_SYSCTLS:
                raise
            loggerToUse.critical(
                f"⚠\tinotify limit reached ({e}), falling back to polling for {directories}; "
                f"raise {INOTIFY_LIMIT_SYSCTLS[e.errno]} on the host to use inotify"
            )
            # the worker processes files on the quiet-period rule when polling
            handler.polling = True

    observer = PollingObserver()
    for directory in directories:
        loggerToUse.info(f"🗐\tScheduling {directory}")
        observer.schedule(handler, directory, recursive=recursive)
    observer.start()
    return observer


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
    loggerToUse = logger if logger else logging
    handler = FileOperationEventHandler(
        logger=loggerToUse,
        polling=polling,
        recursive=recursive,
    )
    observer = StartObserver(handler, directories, polling, recursive, loggerToUse)
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
