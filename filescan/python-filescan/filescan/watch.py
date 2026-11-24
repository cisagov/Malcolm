from __future__ import annotations

import errno
from anyio.from_thread import BlockingPortal
from typing import Any, Final
from watchdog.events import (
    DirAttribEvent,
    DirCreatedEvent,
    DirDeletedEvent,
    DirModifiedEvent,
    DirMovedEvent,
    EventsLostEvent,
    FileAttribEvent,
    FileClosedEvent,
    FileClosedNoWriteEvent,
    FileCreatedEvent,
    FileDeletedEvent,
    FileModifiedEvent,
    FileMovedEvent,
    FileOpenedEvent,
    FileSystemEvent,
    FileSystemEventHandler,
)

# inotify resource limits, by the errno watchdog raises when one is hit: ENOSPC when the user's
# watch limit is reached, EMFILE when the user's instance limit is
INOTIFY_LIMIT_SYSCTLS: Final = {
    errno.ENOSPC: 'fs.inotify.max_user_watches',
    errno.EMFILE: 'fs.inotify.max_user_instances',
}

type AttribEvent = DirAttribEvent | FileAttribEvent
type ClosedEvent = FileClosedEvent
type ClosedNoWriteEvent = FileClosedNoWriteEvent
type CreatedEvent = DirCreatedEvent | FileCreatedEvent
type DeletedEvent = DirDeletedEvent | FileDeletedEvent
type ModifiedEvent = DirModifiedEvent | FileModifiedEvent
type MovedEvent = DirMovedEvent | FileMovedEvent
type OpenedEvent = FileOpenedEvent


# this class (in combination with AsyncFileSystemEventHandler) serves as a
# threaded->async adapter for the watchdog observers
class AsyncFSEventAdapter(FileSystemEventHandler):
    __handler: AsyncFileSystemEventHandler

    def __init__(
        self,
        handler: AsyncFileSystemEventHandler,
        portal: BlockingPortal,
    ) -> None:
        super().__init__()
        self.__handler = handler
        self.__portal = portal

    def __repr__(self) -> str:
        return "{}({!r})".format(type(self).__name__, self.__handler)

    def dispatch(self, event: FileSystemEvent) -> None:
        self.__portal.call(self.__handler.dispatch, event)

    def __getattr__(self, name: str) -> Any:
        return getattr(self.__handler, name)


class AsyncFileSystemEventHandler:
    def __new__(
        cls,
        *args,
        portal: BlockingPortal,
        **kwargs,
    ) -> AsyncFSEventAdapter:
        """
        For sanity's sake, creating an async event handler will return a
        sync->async event adapter so that the return can be directly scheduled
        with the same way one would a standard FileSystemEventHandler.
        """
        self = super().__new__(cls)
        self.__init__(*args, **kwargs)
        return AsyncFSEventAdapter(self, portal)

    async def dispatch(self, event: FileSystemEvent) -> None:
        await self.on_any_event(event)
        # watchdog adds event types over time (attrib in 7.0, events_lost in 7.1.1). An
        # event type with no on_<type> coroutine here is ignored: raising AttributeError
        # would propagate through the portal onto the observer's dispatcher thread, which
        # only catches queue.Empty, so the observer would stop delivering events entirely.
        if (handler := getattr(self, f"on_{event.event_type}", None)) is not None:
            await handler(event)

    async def on_any_event(self, _: FileSystemEvent, /) -> None:
        pass

    async def on_attrib(self, _: AttribEvent, /) -> None:
        pass

    async def on_closed(self, _: ClosedEvent, /) -> None:
        pass

    async def on_closed_no_write(self, _: ClosedNoWriteEvent, /) -> None:
        pass

    async def on_created(self, _: CreatedEvent, /) -> None:
        pass

    async def on_deleted(self, _: DeletedEvent, /) -> None:
        pass

    async def on_events_lost(self, _: EventsLostEvent, /) -> None:
        pass

    async def on_modified(self, _: ModifiedEvent, /) -> None:
        pass

    async def on_moved(self, _: MovedEvent, /) -> None:
        pass

    async def on_opened(self, _: OpenedEvent, /) -> None:
        pass
