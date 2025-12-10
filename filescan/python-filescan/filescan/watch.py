from __future__ import annotations

from anyio.from_thread import BlockingPortal
from typing import Any
from watchdog.events import (
    DirCreatedEvent,
    DirDeletedEvent,
    DirModifiedEvent,
    DirMovedEvent,
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
        await getattr(self, f"on_{event.event_type}")(event)

    async def on_any_event(self, _: FileSystemEvent, /) -> None:
        pass

    async def on_closed(self, _: ClosedEvent, /) -> None:
        pass

    async def on_closed_no_write(self, _: ClosedNoWriteEvent, /) -> None:
        pass

    async def on_created(self, _: CreatedEvent, /) -> None:
        pass

    async def on_deleted(self, _: DeletedEvent, /) -> None:
        pass

    async def on_modified(self, _: ModifiedEvent, /) -> None:
        pass

    async def on_moved(self, _: MovedEvent, /) -> None:
        pass

    async def on_opened(self, _: OpenedEvent, /) -> None:
        pass
