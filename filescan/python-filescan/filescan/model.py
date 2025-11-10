from __future__ import annotations

from . import logging
log = logging.getLogger(__name__)

import hashlib
import magic
import mmap
import uuid
from datetime import datetime, UTC, timedelta
from itertools import chain
from pathlib import Path, PurePosixPath
from pydantic import (
    BaseModel, Discriminator, Field, PlainSerializer, PlainValidator, TypeAdapter, computed_field, model_validator,
)
from typing import ClassVar, Any, Final, Iterator, Literal, Self, Annotated
from uuid import UUID

from .utils import group_items


def _ensure_utc(v: str | None | datetime) -> datetime:
    if v is None:
        v = datetime.now(UTC)
    elif isinstance(v, str):
        v = datetime.fromisoformat(v)
    return v.astimezone(UTC)


type UTCDatetime = Annotated[
    datetime,
    PlainValidator(_ensure_utc),
    PlainSerializer(datetime.isoformat),
]


class FileEvent(BaseModel):
    magic: ClassVar = magic.Magic(mime=True, mime_encoding=True)

    @model_validator(mode='wrap')
    @classmethod
    def _validate(cls, data, handler) -> Self:
        if isinstance(data, cls):
            return data

        if not isinstance(data, dict):
            raise TypeError(type(data))

        if (local_path := data.get('local_path')):
            fh = None
            try:
                if (path := data.get('path')) is None:
                    path = PurePosixPath(local_path)
                if (size := data.get('size')) is None:
                    size = local_path.stat().st_size
                if (mime_type := data.get('mime_type')) is None:
                    fh = fh or local_path.open('rb')
                    mime_type = cls.magic.from_descriptor(fh.fileno())
                if (sha256 := data.get('sha256')) is None:
                    fh = fh or local_path.open('rb')
                    try:
                        with mmap.mmap(
                            fh.fileno(), 0,
                            access=mmap.ACCESS_READ,
                        ) as buf:
                            sha256 = hashlib.sha256(buf).hexdigest()
                    except ValueError:
                        sha256 = hashlib.sha256(b'').hexdigest()
            finally:
                if fh:
                    fh.close()

            data.update({
                'path': path,
                'size': size,
                'sha256': sha256,
                'mime_type': mime_type,
            })

        return handler(data)

    path: PurePosixPath
    size: int
    sha256: str
    mime_type: str

    local_path: Annotated[Path | None, Field(exclude=True)] = None

    @classmethod
    def for_path(cls, local_path: Path, **kw) -> Self:
        return cls.model_validate({'local_path': local_path, **kw})

    def resolve_path(self, path_maps: dict[PurePosixPath, Path]) -> Path:
        for base, real in path_maps.items():
            if self.path.is_relative_to(base):
                if (new := real / self.path.relative_to(base)).exists():
                    return new
        for base, real in path_maps.items():
            if (new := real / self.path).exists():
                log.warning(
                    'file exists in search path, but without prefix: %s => %s',
                    self.path, base,
                )
                return new
        if (new := Path(self.path)).exists():
            log.warning('file exists, but not in search path: %s', new)
            return new
        raise FileNotFoundError(self.path)


class MessageBase(BaseModel):
    id: UUID
    time: UTCDatetime = Field(default_factory=lambda: datetime.now(UTC))

class ScanRequest(MessageBase):
    type: Annotated[Literal['request'], Field(repr=False)] = 'request'
    id: UUID = Field(default_factory=uuid.uuid4)
    file: FileEvent
    source: str | None = None
    metadata: dict[str, str] | None = None

    def get_submit(self, count: int) -> ScanSubmit:
        return ScanSubmit(
            id=self.id,
            count=count,
            file=self.file,
            source=self.source,
            metadata=self.metadata,
        )

    def get_begin(self, name: str) -> ScanBegin:
        return ScanBegin(
            id=self.id,
            name=name,
        )

class ScanResult(MessageBase):
    type: Annotated[Literal['result'], Field(repr=False)] = 'result'
    name: str
    result: Any = None
    error: Any = None

    @property
    def _key(self) -> str:
        return f'{self.id}:{self.name}'

class ScanSubmit(MessageBase):
    type: Annotated[Literal['submit'], Field(repr=False)] = 'submit'
    count: int
    file: FileEvent
    source: str | None = None
    metadata: dict[str, str] | None = None

class ScanBegin(MessageBase):
    type: Annotated[Literal['begin'], Field(repr=False)] = 'begin'
    name: str

    @property
    def _key(self) -> str:
        return f'{self.id}:{self.name}'

    def get_result(
        self, result: Any = None,
        *,
        error: Any = ...,
        time: datetime | None = None,
    ) -> ScanResult:
        return ScanResult(
            id=self.id,
            time=(time or datetime.now(UTC)),
            name=self.name,
            result=result,
            error=(None if error is ... else str(error)),
        )

    def get_end(self, *, time: datetime | None = None) -> ScanEnd:
        return ScanEnd(
            id=self.id,
            time=(time or datetime.now(UTC)),
            name=self.name,
        )

    def get_timeout(self, *, time: datetime | None = None) -> ScanTimeout:
        return ScanTimeout(
            id=self.id,
            time=(time or datetime.now(UTC)),
            name=self.name,
        )

class ScanTimeout(MessageBase):
    type: Annotated[Literal['timeout'], Field(repr=False)] = 'timeout'
    name: str

    @property
    def _key(self) -> str:
        return f'{self.id}:{self.name}'

class ScanEnd(MessageBase):
    type: Annotated[Literal['end'], Field(repr=False)] = 'end'
    name: str

    @property
    def _key(self) -> str:
        return f'{self.id}:{self.name}'

class ScanComplete(MessageBase):
    type: Annotated[Literal['complete'], Field(repr=False)] = 'complete'
    success: set[str] = Field(default_factory=set)
    failure: set[str] = Field(default_factory=set)
    expired: set[str] = Field(default_factory=set)


type AnyScanRequest = Annotated[
    ScanRequest,
    # restore this if we end up with additional request message types
    None #Discriminator('type')
]
AnyScanRequestType: Final = TypeAdapter(AnyScanRequest)

type AnyScanResult = Annotated[
    ScanResult,
    # restore this if we end up with additional result message types
    None #Discriminator('type')
]
AnyScanResultType: Final = TypeAdapter(AnyScanResult)

type AnyScanNotification = Annotated[
    ScanSubmit | ScanBegin | ScanEnd | ScanTimeout | ScanComplete,
    Discriminator('type')
]
AnyScanNotificationType: Final = TypeAdapter(AnyScanNotification)

type AnyScanMessage = Annotated[
    ScanRequest | ScanResult | ScanSubmit | ScanBegin | ScanEnd | ScanTimeout | ScanComplete,
    Discriminator('type')
]
AnyScanMessageType: Final = TypeAdapter(AnyScanMessage)



class FileScanMap:
    scans: dict[UUID, FileScan]
    max_scan_time: timedelta | None

    def __init__(self, *, max_scan_time: timedelta | None = None) -> None:
        self.scans = {}
        self.max_scan_time = max_scan_time

    def update(self, event: MessageBase) -> bool:
        if isinstance(event, ScanRequest | ScanSubmit | ScanBegin):
            if (scan := self.scans.get(event.id)) is None:
                scan = self.scans[event.id] = FileScan.for_event(
                    event,
                    max_scan_time=self.max_scan_time,
                )
            return scan.update(event)
        elif isinstance(event, ScanResult):
            if (scan := self.scans.get(event.id)) is not None:
                return scan.update(event)
        elif isinstance(event, ScanComplete):
            return False
        log.debug('ignoring message: %r', event)
        return False

    def get_completed_scans(self) -> Iterator[FileScan]:
        (_, complete), (_, expired), (_, working) = group_items(
            self.scans.values(),
            lambda s: (s.complete, s.expired),
            [
                (True, ...),    # completed (regardless of expiration)
                (..., True),    # expired (regardless of  completion)
                (False, False), # neither completed nor expired
            ],
        )
        self.scans.clear()
        self.scans.update({s.id: s for s in working})
        yield from {s.id: s for s in chain(complete, expired)}.values()


class FileScan(BaseModel):
    id: UUID
    start: UTCDatetime
    source: str | None = None
    file: FileEvent | None = None
    metadata: dict[str, str] | None = None
    expected: Annotated[int, Field(exclude=True)] = -1
    results: dict[str, FileResult] = {}
    min_scan_time: Annotated[timedelta, Field(exclude=True)] = timedelta(seconds=5)
    max_scan_time: Annotated[timedelta | None, Field(exclude=True)] = None

    @computed_field
    @property
    def end(self) -> UTCDatetime | None:
        end_times = [r.end for r in self.results.values() if r.end]
        return max(end_times) if end_times else None

    @property
    def complete(self) -> bool:
        elapsed = datetime.now(UTC) - self.start
        return ( \
                ((self.expected >= 0) and len(self.results) >= self.expected) \
                or ((elapsed >= self.min_scan_time) and not self.expired) \
            ) \
            and all(s.complete for s in self.results.values())

    @property
    def expired(self) -> bool:
        elapsed = datetime.now(UTC) - self.start
        return self.max_scan_time is not None \
            and elapsed > self.max_scan_time

    @classmethod
    def for_event(
        cls,
        event: MessageBase,
        *,
        max_scan_time: timedelta | None = None,
    ) -> Self:
        return cls(
            id=event.id,
            start=event.time,
            max_scan_time=max_scan_time,
        )

    def update(self, event: MessageBase) -> bool:
        if event.id == self.id:
            if isinstance(event, ScanSubmit):
                self.expected = max(self.expected, event.count)
                self.start = min(self.start, event.time)
                self.source = event.source
                self.file = event.file
                self.metadata = event.metadata
                return True
            elif isinstance(event, ScanBegin):
                if self.results.get(event.name) is None:
                    self.results[event.name] = FileResult.for_event(event)
                    return True
            elif isinstance(event, ScanResult):
                if (result := self.results.get(event.name)) is not None:
                    return result.update(event)
        log.debug('ignoring message: %r', event)
        return False

    def get_complete(self) -> ScanComplete:
        event = ScanComplete(id=self.id)
        for name, result in self.results.items():
            if result.complete:
                if result.errored:
                    event.failure.add(name)
                else:
                    event.success.add(name)
            else:
                event.expired.add(name)
        return event


class FileResult(BaseModel):
    id: Annotated[UUID, Field(exclude=True)]
    name: Annotated[str, Field(exclude=True)]
    start: UTCDatetime
    end: UTCDatetime | None = None
    complete: Annotated[bool, Field(exclude=True)] = False
    errored: Annotated[bool, Field(exclude=True)] = False
    result: Any | None = None
    error: Any | None = None

    @property
    def duration(self) -> float:
        if not self.complete:
            raise ValueError('scan is not complete')
        assert self.end is not None
        return (self.end - self.start).total_seconds()

    @classmethod
    def for_event(cls, event: ScanBegin) -> Self:
        return cls(
            id=event.id,
            name=event.name,
            start=event.time,
        )

    def update(self, event: ScanResult) -> bool:
        if (event.id == self.id) and (event.name == self.name):
            if isinstance(event, ScanResult):
                if not self.complete:
                    if self.end is None:
                        self.end = event.time
                    else:
                        self.end = max(self.end, event.time)
                    self.complete = True
                    if event.error is not None:
                        self.errored = True
                    self.result = event.result
                    self.error = event.error
                    return True
                else:
                    log.error('duplicate scan completion? %r', event)
                    return False
        log.debug('ignoring message: %r', event)
        return False


