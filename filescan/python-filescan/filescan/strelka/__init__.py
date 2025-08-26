from __future__ import annotations

import anyio
import grpc.aio
import json
import uuid
from itertools import chain
from pathlib import Path
from typing import AsyncIterator, Iterator, Any, cast
from uuid import UUID

from ..aio import (
    SingleOrIterable, chunk_async_data_stream, asynciter_save_exception,
)
from .proto import strelka_pb2_grpc
from .proto.strelka_pb2 import (
    Attributes, Request, ScanFileRequest,
    ScanResponse as ScanResponse,
)


type Metadata = dict[str, str]
type Event = dict[str, Any]


class StrelkaFrontend:
    server: str
    credentials: grpc.ChannelCredentials | None
    gatekeeper: bool
    source: str | None
    client: str
    timeout: float
    chunksize: int

    def __init__(
        self, 
        host: str = 'localhost',
        port: int = 57314,
        *,
        cert: Path | None = None,
        secure: bool = False,
        gatekeeper: bool = True,
        source: str | None = None,
        client: str = 'strelka-python',
        timeout: float = 60.0,
        chunksize: int = 32768,
    ) -> None:
        self.server = f'{host}:{port}'
        if secure or cert:
            cert_data = cert.read_bytes() if cert else None
            self.credentials = grpc.ssl_channel_credentials(cert_data)
        else:
            self.credentials = None
        self.gatekeeper = gatekeeper
        self.source = source
        self.client = client
        self.timeout = timeout
        self.chunksize = chunksize

    def open_channel(self) -> grpc.aio.Channel:
        if self.credentials:
            return grpc.aio.secure_channel(self.server, self.credentials)
        else:
            return grpc.aio.insecure_channel(self.server)

    @staticmethod
    def _typecheck_metadata(md: Any) -> Metadata:
        if md is None:
            return {}
        elif not isinstance(md, dict):
            raise TypeError(f"metadata is not dictionary: {md!r}")
        elif not all(isinstance(e, str) for e in chain(md.keys(), md.values())):
            raise TypeError(f"metadata has non-string keys/values: {md!r}")
        return md

    async def request_for_data(
        self,
        filename: str,
        data: SingleOrIterable[bytes],
        *,
        uid: UUID | None = None,
        source: str | None = None,
        metadata: Metadata | None = None,
    ) -> AsyncIterator[ScanFileRequest]:
        request = Request(
            id=str(uid or uuid.uuid4()),
            client=self.client,
            source=(source or self.source),
            gatekeeper=self.gatekeeper,
        )
        attributes=Attributes(
            filename=filename,
            metadata=self._typecheck_metadata(metadata),
        )

        async for chunk in chunk_async_data_stream(data, self.chunksize):
            yield ScanFileRequest(
                data=chunk,
                request=request,
                attributes=attributes,
            )

    def request_for_path(
        self,
        path: Path,
        *,
        uid: UUID | None = None,
        source: str | None = None,
        metadata: Metadata | None = None,
    ) -> AsyncIterator[ScanFileRequest]:
        def _chunk_file(path: Path) -> Iterator[bytes]:
            with path.open('rb') as fh:
                while True:
                    chunk = fh.read(self.chunksize)
                    if not chunk:
                        break
                    yield chunk

        return self.request_for_data(
            str(path),
            _chunk_file(path),
            uid=uid,
            source=source,
            metadata=metadata,
        )

    async def scan(
        self,
        request: AsyncIterator[ScanFileRequest],
    ) -> AsyncIterator[Event]:
        async with self.open_channel() as chan:
            # because of the way pygrpc implements their async hooks, their
            # Cython code eats any exception raised by an async iterator used as
            # a client->server stream, so we wrap the async iterator so we can
            # retrieve a raised exception later
            request, hold = asynciter_save_exception(request)
            # wrap our connected channel with the frontend stubbed service
            stub = strelka_pb2_grpc.FrontendStub(chan)
            try:
                # submit our file for scanning, and return parsed responses as
                # they become available from the frontend
                async for msg in stub.ScanFile(
                    request,
                    timeout=self.timeout,
                ):
                    yield json.loads(msg.event)
            # see comment above about pygrpc and eating exception
            except anyio.get_cancelled_exc_class() as e:
                raise (hold.exception() or e) from None


