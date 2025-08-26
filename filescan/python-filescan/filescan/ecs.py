from __future__ import annotations

import typing
from datetime import datetime
from enum import StrEnum
from pathlib import Path
from pydantic import BaseModel, Field, model_validator, AnyUrl
from pydantic_core import core_schema as _cs
from pydantic_core.core_schema import CoreSchema
from typing import (
    Annotated, ClassVar, Any, Iterator, Literal, overload, Optional as O, Self,
    Iterable, Final,
)


class Array[T]:
    MISSING: ClassVar[Self]

    __in_record: bool
    __list: list[T]

    @classmethod
    def _make_list(cls, value: Any | list[Any] | None) -> list:
        if value is None:
            return []
        elif isinstance(value, list):
            return value
        else:
            return [value]

    @classmethod
    def _to_list(cls, value: Self) -> list[T]:
        return value.__list

    @classmethod
    def __get_pydantic_core_schema__(cls, source, handler) -> CoreSchema:
        item_type, = typing.get_args(source)
        list_schema = _cs.list_schema(handler.generate_schema(item_type))
        return _cs.chain_schema(
            [
                _cs.no_info_plain_validator_function(cls._make_list),
                list_schema,
                _cs.no_info_plain_validator_function(cls),
            ],
            serialization=_cs.plain_serializer_function_ser_schema(
                cls._to_list,
                return_schema = list_schema,
            ),
        )

    @overload
    def __init__(
        self,
        items: Iterable[T],
        *,
        in_record: Literal[True] = True,
    ) -> None:
        ...
    @overload
    def __init__(
        self,
        items: tuple[()] = (),
        *,
        in_record: Literal[False],
    ) -> None:
        ...
    def __init__(
        self,
        items: Iterable[T] = (),
        *,
        in_record: bool = True,
    ) -> None:
        self.__in_record = in_record
        self.__list = list(items)

    def __repr__(self) -> str:
        return repr(self.__list)

    @property
    def in_record(self) -> bool:
        return self.__in_record

    def __getitem__(self, index: int) -> T:
        return self.__list[index]

    def __len__(self) -> int:
        return len(self.__list)

    def __iter__(self) -> Iterator[T]:
        yield from self.__list

Array.MISSING = Array(in_record=False)


class _OctalInteger:
    @classmethod
    def __get_pydantic_core_schema__(cls, source, handler) -> CoreSchema:
        del source, handler
        return _cs.no_info_plain_validator_function(
            cls._validate,
            serialization=_cs.plain_serializer_function_ser_schema(
                cls._serialize,
            ),
        )

    @staticmethod
    def _validate(value: str | int) -> int:
        if not value:
            return 0
        elif isinstance(value, str):
            return int(value, 8)
        else:
            return value

    @staticmethod
    def _serialize(value: int) -> str:
        return oct(value).removeprefix("0o")


type Date = datetime
type Int = int
type Octal = Annotated[int, _OctalInteger]
type Keyword = str

FileType: Final = StrEnum("FileType", [
    "file", "dir", "symlink",
])

EventAgentIdStatus: Final = StrEnum("EventAgentIdStatus", [
    "verified", "mismatch", "missing", "auth_metadata_missing",
])
EventCategory: Final = StrEnum("EventCategory", [
    "api", "authentication", "configuration", "database", "driver", "email",
    "file", "host", "iam", "intrusion_detection", "library", "malware",
    "network", "package", "process", "registry", "session", "threat",
    "vulnerability", "web",
])

EventKind: Final = StrEnum("EventKind", [
    "alert", "asset", "enrichment", "event", "metric", "state",
    "pipeline_error", "signal",
])
EventOutcome: Final = StrEnum("EventOutcome", [
    "failure", "success", "unknown",
])
EventType: Final = StrEnum("EventType", [
    "access", "admin", "allowed", "change", "connection", "creation",
    "deletion", "denied", "end", "error", "group", "indicator", "info",
    "installation", "protocol", "start", "user",
])

class NestedModel(BaseModel):
    MISSING: ClassVar[Self]

    # helper fields
    in_record: Annotated[bool, Field(repr=False)] = True

    def __init_subclass__(cls) -> None:
        super().__init_subclass__()
        cls.MISSING = cls(in_record=False)

class Hash(NestedModel):
    # ECS fields
    md5: O[str] = None
    sha1: O[str] = None
    sha256: O[str] = None
    sha384: O[str] = None
    sha512: O[str] = None
    ssdeep: O[str] = None
    tlsh: O[str] = None

class File(NestedModel):
    # ECS nested objects
    hash: Hash = Hash.MISSING

    # ECS fields
    accessed: O[datetime] = None
    attributes: O[Array[str]] = Array.MISSING
    created: O[datetime] = None
    ctime: O[datetime] = None
    device: O[str] = None
    directory: O[Path] = None
    drive_letter: O[str] = None
    extension: O[str] = None
    fork_name: O[str] = None
    gid: O[int] = None
    group: O[str] = None
    inode: O[int] = None
    mime_type: O[str] = None
    mode: O[Octal] = None
    mtime: O[datetime] = None
    name: O[str] = None
    owner: O[str] = None
    path: Array[Path] = Array.MISSING
    size: O[int] = None
    target_path: Array[Path] = Array.MISSING
    type: O[FileType] = None
    uid: O[int] = None

    # non-ECS fields
    source: O[str] = None

class Event(NestedModel):
    # ECS fields
    action: O[str] = None
    agent_id_status: O[EventAgentIdStatus] = None
    category: O[Array[EventCategory]] = None
    code: O[str] = None
    created: O[datetime] = None
    dataset: O[str] = None
    duration: O[int] = None
    end: O[datetime] = None
    hash: O[str] = None
    id: Array[str] = Array.MISSING
    ingested: O[datetime] = None
    kind: O[EventKind] = None
    module: O[str] = None
    original: O[str] = None
    outcome: O[EventOutcome] = None
    provider: O[str] = None
    reason: O[str] = None
    reference: O[AnyUrl] = None
    risk_score: O[float] = None
    risk_score_norm: O[float] = None
    sequence: O[int] = None
    severity: O[int] = None
    start: O[datetime] = None
    timezone: O[str] = None
    type: O[EventType] = None
    url: O[AnyUrl] = None

class Network(NestedModel):
    # ECS fields
    # ...
    protocol: O[str] = None
    # ...

class Record(BaseModel):
    @model_validator(mode="wrap")
    @classmethod
    def _validate(cls, data, handler) -> Record:
        self = handler(data)
        self.raw = data
        return self

    # non-ECS fields
    raw: Annotated[Any, Field(repr=False, exclude=True)] = None

    # ECS nested objects
    event: Event = Event.MISSING
    file: File = File.MISSING
    hash: Hash = Hash.MISSING



"""

{
    "firstPacket" => 1744928590818,
    "destination" => {
        "port" => "80",
        "ip" => "10.201.0.3"
    },
    "totDataBytes" => 1150,
    "zeek" => {
        "fuid" => [
            [0] "FUCr6J13RGv5WRW0l4"
        ],
        "files" => {
            "mime_type" => "text/plain",
            "extracted_uri" => "extracted-files/HTTP-FUCr6J13RGv5WRW0l4-CdYi1W1dmkABlzvSL6-20250417222310.txt",
            "duration" => "0.000000",
            "extracted" => "HTTP-FUCr6J13RGv5WRW0l4-CdYi1W1dmkABlzvSL6-20250417222310.txt",
            "overflow_bytes" => "0",
            "missing_bytes" => "0",
            "sha1" => "60115647620cb3c25d5575e9a9d2bc2ec6cef0e6",
            "md5" => "5bcc33abffeb341d4ba5388cc20435eb",
            "analyzers" => [
                [0] "MD5",
                [1] "EXTRACT",
                [2] "PE_XOR",
                [3] "SHA1"
            ],
            "timedout" => "F",
            "depth" => "0",
            "local_orig" => "T",
            "total_bytes" => "1150",
            "seen_bytes" => "1150",
            "extracted_cutoff" => "F"
        },
        "ts" => "2025-04-17T22:23:10.818000128Z",
        "uid" => "CdYi1W1dmkABlzvSL6"
    },
    "timestamp" => 1744928590818,
    "length" => "0",
    "related" => {
        "hash" => [
            [0] "5bcc33abffeb341d4ba5388cc20435eb",
            [1] "60115647620cb3c25d5575e9a9d2bc2ec6cef0e6"
        ]
    },
    "@version" => "1",
    "tags" => [
        [0] "_filebeat_zeek_malcolm_upload",
        [1] "beats_input_codec_plain_applied",
        [2] "out1744928588"
    ],
    "host" => {
        "name" => "inl436717"
    },
    "source" => {
        "port" => "45003",
        "ip" => "10.10.10.1"
    },
    "@timestamp" => 2025-04-17T22:23:10.818000128Z,
    "rootId" => "CdYi1W1dmkABlzvSL6",
    "file" => {
        "size" => "1150",
        "path" => [
            [0] "HTTP-FUCr6J13RGv5WRW0l4-CdYi1W1dmkABlzvSL6-20250417222310.txt"
        ],
        "mime_type" => [
            [0] "text/plain"
        ],
        "source" => "HTTP",
        "type" => "file",
        "hash" => {
            "md5" => "5bcc33abffeb341d4ba5388cc20435eb",
            "sha1" => "60115647620cb3c25d5575e9a9d2bc2ec6cef0e6"
        }
    },
    "event" => {
        "id" => [
            [0] "CdYi1W1dmkABlzvSL6",
            [1] "FUCr6J13RGv5WRW0l4"
        ],
        "kind" => "event",
        "dataset" => "files",
        "hash" => "KVuaFhvVdS4SuYdbQaT24A==",
        "provider" => "zeek"
    },
    "protocol" => [
        [0] "http"
    ],
    "log" => {
        "file" => {
            "path" => "/zeek/current/files(out1744928588,pcap,1755723480152452309).log"
        },
        "offset" => 558
    },
    "message" => "1744928590.817840\tFUCr6J13RGv5WRW0l4\tCdYi1W1dmkABlzvSL6\t10.10.10.1\t45003\t10.201.0.3\t80\tHTTP\t0\tMD5,EXTRACT,PE_XOR,SHA1\ttext/plain\t-\t0.000000\tT\tF\t1150\t1150\t0\t0\tF\t-\t5bcc33abffeb341d4ba5388cc20435eb\t60115647620cb3c25d5575e9a9d2bc2ec6cef0e6\t-\tHTTP-FUCr6J13RGv5WRW0l4-CdYi1W1dmkABlzvSL6-20250417222310.txt\tF\t-\t-",
    "lastPacket" => "1744928590818",
    "ecs" => {
        "version" => "8.0.0"
    },
    "input" => {
        "type" => "log"
    },
    "network" => {
        "protocol" => [
            [0] "http"
        ],
        "is_orig" => "F",
        "bytes" => 1150
    },
    "agent" => {
        "name" => "inl436717",
        "id" => "d81c409d-1e01-4aa2-937d-fcee99b61feb",
        "version" => "8.17.0",
        "type" => "filebeat",
        "ephemeral_id" => "f1fff224-bbe3-4989-afb2-af70a7aaab36"
    }
}


"""
