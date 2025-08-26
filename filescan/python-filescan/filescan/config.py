from __future__ import annotations

import copy
import io
import os
import ruamel.yaml
import ruamel.yaml.constructor
import string
import re
from pathlib import Path, PurePosixPath as PurePath
from pydantic import BaseModel, Discriminator, PlainValidator
from typing import Annotated, Any, ClassVar, Final, Literal, Self, override
from . import logging

from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from _typeshed import SupportsRead
else:
    type SupportsRead[T] = "_typeshed.SupportsRead[T]"

log = logging.getLogger(__name__)


VAR_REGEX: Final = re.compile(r'\$\{([A-Za-z_][A-Za-z0-9_]*)\}')

class EnvironAwareConstructor(ruamel.yaml.constructor.RoundTripConstructor):
    environ: ClassVar = os.environ

    @override
    def construct_scalar(self, node: ruamel.yaml.ScalarNode) -> Any:
        new = copy.deepcopy(node)
        new.value = string.Template(new.value).safe_substitute(self.environ)
        for var in VAR_REGEX.finditer(new.value):
            log.warning(
                'unreplaced environment variable in config: %s',
                var.group(1),
            )
        new.value = VAR_REGEX.sub('', new.value)
        return super().construct_scalar(new)


yaml = ruamel.yaml.YAML()
yaml.Constructor = EnvironAwareConstructor


type DirWatchStrategy = Literal['guess', 'inotify', 'polling']
type ResolvedPath = Annotated[Path, PlainValidator(lambda p: Path(p).resolve())]

class DirectoryWatch(BaseModel, frozen=True):
    type: Literal["directory"] = "directory"
    path: ResolvedPath
    recursive: bool = False
    strategy: DirWatchStrategy = 'guess'

type NonEmptyString = Annotated[str, PlainValidator(lambda v: v if v else None)]

class RedisOptions(BaseModel, frozen=True):
    host: str = 'localhost'
    port: int = 6379
    db: int = 0
    username: NonEmptyString | None = None
    password: NonEmptyString | None = None

type RedisWatchMethod = Literal['list', 'pubsub']

class RedisWatch(BaseModel, frozen=True):
    type: Literal['redis'] = 'redis'
    redis: RedisOptions | None = None
    method: RedisWatchMethod = 'list'
    keys: list[str] = []
    source: str | None = None

type AnyWatch = Annotated[DirectoryWatch | RedisWatch, Discriminator('type')]

class RedisKeys(BaseModel, frozen=True):
    request: str = "filescan_request"
    notify: str = "filescan_notify"
    result: str = "filescan_result"

class RedisOutputOptions(RedisOptions, frozen=True):
    keys: RedisKeys = RedisKeys()

class BaseConfig(BaseModel, frozen=True):
    redis: RedisOutputOptions = RedisOutputOptions()
    path_maps: dict[PurePath, Path] = {}

    @classmethod
    def from_string(cls, data: str) -> Self:
        return cls.from_file(io.StringIO(data))

    @classmethod
    def from_path(cls, path: Path) -> Self:
        return cls.from_file(path.open('r'))

    @classmethod
    def from_file(cls, file: SupportsRead[str]) -> Self:
        return cls.model_validate(yaml.load(file))

