from __future__ import annotations

import anyio
from abc import ABCMeta
import dataclasses
import functools
import inspect
from typing import Any, ClassVar, Concatenate, Iterator, Coroutine, overload, override, Awaitable, cast
from typing import Iterable, Callable, Any
from types import CoroutineType
import redis.asyncio
import redis.asyncio.client

# from asyncio import TaskGroup
from pydantic import BaseModel, TypeAdapter
from itertools import chain

from filescan.aio import WorkerPool

from . import logging

# from .asyncio import EventLoop, TaskCreatorMixin


type Handler[*A] = Callable[[*A], Coroutine[Any, Any, None]]


class HandlerMixin[*A]:
    HANDLER_PREFIX: ClassVar = 'on_'

    def get_handlers(self) -> Iterator[str]:
        yield from (n.removeprefix(self.HANDLER_PREFIX) for n in dir(self) if n.startswith(self.HANDLER_PREFIX))

    def get_handler(self, key: Any) -> Handler[*A] | None:
        return getattr(self, f'{self.HANDLER_PREFIX}{key!s}', None)

    async def call_handler(
        self,
        key: Any,
        *a: *A,
    ) -> None:
        if handler := self.get_handler(key):
            return await handler(*a)


type _Model[T: BaseModel] = type[T] | TypeAdapter[T]
type _Coro = Coroutine[Any, Any, None] | CoroutineType[Any, Any, None]
type _Method[S, **P, T, C: _Coro] = Callable[Concatenate[S, T, P], C]
type _Function[**P, T, C: _Coro] = Callable[Concatenate[T, P], C]


@overload
def decode_data_as_model[S, **P, T: BaseModel, C: _Coro](_: _Method[S, P, T, C], /) -> _Method[S, P, str | None, C]: ...
@overload
def decode_data_as_model[**P, T: BaseModel, C: _Coro](_: _Function[P, T, C], /) -> _Function[P, str | None, C]: ...
def decode_data_as_model[S, **P, T: BaseModel, C: _Coro](
    async_func: _Method[S, P, T, C] | _Function[P, T, C],
    /,
) -> _Method[S, P, str | None, C] | _Function[P, str | None, C]:
    argspec = inspect.getfullargspec(async_func)
    notes = inspect.get_annotations(async_func, eval_str=True)
    assert len(argspec.args) > 0, 'wrapped function takes no arguments'
    model = cast(_Model[T], notes[argspec.args[-1]])
    # this is probably a little bit fragile, but it is what it is
    if argspec.args[0] == 'self':
        assert len(argspec.args) > 1, 'wrapped method takes no arguments'
        async_func = cast(Callable[Concatenate[S, T, P], C], async_func)

        @functools.wraps(async_func)
        def method_wrapper(self: S, data: str | None, *args: P.args, **kwargs: P.kwargs) -> C:
            if not data:

                async def dummy() -> None:
                    return None

                return cast(C, dummy())
            if isinstance(model, TypeAdapter):
                return async_func(self, model.validate_json(data), *args, **kwargs)
            else:
                return async_func(self, model.model_validate_json(data), *args, **kwargs)

        return method_wrapper
    else:
        async_func = cast(Callable[Concatenate[T, P], C], async_func)

        @functools.wraps(async_func)
        def function_wrapper(data: str | None, *args: P.args, **kwargs: P.kwargs) -> C:
            if not data:

                async def dummy() -> None:
                    return None

                return cast(C, dummy())
            if isinstance(model, TypeAdapter):
                return async_func(model.validate_json(data), *args, **kwargs)
            else:
                return async_func(model.model_validate_json(data), *args, **kwargs)

        return function_wrapper


type Key = str


class Alias:
    def __new__(cls, value: Alias | str) -> Alias:
        if isinstance(value, Alias):
            return value
        self = super().__new__(cls)
        self.__init__(value)
        return self

    def __init__(self, value: Alias | str) -> None:
        assert isinstance(value, str)
        object.__setattr__(self, 'value', value)

    value: str

    def __setattr__(self, key: str, _: Any) -> None:
        raise dataclasses.FrozenInstanceError(self, name=key)

    def __repr__(self) -> str:
        return f'Alias({self!s})'

    def __str__(self) -> str:
        return self.value

    def __hash__(self) -> int:
        return hash(self.value)

    def __eq__(self, other: object) -> bool:
        if isinstance(other, Alias):
            return self.value == other.value
        elif isinstance(other, str):
            return self.value == other
        else:
            return NotImplemented


class AliasMapping:
    _key_to_alias: dict[Key, Alias]
    _alias_to_key: dict[Alias, Key]

    def __init__(
        self,
        aliases_to_keys: dict[Alias | str, Key] | None = None,
        /,
        **aliases_to_keys_kw: Key,
    ) -> None:
        a2k = {
            Alias(k): v
            for k, v in chain(
                (aliases_to_keys or {}).items(),
                aliases_to_keys_kw.items(),
            )
        }
        if len(set(a2k.keys())) != len(set(a2k.values())):
            raise ValueError('alias/key mappings are not unique')
        self._alias_to_key = {k: v for k, v in a2k.items()}
        self._key_to_alias = {v: k for k, v in a2k.items()}

    def __repr__(self) -> str:
        return '<{} {{{}}}>'.format(
            type(self).__qualname__,
            ', '.join(f'{k}={v}' for k, v in self._alias_to_key.items()),
        )

    def contains_alias(self, alias: Alias) -> bool:
        return alias in self._alias_to_key

    def contains_key(self, key: Key) -> bool:
        return key in self._key_to_alias

    def remove_alias(self, alias: Alias) -> None:
        if key := self._alias_to_key.pop(alias, None):
            self._key_to_alias.pop(key)

    def remove_key(self, key: Key) -> None:
        if alias := self._key_to_alias.pop(key, None):
            self._alias_to_key.pop(alias)

    def add_alias(self, alias: Alias | str, key: Key) -> None:
        alias = Alias(alias)
        self.remove_alias(alias)
        self.remove_key(key)
        self._alias_to_key[alias] = key
        self._key_to_alias[key] = alias

    def alias(self, key: Key) -> Alias:
        if self.contains_key(key):
            return self._key_to_alias[key]
        else:
            return Alias(key)

    def alias_all(self, keys: Iterable[Key]) -> Iterator[Alias]:
        yield from map(self.alias, keys)

    def unalias(self, alias: Alias) -> Key:
        if self.contains_alias(alias):
            return self._alias_to_key[alias]
        else:
            return str(alias)

    def unalias_all(self, aliases: Iterable[Alias]) -> Iterator[Key]:
        yield from map(self.unalias, aliases)


type WorkCoro = Coroutine[None, None, None]


class RedisConnection[OptsT](metaclass=ABCMeta):
    type Redis = redis.asyncio.Redis

    _redis: Redis
    _alias_map: AliasMapping
    _options: OptsT | None
    _workers: int

    def __init__(
        self,
        host: str,
        port: int = 6379,
        *,
        db: int = 0,
        options: OptsT | None = None,
        decode_responses: bool = True,
        aliases_to_keys: dict[Alias | str, Key] | None = None,
        workers: int = 0,
        **kw,
    ) -> None:
        super().__init__()
        self._redis = redis.asyncio.Redis(
            host=host,
            port=port,
            db=db,
            decode_responses=decode_responses,
            **kw,
        )
        self._options = options
        self._alias_map = AliasMapping(aliases_to_keys)
        self._workers = workers
        self.init()

    @property
    def options(self) -> OptsT:
        if self._options is None:
            raise ValueError("no associated options")
        return self._options

    @property
    def aliases(self) -> AliasMapping:
        return self._alias_map

    async def run(self, *, name: str | None = None) -> None:
        await self.pre_run()
        async with anyio.create_task_group() as group:
            pool = WorkerPool(group, name=name, workers=self._workers)
            for coro in self.get_work_coros():
                await pool.create_worker(coro)
        await self.post_run()

    @property
    def redis(self) -> Redis:
        return self._redis

    async def pre_run(self) -> None:
        pass

    async def post_run(self) -> None:
        pass

    def init(self) -> None:
        pass

    def get_work_coros(self) -> Iterable[WorkCoro]:
        return ()


class RedisPublisher[OptsT](RedisConnection[OptsT]):
    async def subscribers(self, *channels: Alias | str, **kw) -> dict[Alias, int]:
        return {
            self.aliases.alias(k): v
            for k, v in await self.redis.pubsub_numsub(
                *self.aliases.unalias_all(map(Alias, channels)),
                **kw,
            )
        }

    async def publish(
        self,
        data: BaseModel,
        channel: Alias | str,
        **kw,
    ) -> int:
        return await self.redis.publish(
            self.aliases.unalias(Alias(channel)),
            data.model_dump_json(),
            **kw,
        )


type PubSub = redis.asyncio.client.PubSub
type Message = dict[str, Any]


class RedisSubscriber[OptsT](RedisConnection[OptsT], HandlerMixin[str | None]):
    HANDLER_PREFIX: ClassVar = 'on_message_'

    _channel_aliases: set[Alias]
    _subscribed_aliases: set[Alias]
    _pubsub: PubSub

    def __init__(
        self,
        host: str,
        port: int = 6379,
        *,
        db: int = 0,
        options: OptsT | None = None,
        decode_responses: bool = True,
        channels: Iterable[Alias | str] = (),
        aliases_to_keys: dict[Alias | str, Key] | None = None,
        workers: int = 0,
        **kw,
    ) -> None:
        super().__init__(
            host,
            port,
            db=db,
            options=options,
            decode_responses=decode_responses,
            aliases_to_keys=aliases_to_keys,
            workers=workers,
            **kw,
        )
        self._pubsub = self.redis.pubsub()
        self._channel_aliases = set(
            map(
                Alias,
                chain(
                    channels,
                    map(Alias, self.get_handlers()),
                ),
            )
        )
        self._subscribed_aliases = set()

    async def add_subscribed_channel(self, alias: Alias | str) -> None:
        self._channel_aliases.add(Alias(alias))
        await self.ensure_subscribed()

    async def remove_subscribed_channel(self, alias: Alias | str) -> None:
        self._channel_aliases.discard(Alias(alias))
        await self.ensure_subscribed()

    async def ensure_subscribed(self) -> None:
        all_keys = set(self.aliases.unalias_all(self._channel_aliases))
        sub_keys = set(self.aliases.unalias_all(self._subscribed_aliases))

        if to_sub := all_keys - sub_keys:
            await self.pubsub.subscribe(*to_sub)
            self._subscribed_aliases |= set(self.aliases.alias_all(to_sub))
        if to_unsub := sub_keys - all_keys:
            await self.pubsub.unsubscribe(*to_unsub)
            self._subscribed_aliases -= set(self.aliases.alias_all(to_unsub))

    @property
    def pubsub(self) -> PubSub:
        return self._pubsub

    @property
    def channels(self) -> Iterator[Alias]:
        yield from self._channel_aliases

    @property
    def subscribed(self) -> Iterator[Alias]:
        yield from self._subscribed_aliases

    @override
    def get_work_coros(self) -> Iterable[WorkCoro]:
        async def work() -> None:
            logging.debug('starting Redis subscriber: %r', self)
            while True:
                await self.dispatch_message(await self.get_message())

        return [*super().get_work_coros(), work()]

    async def get_message(self, timeout: float | None = None) -> Message:
        while True:
            await self.ensure_subscribed()
            msg = await self.pubsub.get_message(timeout=timeout)
            if msg is not None:
                return msg
            await anyio.sleep(0.1)

    async def dispatch_message(self, message: dict[str, Any]) -> None:
        msg_type, key, data = map(message.get, ('type', 'channel', 'data'))
        if msg_type != 'message' or not key:
            return
        channel = self.aliases.alias(key)
        async with anyio.create_task_group() as group:
            group.start_soon(
                self.on_message,
                data,
                channel,
                name='message_handler',
            )
            group.start_soon(
                self.call_handler,
                channel,
                data,
                name=f'{channel}_handler',
            )

    async def on_message(self, data: str | None, channel: Alias, /) -> None:
        pass


class RedisListWatcher[OptsT](RedisConnection[OptsT], HandlerMixin[str | None]):
    HANDLER_PREFIX: ClassVar = 'on_item_'

    _list_aliases: set[Alias]

    def __init__(
        self,
        host: str,
        port: int = 6379,
        *,
        db: int = 0,
        options: OptsT | None = None,
        decode_responses: bool = True,
        list_keys: Iterable[Alias | str] = (),
        aliases_to_keys: dict[Alias | str, Key] | None = None,
        workers: int = 0,
        **kw,
    ) -> None:
        super().__init__(
            host,
            port,
            db=db,
            options=options,
            decode_responses=decode_responses,
            aliases_to_keys=aliases_to_keys,
            workers=workers,
            **kw,
        )
        self._list_aliases = set(
            map(
                Alias,
                chain(
                    list_keys,
                    map(Alias, self.get_handlers()),
                ),
            )
        )

    def add_watched_list(self, key: Alias | str) -> None:
        self._list_aliases.add(Alias(key))

    def remove_watched_list(self, key: Alias | str) -> None:
        self._list_aliases.discard(Alias(key))

    @property
    def keys(self) -> Iterator[Alias]:
        yield from self._list_aliases

    @override
    def get_work_coros(self) -> Iterable[WorkCoro]:
        async def work() -> None:
            logging.debug('starting Redis list watcher: %r', self)
            while True:
                await self.dispatch_item(*await self.get_item())

        return [*super().get_work_coros(), work()]

    async def blpop(
        self,
        lists: Iterable[Alias],
        **kw,
    ) -> tuple[Alias, str]:
        key, value = await cast(
            Awaitable[tuple[Key, str]],
            self.redis.blpop(list(self.aliases.unalias_all(lists)), **kw),
        )
        return self.aliases.alias(key), value

    async def get_item(self, **kw) -> tuple[Alias, str]:
        return await self.blpop(self._list_aliases, **kw)

    async def dispatch_item(self, list_key: Alias, data: str) -> None:
        async with anyio.create_task_group() as group:
            group.start_soon(
                self.on_item,
                data,
                list_key,
                name='item_handler',
            )
            group.start_soon(
                self.call_handler,
                list_key,
                data,
                name=f'{list_key}_handler',
            )

    async def on_item(self, data: str, key: Alias, /) -> None:
        pass
