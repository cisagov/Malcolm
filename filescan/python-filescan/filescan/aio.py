from __future__ import annotations

import anyio
import concurrent.futures
import contextlib
import functools
import human_id
import logging
import signal
import types
from anyio.abc import CancelScope, TaskGroup
from itertools import count
from typing import (
    Any,
    AsyncGenerator,
    Awaitable,
    Callable,
    Coroutine,
    Final,
    Self,
    AsyncIterator,
    Iterator,
    Iterable,
    Generator,
    AsyncIterable,
)


log = logging.Logger(__name__)


type AnyAwaitable[T] = Awaitable[T] | Coroutine[None, None, T] | types.CoroutineType[None, None, T]


def run_as_main[T](main: AnyAwaitable[T]) -> T:
    async def _helper() -> T:
        async with main_task_group():
            return await main

    return anyio.run(_helper)


@contextlib.asynccontextmanager
async def main_task_group(run_forever: bool = False) -> AsyncGenerator[TaskGroup]:
    async with anyio.create_task_group() as group, _atexit:
        group.start_soon(_signal_handler, group.cancel_scope)
        if run_forever:
            group.start_soon(anyio.sleep_forever)
        yield group


async def _signal_handler(scope: CancelScope) -> None:
    with anyio.open_signal_receiver(signal.SIGINT, signal.SIGTERM) as signals:
        async for signum in signals:
            log.warning('caught %s, stopping event loop', signum.name)
            scope.cancel()
            return


class AtEventLoopExit:
    _callbacks: list[Callable[[], Any]]

    def __init__(self) -> None:
        self._callbacks = []

    def add_exit_callback[**P](
        self,
        callback: Callable[P, Any],
        *a: P.args,
        **kw: P.kwargs,
    ) -> None:
        self._callbacks.append(functools.partial(callback, *a, **kw))

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(self, *_) -> None:
        exceptions = []
        while self._callbacks:
            try:
                self._callbacks.pop(0)()
            except Exception as exc:
                exceptions.append(exc)
        if exceptions:
            raise ExceptionGroup(
                'exceptions raised during event loop exit callbacks',
                exceptions,
            )


_atexit: Final = AtEventLoopExit()


def add_loop_exit_callback[**P](
    callback: Callable[P, Any],
    *a: P.args,
    **kw: P.kwargs,
) -> None:
    _atexit.add_exit_callback(callback, *a, **kw)


class WorkerPool:
    _name: str
    _limiter: anyio.CapacityLimiter | None
    _group: TaskGroup
    _counter: count

    def __init__(
        self,
        group: TaskGroup,
        *,
        workers: int = 0,
        name: str | None = None,
    ) -> None:
        self._name = name or human_id.generate_id(word_count=3)
        self._group = group
        self._limiter = anyio.CapacityLimiter(workers) if workers > 0 else None
        self._counter = count()

    @property
    def name(self) -> str:
        return self._name

    async def _do_work(self, coro: AnyAwaitable[Any]) -> None:
        if self._limiter is not None:
            try:
                await self._limiter.acquire()
                await coro
            finally:
                self._limiter.release()
        else:
            await coro

    async def create_worker(self, coro: AnyAwaitable[Any]) -> None:
        self._group.start_soon(
            self._do_work,
            coro,
            name=f'{self._name}:{next(self._counter)}',
        )


# FIXME: this is... not technically correct, because we are not supposed to use
#        concurrent.futures.Future directly, but anyio doesn't provide an easy
#        drop-in and this is a hacky shim to workaround pygrpc nonsense anyway,
#        sooo... might be good to fix at some point, but it works?
def asynciter_save_exception[T](
    iterator: AsyncIterator[T],
    exception: concurrent.futures.Future | None = None,
) -> tuple[AsyncIterator[T], concurrent.futures.Future]:
    exception = exception or concurrent.futures.Future()

    async def _asynciter_save_exception() -> AsyncIterator[T]:
        try:
            async for element in iterator:
                yield element
        except anyio.get_cancelled_exc_class():
            pass
        except GeneratorExit:
            pass
        except Exception as e:
            exception.set_exception(e)
            raise
        else:
            exception.set_result(None)

    return _asynciter_save_exception(), exception


type SingleOrIterable[T] = T | Iterator[T] | Iterable[T] | Generator[T] | AsyncIterator[T] | AsyncIterable[
    T
] | AsyncGenerator[T]


async def as_asynciter[T](
    what: SingleOrIterable[T],
    element_type: type[T] | None = None,
) -> AsyncIterator[T]:
    '''
    Generic hook that allows conversion of a single data value or a synchronous
    data iterator into an async iterator. Also supports passthrough of async
    iterators. This allows for simplification of code that could reasonably
    accept any of those as valid inputs but doesn't want to check types.
    Optionally specify the expected value type, namely important for types that
    are themselves iterable.
    '''
    # if we were given a type and our value is of that type (namely important
    # for data types that are themselves iterable), yield it and be done
    if element_type and isinstance(what, element_type):
        yield what
    # if it's an asynchronous iterator, essentially passthru as-is
    elif isinstance(what, (AsyncIterable, AsyncIterator, AsyncGenerator)):
        async for element in what:
            yield element
    # if it's a synchronous iterator, just iterate normally and yield each item
    elif isinstance(what, (Iterable, Iterator, Generator)):
        for element in what:
            yield element
    # default case: we didn't have a type manually specified and our value isn't
    # sync/async iterable, so we assume it's compatible with the base type
    else:
        yield what


async def chunk_async_data_stream(
    data: SingleOrIterable[bytes],
    chunksize: int,
) -> AsyncIterator[bytes]:
    save = b''
    async for chunk in as_asynciter(data, bytes):
        save += chunk
        while len(save) >= chunksize:
            yield save[:chunksize]
            save = save[chunksize:]
    if save:
        yield save


# FIXME: probably remove this altogether, mostly here for the possibility that
#        we might need it at some point yet... but that's probably unlikely
# class TaskGroupWrapper(anyio.AsyncContextManagerMixin, TaskGroup):
#    __wrapped: TaskGroup
#
#    def __init__(self, *, group: TaskGroup | None = None) -> None:
#        self.__wrapped = group or anyio.create_task_group()
#
#    @property
#    def _wrapped(self) -> TaskGroup:
#        return self.__wrapped
#
#    def start(
#        self,
#        func: Callable[..., Awaitable[Any]],
#        *args: Any,
#        name: Any = None,
#    ) -> types.CoroutineType[Any, Any, Any]:
#        return self._wrapped.start(func, *args, name=name)
#
#    def start_soon[*A](
#        self,
#        func: Callable[[*A],Awaitable[Any]],
#        *args: *A,
#        name: Any = None,
#    ) -> None:
#        self._wrapped.start_soon(func, *args, name=name)
#
#    @contextlib.asynccontextmanager
#    async def __asynccontextmanager__(self) -> AsyncGenerator[Self]:
#        async with self._wrapped:
#            yield self
#
#    def __repr__(self) -> str:
#        return '<{} @0x{:x}>'.format(type(self).__qualname__, id(self))
