"""Waiting scan workers must cancel without releasing unowned tokens."""

import asyncio
import inspect

import anyio
import pytest

from filescan.aio import WorkerPool


@pytest.fixture(params=['asyncio', 'trio'])
def backend(request):
    if request.param == 'trio':
        pytest.importorskip('trio')
    return request.param


async def wait_for_waiters(pool, number):
    with anyio.fail_after(3):
        while pool._limiter.statistics().tasks_waiting != number:
            await anyio.sleep(0)


def test_cancelling_a_saturated_pool_closes_queued_coroutines(backend):
    async def scenario():
        coroutines = []
        started = anyio.Event()

        async def active():
            started.set()
            await anyio.sleep_forever()

        async def queued():
            pytest.fail('A queued coroutine must not start during shutdown')

        try:
            async with anyio.create_task_group() as group:
                pool = WorkerPool(group, workers=1, name='cancel-regression')
                coroutines.append(active())
                await pool.create_worker(coroutines[-1])
                await started.wait()
                for _ in range(3):
                    coroutines.append(queued())
                    await pool.create_worker(coroutines[-1])
                await wait_for_waiters(pool, 3)
                group.cancel_scope.cancel()
            assert pool._limiter.borrowed_tokens == 0
            assert pool._limiter.statistics().tasks_waiting == 0
            assert all(inspect.getcoroutinestate(c) == inspect.CORO_CLOSED for c in coroutines)
        finally:
            for coro in coroutines:
                coro.close()

    anyio.run(scenario, backend=backend)


def test_cancelling_one_waiter_keeps_the_active_token(backend):
    async def scenario():
        scopes = []
        done = anyio.Event()

        async def queued():
            pytest.fail('Cancelled queued work must not run')

        coro = queued()
        try:
            async with anyio.create_task_group() as group:
                pool = WorkerPool(group, workers=1, name='one-waiter')

                async def waiter():
                    try:
                        with anyio.CancelScope() as scope:
                            scopes.append(scope)
                            await pool._do_work(coro)
                    finally:
                        done.set()

                async with pool._limiter:
                    group.start_soon(waiter)
                    await wait_for_waiters(pool, 1)
                    scopes[0].cancel()
                    await done.wait()
                    assert pool._limiter.borrowed_tokens == 1
                    assert inspect.getcoroutinestate(coro) == inspect.CORO_CLOSED
            assert pool._limiter.borrowed_tokens == 0
        finally:
            coro.close()

    anyio.run(scenario, backend=backend)


def test_cancellation_before_acquisition_closes_unstarted_work(backend):
    async def scenario():
        async with anyio.create_task_group() as group:
            pool = WorkerPool(group, workers=1, name='pre-cancel')

            async def work():
                pytest.fail('Pre-cancelled work must not run')

            coro = work()
            try:
                with anyio.CancelScope() as scope:
                    scope.cancel()
                    await pool._do_work(coro)
                assert inspect.getcoroutinestate(coro) == inspect.CORO_CLOSED
                assert pool._limiter.borrowed_tokens == 0
            finally:
                coro.close()

    anyio.run(scenario, backend=backend)


def test_worker_failure_releases_its_acquired_token(backend):
    class WorkerError(Exception):
        pass

    async def scenario():
        async with anyio.create_task_group() as group:
            pool = WorkerPool(group, workers=1, name='failure')

            async def fail():
                raise WorkerError('original worker failure')

            with pytest.raises(WorkerError, match='original worker failure'):
                await pool._do_work(fail())
            assert pool._limiter.borrowed_tokens == 0
            await pool._do_work(anyio.sleep(0))
            assert pool._limiter.borrowed_tokens == 0

    anyio.run(scenario, backend=backend)


@pytest.mark.parametrize('limit', [0, 1, 3])
def test_normal_work_respects_the_configured_concurrency(backend, limit):
    async def scenario():
        active = maximum = 0
        finished = []

        async def job(i):
            nonlocal active, maximum
            active += 1
            maximum = max(maximum, active)
            await anyio.sleep(0.001)
            active -= 1
            finished.append(i)

        async with anyio.create_task_group() as group:
            pool = WorkerPool(group, workers=limit, name='normal')
            for i in range(8):
                await pool.create_worker(job(i))
        assert sorted(finished) == list(range(8))
        assert active == 0
        if limit:
            assert maximum <= limit
            assert pool._limiter.borrowed_tokens == 0

    anyio.run(scenario, backend=backend)


def test_noncoroutine_awaitables_remain_supported(backend):
    class Work:
        def __init__(self):
            self.ran = False

        def __await__(self):
            async def run():
                self.ran = True

            return run().__await__()

    async def scenario():
        work = Work()
        async with anyio.create_task_group() as group:
            pool = WorkerPool(group, workers=1, name='awaitable')
            await pool.create_worker(work)
        assert work.ran
        assert pool._limiter.borrowed_tokens == 0

    anyio.run(scenario, backend=backend)


def test_asyncio_future_remains_supported():
    async def scenario():
        future = asyncio.get_running_loop().create_future()
        future.set_result(42)
        async with anyio.create_task_group() as group:
            pool = WorkerPool(group, workers=1, name='future')
            await pool._do_work(future)
            assert future.result() == 42
            assert pool._limiter.borrowed_tokens == 0

    anyio.run(scenario)
