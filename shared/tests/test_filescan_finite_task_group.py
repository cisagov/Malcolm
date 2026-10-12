"""Finite filescan task groups must terminate without losing child work."""

import importlib.util
import os
import signal
import subprocess
import sys

import anyio
import pytest

from filescan import aio

# Child processes have no conftest, so hand them this process's import path.
CHILD_ENV = {**os.environ, 'PYTHONPATH': os.pathsep.join(sys.path)}


@pytest.fixture(params=['asyncio', 'trio'])
def backend(request):
    if request.param == 'trio' and importlib.util.find_spec('trio') is None:
        pytest.skip('optional Trio backend is not installed')
    return request.param


def leaves(error):
    if isinstance(error, BaseExceptionGroup):
        return [leaf for child in error.exceptions for leaf in leaves(child)]
    return [error]


@pytest.mark.parametrize('children', [0, 3])
def test_finite_group_returns_after_all_finite_children_complete(backend, children):
    completed = []

    async def worker(index):
        await anyio.sleep(0.01)
        completed.append(index)

    async def scenario():
        with anyio.fail_after(0.5):
            async with aio.main_task_group() as group:
                for index in range(children):
                    group.start_soon(worker, index)
        assert sorted(completed) == list(range(children))

    anyio.run(scenario, backend=backend)


def test_exit_callbacks_run_once_and_sequential_groups_finish(monkeypatch, backend):
    monkeypatch.setattr(aio, '_atexit', aio.AtEventLoopExit())
    completed = []

    async def scenario():
        with anyio.fail_after(0.5):
            for index in range(2):
                async with aio.main_task_group():
                    aio.add_loop_exit_callback(completed.append, index)
        assert completed == [0, 1]

    anyio.run(scenario, backend=backend)


@pytest.mark.parametrize('where', ['body', 'child', 'callback'])
def test_failures_still_propagate_and_cancel_siblings(monkeypatch, backend, where):
    monkeypatch.setattr(aio, '_atexit', aio.AtEventLoopExit())
    marker = ValueError('expected failure')

    def fail():
        raise marker

    async def failed_child():
        fail()

    async def scenario():
        with pytest.raises(ExceptionGroup) as raised:
            with anyio.fail_after(0.5):
                async with aio.main_task_group() as group:
                    group.start_soon(anyio.sleep_forever)
                    if where == 'body':
                        fail()
                    elif where == 'callback':
                        aio.add_loop_exit_callback(fail)
                    else:
                        group.start_soon(failed_child)
                        await anyio.sleep_forever()
        assert marker in leaves(raised.value)
        assert not any(isinstance(error, TimeoutError) for error in leaves(raised.value))

    anyio.run(scenario, backend=backend)


def test_explicit_forever_mode_requires_cancellation(backend):
    reached = []

    async def scenario():
        with anyio.move_on_after(0.05) as deadline:
            async with aio.main_task_group(run_forever=True):
                reached.append('body')
            reached.append('returned')
        assert deadline.cancel_called
        assert reached == ['body']

    anyio.run(scenario, backend=backend)


def test_run_as_main_returns_value_in_a_bounded_child_process():
    code = "from filescan.aio import run_as_main\nasync def value(): return 17\nprint(run_as_main(value()), flush=True)"
    completed = subprocess.run(
        [sys.executable, '-c', code], capture_output=True, text=True, timeout=4, check=False, env=CHILD_ENV
    )
    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.strip() == '17'


def test_signal_handler_remains_active_while_children_finish(monkeypatch, backend):
    # A fixture listener triggers the same cancellation path without sending OS signals.
    state = []

    async def handler(scope):
        await anyio.sleep(0.03)
        state.append('signal')
        scope.cancel()

    monkeypatch.setattr(aio, '_signal_handler', handler)

    async def scenario():
        with anyio.fail_after(0.5):
            async with aio.main_task_group() as group:
                group.start_soon(anyio.sleep_forever)
        assert state == ['signal']

    anyio.run(scenario, backend=backend)


@pytest.mark.skipif(sys.platform == 'win32', reason='requires POSIX signals')
@pytest.mark.parametrize('signum', [signal.SIGTERM, signal.SIGINT])
def test_forever_group_still_handles_real_signals_in_an_isolated_process(signum):
    code = """
import os, signal
import anyio
from filescan.aio import main_task_group
async def stop():
    await anyio.sleep(.03)
    os.kill(os.getpid(), int(__import__('sys').argv[1]))
async def main():
    with anyio.fail_after(1):
        async with main_task_group(run_forever=True) as group:
            group.start_soon(stop)
    print('stopped', flush=True)
anyio.run(main)
"""
    completed = subprocess.run(
        [sys.executable, '-c', code, str(int(signum))],
        capture_output=True,
        text=True,
        timeout=5,
        check=False,
        env=CHILD_ENV,
    )
    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.strip() == 'stopped'
