"""Cancellation must not block the event loop on a pending upload future."""

import asyncio
from contextlib import asynccontextmanager
import json
from pathlib import Path
import subprocess
import sys
from unittest.mock import patch

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from filescan import strelka  # noqa: E402 - standalone sources require their checkout paths


class UploadError(Exception):
    """Distinguish an original upload exception from transport cancellation."""


async def cancellation_case(stage, *, guarded=True, emit_first=False):
    frontend = strelka.StrelkaFrontend(chunksize=2)
    original_save = strelka.asynciter_save_exception
    saved = {}
    events = []

    def remember(iterator):
        wrapped, future = original_save(iterator)
        saved.update(iterator=wrapped, future=future)
        if stage == 'cancelled_future':
            future.cancel()
        if guarded:
            original_exception = future.exception

            def no_block(timeout=None):
                # A pending read is a test failure instead of an indefinite hang.
                return original_exception(timeout=0 if timeout is None else timeout)

            future.exception = no_block
        return wrapped, future

    @asynccontextmanager
    async def channel():
        try:
            yield object()
        finally:
            saved['channel_closed'] = True

    class Stub:
        def __init__(self, unused):
            pass

        async def ScanFile(self, request, timeout):
            assert timeout == frontend.timeout
            if stage == 'partial':
                await anext(request)
            elif stage in ('complete', 'upload_error'):
                try:
                    async for _ in request:
                        pass
                except UploadError:
                    pass  # Model gRPC translating an upload failure to cancellation.
            if emit_first:
                yield strelka.ScanResponse(event=json.dumps({'part': 1}))
            raise asyncio.CancelledError('transport cancelled')

    async def broken_upload():
        yield b'ab'
        raise UploadError('original upload error')

    data = broken_upload() if stage == 'upload_error' else b'abcd'
    request = frontend.request_for_data('fixture.bin', data)
    with patch.object(frontend, 'open_channel', channel), patch.object(
        strelka.strelka_pb2_grpc, 'FrontendStub', Stub
    ), patch.object(strelka, 'asynciter_save_exception', remember):
        expected = UploadError if stage == 'upload_error' else asyncio.CancelledError
        try:
            with pytest.raises(expected) as failure:
                async for event in frontend.scan(request):
                    events.append(event)
            assert str(failure.value) == ('original upload error' if stage == 'upload_error' else 'transport cancelled')
            assert events == ([{'part': 1}] if emit_first else [])
            assert saved['channel_closed']
        finally:
            await saved['iterator'].aclose()
            await request.aclose()


@pytest.mark.parametrize('stage', ['unstarted', 'partial', 'complete', 'upload_error', 'cancelled_future'])
@pytest.mark.parametrize('emit_first', [False, True])
def test_cancellation_preserves_original_error_without_waiting(stage, emit_first):
    asyncio.run(cancellation_case(stage, emit_first=emit_first))


def test_pending_future_cancellation_finishes_in_a_separate_process():
    code = "import asyncio,importlib.util,sys; s=importlib.util.spec_from_file_location('regression',sys.argv[1]); m=importlib.util.module_from_spec(s); s.loader.exec_module(m); asyncio.run(m.cancellation_case('partial',guarded=False))"
    try:
        result = subprocess.run(
            [sys.executable, '-c', code, __file__], capture_output=True, text=True, timeout=5, check=False
        )
    except subprocess.TimeoutExpired:
        pytest.fail('scan cancellation blocked on an unfinished Future')
    assert result.returncode == 0, result.stderr


async def real_grpc_cancellation():
    import grpc.aio

    request_waiting = asyncio.Event()
    server_received = asyncio.Event()
    never = asyncio.Event()

    class Service(strelka.strelka_pb2_grpc.FrontendServicer):
        async def ScanFile(self, request_iterator, context):
            async for message in request_iterator:
                assert message.data == b'ab'
                server_received.set()
                await never.wait()
                yield strelka.ScanResponse(event='{}')

    server = grpc.aio.server()
    strelka.strelka_pb2_grpc.add_FrontendServicer_to_server(Service(), server)
    port = server.add_insecure_port('127.0.0.1:0')
    assert port > 0
    await server.start()
    frontend = strelka.StrelkaFrontend(host='127.0.0.1', port=port, chunksize=2)

    async def input_data():
        yield b'ab'
        request_waiting.set()
        await never.wait()

    async def consume():
        async for _ in frontend.scan(frontend.request_for_data('fixture', input_data())):
            pass

    task = asyncio.create_task(consume())
    try:
        await asyncio.wait_for(request_waiting.wait(), 3)
        await asyncio.wait_for(server_received.wait(), 3)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
    finally:
        task.cancel()
        await server.stop(0)


def test_real_grpc_cancellation_finishes_with_an_incomplete_upload():
    code = "import asyncio,importlib.util,sys; s=importlib.util.spec_from_file_location('regression',sys.argv[1]); m=importlib.util.module_from_spec(s); s.loader.exec_module(m); asyncio.run(m.real_grpc_cancellation())"
    try:
        result = subprocess.run(
            [sys.executable, '-c', code, __file__], capture_output=True, text=True, timeout=8, check=False
        )
    except subprocess.TimeoutExpired:
        pytest.fail('real gRPC cancellation blocked with an unfinished upload')
    assert result.returncode == 0, result.stderr


def test_successful_scan_still_yields_all_decoded_responses():
    async def run():
        frontend = strelka.StrelkaFrontend(chunksize=2)
        seen = []

        @asynccontextmanager
        async def channel():
            yield object()

        class Stub:
            def __init__(self, unused):
                pass

            async def ScanFile(self, request, timeout):
                async for message in request:
                    seen.append(message.data)
                for part in [1, 2]:
                    yield strelka.ScanResponse(event=json.dumps({'part': part}))

        with patch.object(frontend, 'open_channel', channel), patch.object(
            strelka.strelka_pb2_grpc, 'FrontendStub', Stub
        ):
            result = [event async for event in frontend.scan(frontend.request_for_data('fixture', b'abcde'))]
        assert seen == [b'ab', b'cd', b'e']
        assert result == [{'part': 1}, {'part': 2}]

    asyncio.run(run())
