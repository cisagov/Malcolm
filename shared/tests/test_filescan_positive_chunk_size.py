"""Invalid chunk sizes must fail before consuming or uploading file data."""

import asyncio
from pathlib import Path
from unittest.mock import patch

import pytest

from filescan.aio import chunk_async_data_stream

try:
    from filescan.strelka import StrelkaFrontend
except ImportError:
    StrelkaFrontend = None

needs_strelka = pytest.mark.skipif(
    StrelkaFrontend is None,
    reason='Strelka protobuf bindings not generated (run make in filescan/python-filescan)',
)


@pytest.mark.parametrize('size', [0, -1, -128])
@pytest.mark.parametrize('data', [b'', b'abcdef', []])
def test_nonpositive_chunk_size_is_rejected_before_any_yield(size, data):
    async def run():
        stream = chunk_async_data_stream(data, size)
        try:
            with pytest.raises(ValueError, match='positive'):
                await anext(stream)
        finally:
            await stream.aclose()

    asyncio.run(run())


@pytest.mark.parametrize('size', [0, -1])
def test_invalid_size_does_not_consume_input(size):
    def source():
        pytest.fail('invalid chunk size must not consume input')
        yield b'data'

    async def run():
        stream = chunk_async_data_stream(source(), size)
        try:
            with pytest.raises(ValueError, match='positive'):
                await anext(stream)
        finally:
            await stream.aclose()

    asyncio.run(run())


@needs_strelka
@pytest.mark.parametrize('size', [0, -1, -128])
def test_frontend_rejects_invalid_configuration_before_reading_credentials(size):
    with patch.object(Path, 'read_bytes', side_effect=AssertionError('certificate must not be read')):
        with pytest.raises(ValueError, match='positive'):
            StrelkaFrontend(chunksize=size, cert=Path('unused-certificate.pem'))


@pytest.mark.parametrize('size', [1, 2, 4, 64])
@pytest.mark.parametrize('kind', ['bytes', 'list', 'async'])
def test_valid_chunking_keeps_byte_order_and_final_remainder(size, kind):
    async def source():
        for value in [b'ab', b'', b'cdef', b'g']:
            yield value

    async def run():
        data = b'abcdefg' if kind == 'bytes' else [b'ab', b'', b'cdef', b'g'] if kind == 'list' else source()
        result = [chunk async for chunk in chunk_async_data_stream(data, size)]
        assert result == [b'abcdefg'[i : i + size] for i in range(0, 7, size)]

    asyncio.run(run())


@needs_strelka
@pytest.mark.parametrize('size', [1, 3, 64])
def test_real_file_requests_keep_protobuf_metadata_and_contents(tmp_path, size):
    path = tmp_path / 'fixture.bin'
    path.write_bytes(b'abcdefg')
    frontend = StrelkaFrontend(chunksize=size, source='regression')

    async def run():
        return [request async for request in frontend.request_for_path(path, metadata={'scope': 'test'})]

    result = asyncio.run(run())
    assert b''.join(request.data for request in result) == b'abcdefg'
    assert all(0 < len(request.data) <= size for request in result)
    assert all(request.attributes.filename == str(path) for request in result)
    assert all(dict(request.attributes.metadata) == {'scope': 'test'} for request in result)
    assert len({request.request.id for request in result}) == 1


@needs_strelka
def test_default_chunk_size_and_empty_input_are_unchanged():
    frontend = StrelkaFrontend()
    assert frontend.chunksize == 32768

    async def run():
        return [request async for request in frontend.request_for_data('empty', b'')]

    assert asyncio.run(run()) == []
