"""Localhost end-to-end tests for classic PCAP-over-IP ingestion."""

import io
from pathlib import Path
import socket
import struct
import subprocess
import sys
import threading

import pytest

import pcap_over_ip as pcap

ROOT = Path(__file__).resolve().parents[2]


def make_pcap(*, endian='<', nanos=False, payloads=(b'first packet', b'second')):
    magic = (
        {
            ('<', False): b'\xd4\xc3\xb2\xa1',
            ('>', False): b'\xa1\xb2\xc3\xd4',
            ('<', True): b'\x4d\x3c\xb2\xa1',
            ('>', True): b'\xa1\xb2\x3c\x4d',
        }
    )[(endian, nanos)]
    header = magic + struct.pack(endian + 'HHiIII', 2, 4, 0, 0, 65535, 1)
    return header + b''.join(
        struct.pack(endian + 'IIII', 123, 7, len(payload), len(payload)) + payload for payload in payloads
    )


class StubStream:
    def __init__(self, data, *, chunksize=5):
        self._source = io.BytesIO(data)
        self.chunksize = chunksize

    def recv(self, size):
        return self._source.read(min(size, self.chunksize))


@pytest.mark.parametrize('endian,nanos', [('<', False), ('>', False), ('<', True), ('>', True)])
def test_incremental_classic_pcap_validates_all_header_flavors(endian, nanos):
    data = make_pcap(endian=endian, nanos=nanos)
    output = io.BytesIO()
    assert pcap.receive_pcap(StubStream(data), output) == 2
    assert output.getvalue() == data


def test_zero_packet_file_is_rejected():
    with pytest.raises(pcap.PCAPStreamError, match='empty'):
        pcap.receive_pcap(StubStream(make_pcap(payloads=())), io.BytesIO())


@pytest.mark.parametrize(
    'payload',
    [
        b'',
        b'\x0a\x0d\x0d\x0a' + b'\0' * 24,
        make_pcap()[:20],
        make_pcap()[:-2],
        make_pcap()[:24] + b'\x01',
    ],
)
def test_truncated_or_pcapng_stream_is_rejected(payload):
    with pytest.raises(pcap.PCAPStreamError):
        pcap.receive_pcap(StubStream(payload), io.BytesIO())


def test_valid_caplen_but_declared_size_over_max_is_rejected():
    data = make_pcap(payloads=(b'abc' * 16,))
    with pytest.raises(pcap.PCAPStreamError, match='exceeds'):
        pcap.receive_pcap(StubStream(data), io.BytesIO(), max_bytes=45)


def test_bad_packet_lengths_rejected():
    for captured, original in ((65536, 65536), (8, 5)):
        data = make_pcap(payloads=())
        data += struct.pack('<IIII', 0, 0, captured, original)
        with pytest.raises(pcap.PCAPStreamError, match='length'):
            pcap.receive_pcap(StubStream(data), io.BytesIO())


def test_bad_timestamp_fraction_rejected():
    data = make_pcap(payloads=()) + struct.pack('<IIII', 0, 1_000_000, 0, 0)
    with pytest.raises(pcap.PCAPStreamError, match='timestamp'):
        pcap.receive_pcap(StubStream(data), io.BytesIO())


def test_bad_global_header_rejected():
    data = make_pcap()
    for changed in (data[:4] + b'\x02\x00\x05\x00' + data[8:], data[:16] + b'\0' * 4 + data[20:]):
        with pytest.raises(pcap.PCAPStreamError):
            pcap.receive_pcap(StubStream(changed), io.BytesIO())


@pytest.fixture
def uploads(tmp_path):
    directory = tmp_path / 'pcap' / 'upload'
    directory.mkdir(parents=True)
    return directory


def local_sender(data, *, chunk_size=3):
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(('127.0.0.1', 0))
    listener.listen(1)
    port = listener.getsockname()[1]

    def serve():
        try:
            with listener:
                connection, _ = listener.accept()
                with connection:
                    for offset in range(0, len(data), chunk_size):
                        connection.sendall(data[offset : offset + chunk_size])
        except OSError:
            pass

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    return port, thread


def test_end_to_end_local_tcp_upload_and_no_partial_visibility(uploads):
    data = make_pcap(payloads=(b'one', b'two', b'three'))
    port, thread = local_sender(data, chunk_size=7)
    target, count = pcap.capture_from_tcp('127.0.0.1', port, uploads, max_bytes=1_000_000)
    thread.join(timeout=2)
    assert count == 3
    assert target.parent == uploads
    assert target.read_bytes() == data
    assert list(uploads.iterdir()) == [target]
    assert not list(uploads.parent.glob('.pcap-over-ip-*'))


def test_failed_stream_leaves_no_files_in_upload_or_staging(uploads):
    port, thread = local_sender(make_pcap()[:-3], chunk_size=15)
    with pytest.raises(pcap.PCAPStreamError):
        pcap.capture_from_tcp('127.0.0.1', port, uploads)
    thread.join(timeout=2)
    assert not list(uploads.iterdir())
    assert not list(uploads.parent.glob('.pcap-over-ip-*'))


def test_collision_preserves_existing_upload(uploads, monkeypatch):
    old = uploads / 'pcapip_deadbeefdeadbeef.pcap'
    old.write_bytes(b'existing capture')
    tokens = iter(['deadbeefdeadbeef', 'cafebabecafebabe'])
    monkeypatch.setattr(pcap.secrets, 'token_hex', lambda _: next(tokens))
    port, thread = local_sender(make_pcap())
    target, count = pcap.capture_from_tcp('127.0.0.1', port, uploads)
    thread.join(timeout=2)
    assert count == 2
    assert target.name == 'pcapip_cafebabecafebabe.pcap'
    assert old.read_bytes() == b'existing capture'


def test_symlink_or_missing_output_directory_rejected(tmp_path, uploads):
    symlink = tmp_path / 'upload'
    symlink.symlink_to(uploads)
    for directory in (symlink, tmp_path / 'missing'):
        with pytest.raises(pcap.PCAPStreamError):
            pcap.capture_from_tcp('127.0.0.1', 1, directory)


def test_invalid_port_and_limit_rejected_before_connect(uploads):
    for port, limit in ((0, 1000), (65536, 1000), (1, 12)):
        with pytest.raises(ValueError):
            pcap.capture_from_tcp('127.0.0.1', port, uploads, max_bytes=limit)


def test_cli_import_uses_real_subprocess_on_localhost(uploads):
    port, thread = local_sender(make_pcap())
    proc = subprocess.run(
        [
            sys.executable,
            str(ROOT / 'scripts' / 'pcap_over_ip.py'),
            '--host',
            '127.0.0.1',
            '--port',
            str(port),
            '--output-dir',
            str(uploads),
            '--max-bytes',
            '100000',
        ],
        capture_output=True,
        text=True,
        cwd=ROOT,
        timeout=20,
    )
    thread.join(timeout=2)
    assert proc.returncode == 0, proc.stderr
    assert 'Queued 2 packet' in proc.stdout
    assert len(list(uploads.iterdir())) == 1


def test_cli_connection_refused_exits_nonzero_without_staging(uploads):
    # Bind-and-release is enough to pick an ephemeral localhost port.
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0))
        port = listener.getsockname()[1]
    proc = subprocess.run(
        [
            sys.executable,
            str(ROOT / 'scripts' / 'pcap_over_ip.py'),
            '--port',
            str(port),
            '--output-dir',
            str(uploads),
            '--connect-timeout',
            '1',
        ],
        capture_output=True,
        text=True,
        cwd=ROOT,
        timeout=10,
    )
    assert proc.returncode == 1
    assert 'failed' in proc.stderr.lower()
    assert not list(uploads.iterdir())
