#!/usr/bin/env python3
"""Receive a complete classic PCAP over TCP and publish it to Malcolm's upload queue.

Only outbound connections are made. The stream is copied into a private staging
directory outside pcap/upload and atomically linked into place once the server
closes its connection and all headers and packet bodies have been verified.
"""

import argparse
import os
from pathlib import Path
import secrets
import socket
import struct
import sys
import tempfile

MAGICS = {
    b'\xd4\xc3\xb2\xa1': ('<', 1_000_000),
    b'\xa1\xb2\xc3\xd4': ('>', 1_000_000),
    b'\x4d\x3c\xb2\xa1': ('<', 1_000_000_000),
    b'\xa1\xb2\x3c\x4d': ('>', 1_000_000_000),
}
PACKET_HEADER_BYTES = 16
GLOBAL_HEADER_BYTES = 24
MAX_SNAPLEN_BYTES = 16 * 1024 * 1024
DEFAULT_MAX_BYTES = 1024 * 1024 * 1024
CHUNK_BYTES = 65536
REPO_ROOT = Path(__file__).resolve().parents[1]


class PCAPStreamError(ValueError):
    """Malformed, incomplete, or oversized incoming capture."""


def _positive_int(raw):
    value = int(raw)
    if value <= 0:
        raise argparse.ArgumentTypeError('value must be greater than zero')
    return value


def _positive_float(raw):
    value = float(raw)
    if not 0 < value < float('inf'):
        raise argparse.ArgumentTypeError('timeout must be a positive finite number')
    return value


def _destination_directory(path):
    """Do not create upload directories or follow symlink destinations."""
    path = Path(path)
    if path.is_symlink() or not path.is_dir():
        raise PCAPStreamError(f'upload directory must already exist and not be a symlink: {path}')
    if path.name != 'upload' or path.parent.is_symlink():
        raise PCAPStreamError('upload directory must be named upload under a non-symlink PCAP root')
    if not os.access(path, os.W_OK):
        raise PCAPStreamError(f'upload directory is not writable: {path}')
    return path


def _read_exact(stream, length, *, eof_allowed=False):
    """Receive a bounded amount; EOF is legal only before a packet header."""
    chunks = []
    remaining = length
    while remaining:
        data = stream.recv(min(remaining, CHUNK_BYTES))
        if not data:
            if eof_allowed and remaining == length:
                return None
            raise PCAPStreamError(f'truncated PCAP stream: expected {length} bytes, received {length - remaining}')
        chunks.append(data)
        remaining -= len(data)
    return b''.join(chunks)


def _global_header(stream):
    header = _read_exact(stream, GLOBAL_HEADER_BYTES)
    magic = header[:4]
    if magic not in MAGICS:
        raise PCAPStreamError('not a classic PCAP stream (PCAPNG is not supported)')
    endian, fraction_limit = MAGICS[magic]
    major, minor, _zone, _sigfig, snaplen, _network = struct.unpack(endian + 'HHiIII', header[4:])
    if (major, minor) != (2, 4) or not 0 < snaplen <= MAX_SNAPLEN_BYTES:
        raise PCAPStreamError(f'unsupported PCAP version or snapshot length: {major}.{minor}, {snaplen}')
    return header, endian, fraction_limit, snaplen


def receive_pcap(stream, destination, *, max_bytes=DEFAULT_MAX_BYTES):
    """Verify every packet while streaming it to the private temporary file.

    Returns the packet count. No destination path is published by this function.
    """
    if type(max_bytes) is not int or max_bytes < GLOBAL_HEADER_BYTES + PACKET_HEADER_BYTES:
        raise ValueError('max_bytes must allow a PCAP global header and at least one packet header')

    header, endian, fraction_limit, snaplen = _global_header(stream)
    total = GLOBAL_HEADER_BYTES
    count = 0
    destination.write(header)
    while True:
        packet_header = _read_exact(stream, PACKET_HEADER_BYTES, eof_allowed=True)
        if packet_header is None:
            break
        total += PACKET_HEADER_BYTES
        if total > max_bytes:
            raise PCAPStreamError(f'PCAP stream exceeds {max_bytes} bytes')
        _seconds, fraction, included, original = struct.unpack(endian + 'IIII', packet_header)
        if fraction >= fraction_limit:
            raise PCAPStreamError('invalid PCAP packet timestamp fraction')
        if included > original or included > snaplen:
            raise PCAPStreamError('invalid PCAP captured/original packet length')
        if total + included > max_bytes:
            raise PCAPStreamError(f'PCAP stream exceeds {max_bytes} bytes')
        destination.write(packet_header)
        remaining = included
        while remaining:
            piece = _read_exact(stream, min(remaining, CHUNK_BYTES))
            destination.write(piece)
            remaining -= len(piece)
        total += included
        count += 1

    if count == 0:
        raise PCAPStreamError('empty PCAP stream: no complete packet records received')
    return count


def _publish(staged, directory):
    """Atomically expose a complete PCAP without overwriting another capture."""
    for _ in range(10):
        target = directory / f'pcapip_{secrets.token_hex(8)}.pcap'
        try:
            os.link(staged, target)
        except FileExistsError:
            continue
        return target
    raise FileExistsError('unable to create a unique PCAP filename')


def capture_from_tcp(host, port, output_dir, *, max_bytes=DEFAULT_MAX_BYTES, connect_timeout=10, idle_timeout=30):
    """Connect to one PCAP-over-IP producer and import one EOF-terminated PCAP."""
    directory = _destination_directory(output_dir)
    if not 1 <= port <= 65535:
        raise ValueError('TCP port must be between 1 and 65535')
    if max_bytes < GLOBAL_HEADER_BYTES + PACKET_HEADER_BYTES:
        raise ValueError('max_bytes is too small for a PCAP file')
    if not 0 < connect_timeout < float('inf') or not 0 < idle_timeout < float('inf'):
        raise ValueError('timeouts must be positive and finite')

    # A sibling temp directory is unwatched by the usual pcap/upload watcher.
    # Linking the finished file into upload is a single atomic publication.
    with tempfile.TemporaryDirectory(prefix='.pcap-over-ip-', dir=directory.parent) as staging:
        staged = Path(staging) / 'capture.pcap'
        with socket.create_connection((host, port), timeout=connect_timeout) as stream:
            stream.settimeout(idle_timeout)
            with staged.open('xb') as target:
                packets = receive_pcap(stream, target, max_bytes=max_bytes)
                target.flush()
                os.fsync(target.fileno())
        published = _publish(staged, directory)
    return published, packets


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--host', default='127.0.0.1', help='PCAP-over-IP TCP producer host (default 127.0.0.1)')
    parser.add_argument('--port', type=_positive_int, default=57012, help='producer TCP port (default 57012)')
    parser.add_argument(
        '--output-dir',
        type=Path,
        default=REPO_ROOT / 'pcap' / 'upload',
        help='existing Malcolm pcap/upload directory; never created automatically',
    )
    parser.add_argument(
        '--max-bytes', type=_positive_int, default=DEFAULT_MAX_BYTES, help='maximum received capture size'
    )
    parser.add_argument('--connect-timeout', type=_positive_float, default=10, help='connection timeout in seconds')
    parser.add_argument(
        '--idle-timeout', type=_positive_float, default=30, help='timeout for stalled stream reads in seconds'
    )
    args = parser.parse_args(argv)
    try:
        filename, packets = capture_from_tcp(
            args.host,
            args.port,
            args.output_dir,
            max_bytes=args.max_bytes,
            connect_timeout=args.connect_timeout,
            idle_timeout=args.idle_timeout,
        )
    except (OSError, ValueError, socket.timeout) as error:
        print(f'PCAP-over-IP import failed: {error}', file=sys.stderr)
        return 1
    print(f'Queued {packets} packet(s) in {filename}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
