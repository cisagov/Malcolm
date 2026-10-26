"""Framing, retry and resend behavior of the Suricata unix socket client, against a fake Suricata."""

import json
import logging
import os
import shutil
import socket
import sys
import tempfile
import threading
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'suricata' / 'scripts'))

import suricata_socket
from suricata_socket import SuricataSocketClient, SuricataQueueSizeError

OK = {'return': 'OK'}


@pytest.fixture(autouse=True)
def no_rule_reload(monkeypatch):
    """Connecting normally warms up and reloads rules; that's covered separately."""
    monkeypatch.setattr(SuricataSocketClient, '_ensure_rules_reloaded', lambda self: None)


###################################################################################################
# helpers


def chunked(obj, *cut_points, delay=0.02):
    """Serialize obj and return it as a list of byte chunks split at the given offsets."""
    data = json.dumps(obj, ensure_ascii=False).encode('utf-8') if not isinstance(obj, bytes) else obj
    cuts = [0, *cut_points, len(data)]
    return [data[a:b] for a, b in zip(cuts, cuts[1:])], delay


def send_chunks(sock, chunks, delay=0.02):
    for i, chunk in enumerate(chunks):
        if i:
            time.sleep(delay)
        sock.sendall(chunk)


def bare_client(sock):
    """A client wired to one end of a socketpair, skipping __init__ and its connection handshake."""
    client = SuricataSocketClient.__new__(SuricataSocketClient)
    client.sock = sock
    client.debug_enabled = False
    client.logger = logging.getLogger('test_suricata_socket_client')
    client.retry_delay = 0
    client.max_retries = 1
    client.socket_path = '/nonexistent'
    return client


@pytest.fixture
def pair():
    client_sock, server_sock = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    client_sock.settimeout(5)
    server_sock.settimeout(5)
    try:
        yield bare_client(client_sock), server_sock
    finally:
        client_sock.close()
        server_sock.close()


def in_background(fn, *args):
    thread = threading.Thread(target=fn, args=args, daemon=True)
    thread.start()
    return thread


def read_line(sock):
    buf = b''
    while not buf.endswith(b'\n'):
        data = sock.recv(4096)
        if not data:
            return None
        buf += data
    return buf


class FakeSuricata:
    """A unix socket server speaking just enough of Suricata's command protocol.

    responder(command_dict, connection_number) returns a list of byte chunks to send back, or None to drop
    the connection without replying.
    """

    def __init__(self, path, responder, handshake=None):
        self.path = path
        self.responder = responder
        self.handshake = handshake or (lambda: [json.dumps(OK).encode()])
        self.commands = []
        self.connections = 0
        self.server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.server.bind(path)
        self.server.listen(5)
        self.server.settimeout(0.2)
        self.stopping = False
        self.thread = in_background(self._serve)

    def _serve(self):
        while not self.stopping:
            try:
                conn, _ = self.server.accept()
            except (socket.timeout, OSError):
                continue
            self.connections += 1
            in_background(self._handle, conn, self.connections)

    def _handle(self, conn, number):
        with conn:
            try:
                if read_line(conn) is None:
                    return
                send_chunks(conn, self.handshake())
                while (line := read_line(conn)) is not None:
                    command = json.loads(line)
                    self.commands.append((number, command))
                    reply = self.responder(command, number)
                    if reply is None:
                        return
                    send_chunks(conn, reply)
            except OSError:
                return

    def sent(self, name):
        return [c for _, c in self.commands if c.get('command') == name]

    def stop(self):
        self.stopping = True
        self.thread.join(2)
        self.server.close()


@pytest.fixture
def socket_dir():
    # unix socket paths are limited to ~100 characters, so keep this short rather than using tmp_path
    path = tempfile.mkdtemp(prefix='sur-')
    try:
        yield path
    finally:
        shutil.rmtree(path, ignore_errors=True)


@pytest.fixture
def fake_suricata(socket_dir):
    servers = []

    def start(responder, handshake=None):
        server = FakeSuricata(os.path.join(socket_dir, f's{len(servers)}.sock'), responder, handshake)
        servers.append(server)
        return server

    try:
        yield start
    finally:
        for server in servers:
            server.stop()


def connect(server, socket_dir, **kwargs):
    kwargs.setdefault('retry_delay', 0)
    kwargs.setdefault('max_retries', 2)
    return SuricataSocketClient(socket_path=server.path, output_dir=socket_dir, **kwargs)


def reply(obj):
    return [json.dumps(obj).encode()]


###################################################################################################
# _recv_json framing


def test_recv_json_single_chunk(pair):
    client, server = pair
    server.sendall(b'{"return": "OK", "message": "x"}')
    assert client._recv_json() == {'return': 'OK', 'message': 'x'}


@pytest.mark.parametrize('cut_points', [(1,), (10,), (5, 15, 20)])
def test_recv_json_split_across_reads(pair, cut_points):
    client, server = pair
    chunks, delay = chunked({'return': 'OK', 'message': 'split reply'}, *cut_points)
    in_background(send_chunks, server, chunks, delay)
    assert client._recv_json() == {'return': 'OK', 'message': 'split reply'}


def test_recv_json_larger_than_one_read(pair):
    client, server = pair
    message = 'x' * 20000
    chunks, delay = chunked({'return': 'OK', 'message': message}, 3000, 9000)
    in_background(send_chunks, server, chunks, delay)
    assert client._recv_json()['message'] == message


def test_recv_json_multibyte_character_split_between_reads(pair):
    client, server = pair
    data = json.dumps({'return': 'OK', 'message': 'é' * 3000}, ensure_ascii=False).encode('utf-8')
    cut = data.index('é'.encode('utf-8')) + 1  # in the middle of a two-byte character
    in_background(send_chunks, server, [data[:cut], data[cut:]])
    assert client._recv_json()['message'] == 'é' * 3000


def test_recv_json_tolerates_surrounding_whitespace(pair):
    client, server = pair
    server.sendall(b'\n  {"return": "OK"}\n')
    assert client._recv_json() == OK


@pytest.mark.parametrize('payload', [b'', b'{"return": "OK", "mess'])
def test_recv_json_peer_closes_early(pair, payload):
    client, server = pair
    server.sendall(payload)
    server.shutdown(socket.SHUT_WR)
    with pytest.raises(ConnectionError):
        client._recv_json()


@pytest.mark.parametrize('payload', [b'[1, 2]', b'"OK"', b'42'])
def test_recv_json_rejects_non_object(pair, payload):
    client, server = pair
    server.sendall(payload)
    with pytest.raises(ConnectionError):
        client._recv_json()


def test_recv_json_rejects_invalid_utf8(pair):
    client, server = pair
    server.sendall(b'{"return": "\xff\xfe"}')
    with pytest.raises(ConnectionError):
        client._recv_json()


def test_recv_json_gives_up_past_max_bytes(pair):
    client, server = pair
    server.sendall(b'{' * 500)
    with pytest.raises(ConnectionError, match='exceeded'):
        client._recv_json(max_bytes=100)


def test_recv_json_timeout_is_a_socket_error(pair):
    client, _ = pair
    client.sock.settimeout(0.1)
    with pytest.raises(OSError):
        client._recv_json()


###################################################################################################
# _send_command over a connected socket


def test_send_command_sends_one_newline_terminated_json_line(pair):
    client, server = pair
    received = []

    def peer():
        received.append(read_line(server))
        server.sendall(json.dumps({'return': 'OK', 'message': 3}).encode())

    thread = in_background(peer)
    assert client._send_command({'command': 'pcap-file-number'}) == {'return': 'OK', 'message': 3}
    thread.join(2)
    assert received[0].endswith(b'\n')
    assert received[0].count(b'\n') == 1
    assert json.loads(received[0]) == {'command': 'pcap-file-number'}


def test_send_command_nok_returns_none(pair):
    client, server = pair

    def peer():
        read_line(server)
        server.sendall(b'{"return": "NOK", "message": "nope"}')

    in_background(peer)
    assert client._send_command({'command': 'pcap-current'}) is None


def test_send_command_stays_in_sync_after_a_split_reply(pair):
    # a reply that arrives in pieces must not leave a tail behind for the next command to read
    client, server = pair
    first = {'return': 'OK', 'message': 'a' * 10000}
    second = {'return': 'OK', 'message': 'second'}

    def peer():
        read_line(server)
        chunks, delay = chunked(first, 4000, 8000)
        send_chunks(server, chunks, delay)
        read_line(server)
        server.sendall(json.dumps(second).encode())

    in_background(peer)
    assert client._send_command({'command': 'one'}) == first
    assert client._send_command({'command': 'two'}) == second


###################################################################################################
# connecting, reconnecting and resending


def test_connect_handles_a_split_handshake(fake_suricata, socket_dir):
    server = fake_suricata(lambda c, n: reply(OK), handshake=lambda: [b'{"ret', b'urn": "OK"}'])
    client = connect(server, socket_dir)
    try:
        assert client._send_command({'command': 'pcap-current'}) == OK
    finally:
        client.close()


def test_connect_fails_on_rejected_handshake(fake_suricata, socket_dir):
    server = fake_suricata(lambda c, n: reply(OK), handshake=lambda: [b'{"return": "NOK"}'])
    with pytest.raises(ConnectionError):
        connect(server, socket_dir)
    assert server.connections == 2  # max_retries


def test_connect_fails_without_a_server(socket_dir):
    with pytest.raises(ConnectionError):
        SuricataSocketClient(
            socket_path=os.path.join(socket_dir, 'missing.sock'), output_dir=socket_dir, retry_delay=0, max_retries=2
        )


def test_idempotent_command_is_resent_after_a_dropped_connection(fake_suricata, socket_dir):
    server = fake_suricata(lambda c, n: None if n == 1 else reply({'return': 'OK', 'message': 'None'}))
    client = connect(server, socket_dir)
    try:
        assert client._send_command({'command': 'pcap-current'}) == {'return': 'OK', 'message': 'None'}
    finally:
        client.close()
    assert len(server.sent('pcap-current')) == 2
    assert server.connections == 2


def test_non_idempotent_command_is_not_resent_after_a_dropped_connection(fake_suricata, socket_dir):
    server = fake_suricata(lambda c, n: None if n == 1 else reply({'return': 'OK', 'message': 0}))
    client = connect(server, socket_dir)
    try:
        assert client._send_command({'command': 'pcap-file'}, idempotent=False) is None
        # the client reconnected, so the next command works on a clean stream
        assert client._send_command({'command': 'pcap-file-number'}) == {'return': 'OK', 'message': 0}
    finally:
        client.close()
    assert len(server.sent('pcap-file')) == 1
    assert server.connections == 2


def test_send_command_gives_up_after_retries(fake_suricata, socket_dir):
    server = fake_suricata(lambda c, n: None)
    client = connect(server, socket_dir, max_retries=5)
    try:
        assert client._send_command({'command': 'pcap-current'}, retries=3) is None
    finally:
        client.close()
    assert len(server.sent('pcap-current')) == 3


def test_reconnect_closes_the_old_socket(fake_suricata, socket_dir):
    server = fake_suricata(lambda c, n: reply(OK))
    client = connect(server, socket_dir)
    try:
        old_sock = client.sock
        client._reconnect()
        assert old_sock.fileno() == -1
        assert client.sock is not old_sock
        assert client._send_command({'command': 'pcap-current'}) == OK
    finally:
        client.close()


###################################################################################################
# process_pcap and queue_size


def test_process_pcap_submits_file_and_creates_output_dir(fake_suricata, socket_dir):
    server = fake_suricata(lambda c, n: reply({'return': 'OK', 'message': 'Successfully added file to list'}))
    client = connect(server, socket_dir)
    output_dir = os.path.join(socket_dir, 'out', 'nested')
    try:
        assert client.process_pcap('/data/pcap/upload/test.pcap', output_dir) is True
    finally:
        client.close()
    assert os.path.isdir(output_dir)
    assert server.sent('pcap-file') == [
        {'command': 'pcap-file', 'arguments': {'filename': '/data/pcap/upload/test.pcap', 'output-dir': output_dir}}
    ]


def test_process_pcap_rejected(fake_suricata, socket_dir):
    server = fake_suricata(lambda c, n: reply({'return': 'NOK', 'message': 'file does not exist'}))
    client = connect(server, socket_dir)
    try:
        assert client.process_pcap('/missing.pcap', os.path.join(socket_dir, 'out')) is False
    finally:
        client.close()


def test_process_pcap_is_not_resubmitted_when_the_reply_is_lost(fake_suricata, socket_dir):
    server = fake_suricata(lambda c, n: None if (n == 1 and c['command'] == 'pcap-file') else reply(OK))
    client = connect(server, socket_dir)
    try:
        assert client.process_pcap('/data/pcap/test.pcap', os.path.join(socket_dir, 'out')) is False
    finally:
        client.close()
    assert len(server.sent('pcap-file')) == 1


def test_process_pcap_handles_a_slow_reply_without_resubmitting(fake_suricata, socket_dir):
    def responder(command, number):
        if command['command'] == 'pcap-file':
            time.sleep(0.5)
        return reply(OK)

    server = fake_suricata(responder)
    client = connect(server, socket_dir)
    client.sock.settimeout(0.1)
    try:
        assert client.process_pcap('/data/pcap/test.pcap', os.path.join(socket_dir, 'out')) is False
    finally:
        client.close()
    assert len(server.sent('pcap-file')) == 1


@pytest.mark.parametrize(
    'response, expected',
    [
        ({'return': 'OK', 'message': 3}, 3),
        ({'return': 'OK', 'message': 0}, 0),
        ({'return': 'OK', 'message': 'lots'}, SuricataQueueSizeError),
        ({'return': 'NOK', 'message': 'error'}, SuricataQueueSizeError),
        ({'message': 3}, SuricataQueueSizeError),
    ],
)
def test_queue_size(fake_suricata, socket_dir, response, expected):
    server = fake_suricata(lambda c, n: reply(response))
    client = connect(server, socket_dir)
    try:
        assert client.queue_size() == expected
    finally:
        client.close()


def test_queue_size_when_suricata_goes_away(fake_suricata, socket_dir):
    server = fake_suricata(lambda c, n: reply(OK))
    client = connect(server, socket_dir)
    server.stop()
    os.unlink(server.path)
    client.sock.close()
    assert client.queue_size() == SuricataQueueSizeError


###################################################################################################
# warm-up and rule reload


def test_is_idle(fake_suricata, socket_dir):
    state = {'current': 'None', 'queued': 0}

    def responder(command, number):
        if command['command'] == 'pcap-current':
            return reply({'return': 'OK', 'message': state['current']})
        return reply({'return': 'OK', 'message': state['queued']})

    server = fake_suricata(responder)
    client = connect(server, socket_dir)
    try:
        assert client._is_idle() is True
        state['queued'] = 1
        assert client._is_idle() is False
        state.update(current='/tmp/x.pcap', queued=0)
        assert client._is_idle() is False
    finally:
        client.close()


def test_warm_up_submits_the_warm_up_pcap_once_and_waits_for_idle(fake_suricata, socket_dir):
    submitted = []

    def responder(command, number):
        if command['command'] == 'pcap-file':
            path = command['arguments']['filename']
            with open(path, 'rb') as f:
                submitted.append(f.read())
            return reply(OK)
        if command['command'] == 'pcap-current':
            return reply({'return': 'OK', 'message': 'None'})
        return reply({'return': 'OK', 'message': 0})

    server = fake_suricata(responder)
    client = connect(server, socket_dir)
    try:
        assert client._warm_up(timeout=10) is True
    finally:
        client.close()
    assert submitted == [suricata_socket.SuricataWarmUpPcap]


def test_warm_up_is_not_resubmitted_when_the_reply_is_lost(fake_suricata, socket_dir):
    server = fake_suricata(lambda c, n: None if c['command'] == 'pcap-file' else reply(OK))
    client = connect(server, socket_dir)
    try:
        assert client._warm_up(timeout=2) is False
    finally:
        client.close()
    assert len(server.sent('pcap-file')) == 1


@pytest.mark.parametrize('response, expected', [(OK, True), ({'return': 'NOK', 'message': 'busy'}, False)])
def test_reload_rules_restores_socket_timeout(fake_suricata, socket_dir, response, expected):
    server = fake_suricata(lambda c, n: reply(response))
    client = connect(server, socket_dir)
    try:
        previous = client.sock.gettimeout()
        assert client.reload_rules(timeout=30) is expected
        assert client.sock.gettimeout() == previous
    finally:
        client.close()
    assert len(server.sent('reload-rules')) == 1


def test_close_is_safe_to_repeat(fake_suricata, socket_dir):
    server = fake_suricata(lambda c, n: reply(OK))
    client = connect(server, socket_dir)
    client.close()
    client.close()
