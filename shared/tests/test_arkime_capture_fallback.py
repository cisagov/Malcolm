"""Exercise the live-capture supervisor with executable curl/capture probes."""

import json
import os
import shlex
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
HELPER = ROOT / 'arkime/scripts/capture-fallback.sh'
pytestmark = pytest.mark.skipif(
    sys.platform != 'linux' or not shutil.which('jq'), reason='requires Linux, jq and Bash 4.3+'
)


@pytest.fixture
def harness(tmp_path):
    tools = tmp_path / 'bin'
    tools.mkdir()
    output = tmp_path / 'upload'
    output.mkdir()
    probe = '#!' + sys.executable + '\n' + r'''
import json, os, signal, sys, time
from pathlib import Path
kind = Path(sys.argv[0]).name
record = Path(os.environ['PROBE_LOG'])
def log(event):
    with record.open('a') as f:
        f.write(json.dumps(dict(kind=kind, event=event, pid=os.getpid(), args=sys.argv[1:])) + '\n')
log('start')
if kind == 'curl':
    url = sys.argv[-1]
    if '_cat/health' in url:
        print(os.environ.get('HEALTH', 'green'))
        sys.exit(int(os.environ.get('HEALTH_STATUS', '0')))
    if '_index_template/' in url:
        print(os.environ.get('TEMPLATE', '{"index_templates":[{"name":"malcolm_template"}]}'))
        sys.exit(int(os.environ.get('TEMPLATE_STATUS', '0')))
    print(os.environ.get('USERS', '[{"index":"arkime_users_v8"}]'))
    sys.exit(int(os.environ.get('USERS_STATUS', '0')))
def stop(sig, frame):
    log('stop')
    sys.exit(0)
signal.signal(signal.SIGTERM, stop)
signal.signal(signal.SIGINT, stop)
mode = os.environ.get('CAPTURE_MODE' if kind == 'capture' else 'TCPDUMP_MODE', 'exit')
if mode == 'hold' or (mode == 'fail-one' and sys.argv[sys.argv.index('-i') + 1] != 'test0'):
    while True:
        time.sleep(0.05)
time.sleep(0.15)
sys.exit(int(os.environ.get('CAPTURE_STATUS' if kind == 'capture' else 'TCPDUMP_STATUS', '17')))
'''
    for name in ('curl', 'capture', 'tcpdump'):
        path = tools / name
        path.write_text(probe)
        path.chmod(0o755)
    env = {k: v for k, v in os.environ.items() if not k.startswith(('ARKIME_', 'PCAP_'))}
    env.update(
        PATH=f'{tools}:{os.environ["PATH"]}',
        PROBE_LOG=str(tmp_path / 'calls.jsonl'),
        PCAP_IFACE='test0',
        PUSER='root',
        ARKIME_LIVE_CAPTURE_FALLBACK_SECONDS='1',
    )
    return env, output


def calls(harness, kind=None, event='start'):
    path = Path(harness[0]['PROBE_LOG'])
    rows = [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []
    return [row for row in rows if (kind is None or row['kind'] == kind) and row['event'] == event]


def command(harness, expression):
    return [
        'bash',
        '-c',
        f'source {shlex.quote(str(HELPER))}; capture_fallback_init; '
        'CURL_CONFIG_PARAMS=(--config /test/credentials); OPENSEARCH_URL=https://backend.invalid; ' + expression,
        'capture-test',
        str(harness[1]),
    ]


def run(harness, expression, **extra):
    return subprocess.run(
        command(harness, expression), env=harness[0] | extra, capture_output=True, text=True, timeout=8, check=False
    )


@pytest.mark.parametrize('health', ['green', 'yellow', ' yellow \n'])
def test_backend_ready(harness, health):
    result = run(harness, 'wait_for_arkime_backend', HEALTH=health)
    assert result.returncode == 0, result.stderr
    requests = calls(harness, 'curl')
    assert len(requests) == 3
    for row in requests:
        assert row['args'][:2] == ['--config', '/test/credentials']
        assert '--fail' in row['args']
        assert int(row['args'][row['args'].index('--max-time') + 1]) <= 1


@pytest.mark.parametrize(
    'overrides',
    [
        {'HEALTH': 'red'},
        {'HEALTH_STATUS': '22'},
        {'TEMPLATE': '{"index_templates":[]}'},
        {'TEMPLATE': 'not json'},
        {'TEMPLATE_STATUS': '22'},
        {'USERS': '[]'},
        {'USERS': '[{"index":"unrelated"}]'},
        {'USERS_STATUS': '22'},
    ],
)
def test_backend_failure_is_bounded(harness, overrides):
    started = time.monotonic()
    result = run(harness, 'wait_for_arkime_backend', **overrides)
    assert result.returncode == 1
    assert time.monotonic() - started < 4
    assert not calls(harness, 'tcpdump')


def test_timeout_starts_fallback(harness):
    result = run(harness, 'wait_for_arkime_backend || tcpdump_fallback "$1"', HEALTH='red')
    assert result.returncode == 17
    assert len(calls(harness, 'tcpdump')) == 1
    assert not calls(harness, 'capture')


@pytest.mark.parametrize(
    'value,expected', [('0', '0'), ('008', '8'), ('invalid', '300'), ('999999999999999999999', '300')]
)
def test_timeout_validation(harness, value, expected):
    result = run(
        harness, 'printf "%s" "$ARKIME_LIVE_CAPTURE_FALLBACK_SECONDS"', ARKIME_LIVE_CAPTURE_FALLBACK_SECONDS=value
    )
    assert result.returncode == 0
    assert result.stdout == expected


def wait_for_calls(harness, kind, count):
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if len(calls(harness, kind)) >= count:
            return
        time.sleep(0.02)
    pytest.fail(f'{kind} did not start')


def assert_stopped(harness, kind):
    for row in calls(harness, kind):
        with pytest.raises(ProcessLookupError):
            os.kill(row['pid'], 0)


def test_disabled_fallback_keeps_waiting_and_can_be_stopped(harness):
    env = harness[0] | {'ARKIME_LIVE_CAPTURE_FALLBACK_SECONDS': '0', 'HEALTH': 'red'}
    p = subprocess.Popen(
        command(harness, 'wait_for_arkime_backend || tcpdump_fallback "$1"'),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        wait_for_calls(harness, 'curl', 2)
        assert p.poll() is None
        p.terminate()
        p.communicate(timeout=6)
        assert p.returncode == 143
        assert not calls(harness, 'tcpdump')
    finally:
        if p.poll() is None:
            p.kill()
            p.wait()


@pytest.mark.parametrize('status,fallback', [('0', False), ('130', False), ('143', False), ('1', True), ('134', True)])
def test_capture_exit_policy(harness, status, fallback):
    result = run(harness, 'run_arkime_capture "$1" capture --node test-node', CAPTURE_STATUS=status)
    assert result.returncode == (17 if fallback else int(status))
    assert bool(calls(harness, 'tcpdump')) is fallback
    assert calls(harness, 'capture')[0]['args'] == ['--node', 'test-node']


def test_disabled_fallback_preserves_capture_error(harness):
    result = run(
        harness, 'run_arkime_capture "$1" capture', CAPTURE_STATUS='42', ARKIME_LIVE_CAPTURE_FALLBACK_SECONDS='0'
    )
    assert result.returncode == 42
    assert not calls(harness, 'tcpdump')


def test_multi_interface_arguments_and_failed_sibling_cleanup(harness):
    result = run(
        harness,
        'tcpdump_fallback "$1"',
        PCAP_IFACE='test0,test1,test0',
        PCAP_FILTER='tcp port 443 or (udp and port 53)',
        PCAP_ROTATE_MINUTES='02',
        PCAP_ROTATE_MEGABYTES='08',
        PCAP_SNAPLEN='096',
        TCPDUMP_MODE='fail-one',
    )
    assert result.returncode == 17, result.stderr
    rows = calls(harness, 'tcpdump')
    assert len(rows) == 2
    assert {r['args'][1] for r in rows} == {'test0', 'test1'}
    for row in rows:
        args = row['args']
        assert args[args.index('-G') + 1] == '120'
        assert args[args.index('-C') + 1] == '8'
        assert args[args.index('-s') + 1] == '96'
        assert args[args.index('-Z') + 1] == 'root'
        filename = Path(args[args.index('-w') + 1])
        assert filename.parent == harness[1]
        assert filename.name.startswith('mtcpdump-')
        assert args[-1] == 'tcp port 443 or (udp and port 53)'
    assert_stopped(harness, 'tcpdump')


@pytest.mark.parametrize(
    'expression,kind,count,extra',
    [
        ('run_arkime_capture "$1" capture', 'capture', 1, {'CAPTURE_MODE': 'hold'}),
        ('tcpdump_fallback "$1"', 'tcpdump', 2, {'TCPDUMP_MODE': 'hold', 'PCAP_IFACE': 'test0,test1'}),
    ],
)
@pytest.mark.parametrize('stop_signal,expected', [(signal.SIGTERM, 143), (signal.SIGINT, 130)])
def test_service_shutdown_cleans_up_all_children(harness, expression, kind, count, extra, stop_signal, expected):
    p = subprocess.Popen(
        command(harness, expression), env=harness[0] | extra, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
    )
    try:
        wait_for_calls(harness, kind, count)
        p.send_signal(stop_signal)
        p.communicate(timeout=6)
        assert p.returncode == expected
        assert_stopped(harness, kind)
        if kind == 'capture':
            assert not calls(harness, 'tcpdump')
    finally:
        if p.poll() is None:
            p.kill()
            p.wait()


@pytest.mark.parametrize(
    'overrides',
    [
        {'PCAP_IFACE': ''},
        {'PCAP_IFACE': '../outside'},
        {'PCAP_ROTATE_MINUTES': '1+1'},
        {'PCAP_SNAPLEN': '-1'},
        {'PCAP_TCPDUMP_FILENAME_PATTERN': '../%s.pcap'},
        {'PCAP_TCPDUMP_FILENAME_PATTERN': '%D.pcap'},
    ],
)
def test_invalid_capture_configuration_is_rejected_before_launch(harness, overrides):
    result = run(harness, 'tcpdump_fallback "$1"', **overrides)
    assert result.returncode != 0
    assert not calls(harness, 'tcpdump')
