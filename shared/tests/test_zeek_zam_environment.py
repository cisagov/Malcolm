"""Exercise Zeek launchers with executable probes that record their arguments and environment."""

import json
import logging
import os
import shlex
import shutil
import struct
import subprocess
import sys
from collections import deque
from pathlib import Path
from types import SimpleNamespace

import pcap_processor
import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
ZAM_SETTINGS = [(None, False), ('false', False), ('0', False), ('', False), ('true', True)]


@pytest.fixture
def zeek_tools(tmp_path):
    install = tmp_path / 'zeek'
    bin_dir = install / 'bin'
    bin_dir.mkdir(parents=True)
    (install / 'etc').mkdir()
    (install / 'etc' / 'zeekctl.cfg').write_text('ZeekArgs = -C -O ZAM\nSitePolicyScripts = local\n')
    records = tmp_path / 'invocations.jsonl'
    probe = f'#!{sys.executable}\n' + '''\
import json
import os
from pathlib import Path
import sys

command = Path(sys.argv[0]).name
with open(os.environ['TEST_ZEEK_INVOCATIONS'], 'a') as output:
    output.write(json.dumps({
        'command': command,
        'args': sys.argv[1:],
        'zam_present': 'ZEEK_ZAM' in os.environ,
        'extract_mode': os.getenv('ZEEK_EXTRACTOR_MODE'),
        'capture_filter': os.getenv('CAPTURE_FILTER'),
    }) + '\\n')
if command == 'zeekctl':
    if sys.argv[1:] == ['status']:
        print('Name Type Host Status Pid')
else:
    if '-NN' in sys.argv:
        print('Test::Plugin')
    if 'policy/misc/loaded-scripts' in sys.argv:
        Path('loaded_scripts.log').write_text('test.zeek\\n')
    Path('conn.log').write_text('connection\\n')
'''
    for name in ('zeek-offline', 'zeekctl'):
        executable = bin_dir / name
        executable.write_text(probe)
        executable.chmod(0o755)

    # Let the real deployment script finish without waiting or inspecting host Zeek processes.
    for name, exit_code in (('sleep', 0), ('pidof', 1)):
        executable = bin_dir / name
        executable.write_text(f'#!/bin/sh\nexit {exit_code}\n')
        executable.chmod(0o755)

    pcap = tmp_path / 'sample.pcap'
    pcap.write_bytes(struct.pack('<IHHIIII', 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    return SimpleNamespace(install=install, bin_dir=bin_dir, records=records, pcap=pcap)


def read_invocations(tools):
    return [json.loads(line) for line in tools.records.read_text().splitlines()]


def shell_environment(tools, tmp_path, setting):
    env = {key: value for key, value in os.environ.items() if not key.startswith('ZEEK_')}
    env.update(
        PATH=f'{tools.bin_dir}{os.pathsep}{os.environ["PATH"]}',
        TEST_ZEEK_INVOCATIONS=str(tools.records),
        ZEEK_DIR=str(tools.install),
        ZEEK_LOG_PATH=str(tmp_path / 'logs'),
        EXTRACT_FILES_PATH=str(tmp_path / 'extract_files'),
        ZEEK_INTEL_PATH=str(tmp_path / 'intel'),
        ZEEK_CUSTOM_PATH=str(tmp_path / 'custom'),
        ZEEK_INTEL_REFRESH_ON_DEPLOY='false',
        ZEEK_AF_PACKET_BUFFER_SIZE='67108864',
        ZEEK_LB_PROCS_WORKER_DEFAULT='1',
        CAPTURE_INTERFACE='test0',
        CAPTURE_FILTER='tcp port 443',
    )
    if setting is not None:
        env['ZEEK_ZAM'] = setting
    return env


def run_shell(script, env, *args):
    required = ('bash', 'which', 'realpath', 'dirname', 'grep', 'sed', 'awk', 'stat', 'tail', 'wc', 'tr', 'mktemp')
    if sys.platform != 'linux' or not all(shutil.which(name) for name in required):
        pytest.skip('requires Linux and the Zeek launcher shell utilities')
    result = subprocess.run(
        ['bash', str(REPO_ROOT / 'zeek' / 'scripts' / script), *args],
        env=env,
        text=True,
        capture_output=True,
        timeout=15,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize('setting,enabled', ZAM_SETTINGS + [('TRUE', True), ('1', True)])
def test_offline_worker_controls_zam_without_exporting_it(monkeypatch, tmp_path, zeek_tools, setting, enabled):
    if setting is None:
        monkeypatch.delenv('ZEEK_ZAM', raising=False)
    else:
        monkeypatch.setenv('ZEEK_ZAM', setting)
    monkeypatch.setenv('TEST_ZEEK_INVOCATIONS', str(zeek_tools.records))
    monkeypatch.setenv('CAPTURE_FILTER', 'tcp port 443')
    monkeypatch.setattr(pcap_processor, 'shuttingDown', False)

    class FiniteQueue(deque):
        def popleft(self):
            item = super().popleft()
            if not self:
                pcap_processor.shuttingDown = True
            return item

    captures = [tmp_path / 'first.pcap', tmp_path / 'second.pcap']
    for capture in captures:
        capture.write_bytes(zeek_tools.pcap.read_bytes())
    queue = FiniteQueue({'name': str(capture)} for capture in captures)
    upload = tmp_path / 'upload'
    upload.mkdir()
    pcap_processor.zeekFileWorker(
        (
            queue,
            [str(tmp_path)],
            str(zeek_tools.bin_dir / 'zeek-offline'),
            True,
            False,
            [],
            True,
            str(upload),
            'interesting',
            logging.getLogger(__name__),
            False,
        )
    )

    invocations = read_invocations(zeek_tools)
    assert len(invocations) == 2
    for capture, invocation in zip(captures, invocations):
        expected_args = ['-r', str(capture), 'local']
        if enabled:
            expected_args.extend(['-O', 'ZAM'])
        expected_args.extend(['extractor.zeek', 'extractor_override.interesting.zeek'])
        assert invocation['args'] == expected_args
        assert not invocation['zam_present']
        assert invocation['extract_mode'] == 'mapped'
        assert invocation['capture_filter'] == 'tcp port 443'
    assert os.environ.get('ZEEK_ZAM') == setting
    assert len(list(upload.glob('*.tar.gz'))) == 2


@pytest.mark.parametrize('setting,enabled', ZAM_SETTINGS)
@pytest.mark.parametrize('from_config_file', [False, True])
def test_live_deploy_controls_zam_without_exporting_it(tmp_path, zeek_tools, setting, enabled, from_config_file):
    env = shell_environment(zeek_tools, tmp_path, setting)
    args = []
    if from_config_file:
        # The sourced setting must take precedence over the inherited environment.
        env['ZEEK_ZAM'] = 'false' if enabled else 'true'
        config = tmp_path / 'capture.conf'
        config.write_text('unset ZEEK_ZAM\n' if setting is None else f'ZEEK_ZAM={shlex.quote(setting)}\n')
        args.append(str(config))
    run_shell('zeekdeploy.sh', env, *args)

    invocations = read_invocations(zeek_tools)
    assert [invocation['args'] for invocation in invocations] == [['deploy'], ['status'], ['status'], ['stop']]
    assert all(not invocation['zam_present'] for invocation in invocations)
    assert all(invocation['capture_filter'] == 'tcp port 443' for invocation in invocations)
    config = (zeek_tools.install / 'etc' / 'zeekctl.cfg').read_text()
    zeek_args = next(line.split('=', 1)[1].split() for line in config.splitlines() if line.startswith('ZeekArgs'))
    assert zeek_args == (['-C', '-O', 'ZAM'] if enabled else ['-C'])
    assert 'ZEEK_ZAM' not in (zeek_tools.install / 'etc' / 'node.cfg').read_text()


@pytest.mark.parametrize('setting,enabled', ZAM_SETTINGS)
@pytest.mark.parametrize('script', ['validate_local_site_policy.sh', 'zeek_sanity_check.sh'])
def test_direct_launch_helpers_control_zam(tmp_path, zeek_tools, script, setting, enabled):
    env = shell_environment(zeek_tools, tmp_path, setting)
    env.update(
        ZEEK_SANITY_PCAP=str(zeek_tools.pcap),
        ZEEK_THIRD_PARTY_PLUGINS_GREP='(Test::Plugin)',
        ZEEK_THIRD_PARTY_SCRIPTS_GREP=r'(test)\.(zeek|bro)',
    )
    args = ['-p', str(zeek_tools.pcap)] if script == 'validate_local_site_policy.sh' else []
    run_shell(script, env, *args)

    invocations = read_invocations(zeek_tools)
    assert len(invocations) == (1 if script == 'validate_local_site_policy.sh' else 2)
    for invocation in invocations:
        assert not invocation['zam_present']
        assert ('ZAM' in invocation['args']) == enabled
        if enabled:
            assert invocation['args'][invocation['args'].index('ZAM') - 1] == '-O'
        assert invocation['capture_filter'] == 'tcp port 443'


def test_policy_validation_preserves_explicit_optimizer_arguments(tmp_path, zeek_tools):
    env = shell_environment(zeek_tools, tmp_path, 'false')
    run_shell('validate_local_site_policy.sh', env, '-p', str(zeek_tools.pcap), '--', '-O', 'ZAM')
    (invocation,) = read_invocations(zeek_tools)
    assert not invocation['zam_present']
    assert invocation['args'] == ['-C', '-r', str(zeek_tools.pcap), 'local', '-O', 'ZAM']
