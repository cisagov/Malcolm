"""Supervisor process failures must not disappear from filescan health."""

import importlib
from pathlib import Path
import sys
from unittest.mock import Mock, patch

import pytest
import supervisor.childutils

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

# Replace the external supervisor interface before importing the health module.
with patch.object(supervisor.childutils, 'getRPCInterface', return_value=Mock()):
    health = importlib.import_module('filescan.health')


@pytest.fixture
def endpoint(monkeypatch):
    rpc = Mock()
    rpc.supervisor.getSupervisorVersion.return_value = '4.3.0'
    rpc.supervisor.getState.return_value = {'statename': 'RUNNING'}
    monkeypatch.setattr(health, 'rpc', rpc)

    def request(state, *, autostart=False, exitstatus=0, start=100, stop=200, exitcodes=(0,)):
        rpc.supervisor.getAllConfigInfo.return_value = [
            {'name': 'scanner', 'group': 'filescan', 'autostart': autostart, 'exitcodes': list(exitcodes)}
        ]
        rpc.supervisor.getAllProcessInfo.return_value = [
            {
                'name': 'scanner',
                'group': 'filescan',
                'statename': state,
                'start': start,
                'stop': stop,
                'exitstatus': exitstatus,
                'spawnerr': '',
            }
        ]
        response = health.app.test_client().get('/health')
        assert response.status_code == 200
        return response.get_json()

    return request, rpc


@pytest.mark.parametrize('state', ['FATAL', 'BACKOFF', 'UNKNOWN'])
def test_failed_optional_process_is_unhealthy(endpoint, state):
    request, _ = endpoint
    result = request(state, start=0, stop=0)
    assert result['health'] == 'unhealthy'
    assert result['programs']['filescan'][0]['healthy'] is False
    assert 'error' not in result


@pytest.mark.parametrize('exitstatus,expected', [(0, 'healthy'), (2, 'healthy'), (1, 'unhealthy'), (127, 'unhealthy')])
def test_exited_process_uses_allowed_codes_and_real_stop_field(endpoint, exitstatus, expected):
    request, _ = endpoint
    result = request('EXITED', exitstatus=exitstatus, exitcodes=(0, 2))
    assert result['health'] == expected
    assert 'error' not in result
    program = result['programs']['filescan'][0]
    assert program['start'] == 100
    assert program['stop'] == 200
    assert program['exitstatus'] == exitstatus
    if expected == 'unhealthy':
        assert program['healthy'] is False


def test_running_process_retains_start_time_and_positive_health(endpoint):
    request, _ = endpoint
    result = request('RUNNING', autostart=True, stop=0)
    assert result['health'] == 'healthy'
    program = result['programs']['filescan'][0]
    assert program['state'] == 'running'
    assert program['healthy'] is True
    assert program['start'] == 100
    assert 'stop' not in program
    assert 'exitstatus' not in program


@pytest.mark.parametrize('state', ['STARTING', 'STOPPED', 'STOPPING'])
@pytest.mark.parametrize('autostart', [False, True])
def test_existing_startup_and_optional_stop_policy_is_preserved(endpoint, state, autostart):
    request, _ = endpoint
    result = request(state, autostart=autostart, start=0, stop=0)
    assert result['health'] == ('unhealthy' if autostart else 'healthy')
    assert result['programs']['filescan'][0]['state'] == state.lower()


def test_nonrunning_autostart_process_is_unhealthy_even_after_expected_exit(endpoint):
    request, _ = endpoint
    result = request('EXITED', autostart=True, exitstatus=0)
    assert result['health'] == 'unhealthy'
    assert result['programs']['filescan'][0]['stop'] == 200


def test_one_failed_program_marks_aggregate_health_unhealthy(endpoint):
    _, rpc = endpoint
    rpc.supervisor.getAllConfigInfo.return_value = [
        {'name': name, 'group': 'filescan', 'autostart': False, 'exitcodes': [0]} for name in ['a', 'b']
    ]
    rpc.supervisor.getAllProcessInfo.return_value = [
        {
            'name': name,
            'group': 'filescan',
            'statename': state,
            'start': 100,
            'stop': stop,
            'exitstatus': code,
            'spawnerr': '',
        }
        for name, state, stop, code in [('a', 'RUNNING', 0, 0), ('b', 'EXITED', 200, 1)]
    ]
    result = health.app.test_client().get('/health').get_json()
    assert result['health'] == 'unhealthy'
    assert [program['healthy'] for program in result['programs']['filescan']] == [True, False]


def test_supervisor_errors_keep_the_existing_error_response(endpoint):
    _, rpc = endpoint
    rpc.supervisor.getAllProcessInfo.side_effect = RuntimeError('offline test interface')
    result = health.app.test_client().get('/health').get_json()
    assert result['health'] == 'error'
    assert 'offline test interface' in result['error']
