"""Supervisor health must pair configuration with the same process identity."""

from copy import deepcopy
import importlib
from pathlib import Path
import sys
from unittest.mock import Mock, patch

import pytest
import supervisor.childutils

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
with patch.object(supervisor.childutils, 'getRPCInterface', return_value=Mock()):
    health = importlib.import_module('filescan.health')


def config(group, name, autostart, inuse=True):
    return {'group': group, 'name': name, 'autostart': autostart, 'exitcodes': [0], 'inuse': inuse}


def process(group, name, state):
    return {'group': group, 'name': name, 'statename': state, 'start': 0, 'stop': 0, 'exitstatus': 0, 'spawnerr': ''}


@pytest.fixture
def endpoint(monkeypatch):
    rpc = Mock()
    rpc.supervisor.getSupervisorVersion.return_value = '4.3.0'
    rpc.supervisor.getState.return_value = {'statename': 'RUNNING'}
    monkeypatch.setattr(health, 'rpc', rpc)

    def request(configs, procs):
        original = deepcopy((configs, procs))
        rpc.supervisor.getAllConfigInfo.return_value = configs
        rpc.supervisor.getAllProcessInfo.return_value = procs
        response = health.app.test_client().get('/health')
        assert response.status_code == 200
        assert (configs, procs) == original
        return response.get_json()

    return request


@pytest.mark.parametrize('reverse_config', [False, True])
@pytest.mark.parametrize('reverse_processes', [False, True])
def test_repeated_names_use_their_own_groups_policy(endpoint, reverse_config, reverse_processes):
    configs = [config('required', 'worker', True), config('optional', 'worker', False)]
    procs = [process('required', 'worker', 'STOPPED'), process('optional', 'worker', 'RUNNING')]
    result = endpoint(configs[::-1] if reverse_config else configs, procs[::-1] if reverse_processes else procs)
    assert result['health'] == 'unhealthy'
    assert result['programs']['required'][0]['healthy'] is False
    assert result['programs']['optional'][0]['healthy'] is True


@pytest.mark.parametrize('inactive_name', ['aaa', 'worker', 'zzz'])
def test_unused_configuration_cannot_mask_a_required_process(endpoint, inactive_name):
    result = endpoint(
        [config('unused', inactive_name, False, inuse=False), config('filescan', 'worker', True)],
        [process('filescan', 'worker', 'STOPPED')],
    )
    assert result['health'] == 'unhealthy'
    assert list(result['programs']) == ['filescan']
    assert result['programs']['filescan'][0]['healthy'] is False


def test_unused_required_configuration_does_not_make_an_optional_stop_unhealthy(endpoint):
    result = endpoint(
        [config('unused', 'aaa', True, inuse=False), config('filescan', 'worker', False)],
        [process('filescan', 'worker', 'STOPPED')],
    )
    assert result['health'] == 'healthy'
    assert 'healthy' not in result['programs']['filescan'][0]


@pytest.mark.parametrize('configs', [[], [config('different', 'worker', False)]])
def test_process_without_matching_configuration_returns_error(endpoint, configs):
    result = endpoint(configs, [process('filescan', 'worker', 'RUNNING')])
    assert result['health'] == 'error'
    assert 'filescan' in result['error']
    assert 'worker' in result['error']


def test_extra_process_is_not_silently_dropped_by_zip(endpoint):
    result = endpoint(
        [config('filescan', 'first', False)],
        [process('filescan', 'first', 'RUNNING'), process('filescan', 'unconfigured', 'RUNNING')],
    )
    assert result['health'] == 'error'
    assert 'unconfigured' in result['error']


def test_unique_names_keep_the_existing_sorted_output(endpoint):
    result = endpoint(
        [config('filescan', 'b', False), config('filescan', 'a', True)],
        [process('filescan', 'b', 'STOPPED'), process('filescan', 'a', 'RUNNING')],
    )
    assert result['health'] == 'healthy'
    assert [p['name'] for p in result['programs']['filescan']] == ['a', 'b']


def test_empty_process_snapshot_preserves_existing_response(endpoint):
    result = endpoint([config('unloaded', 'worker', True, inuse=False)], [])
    assert result['health'] == 'healthy'
    assert result['programs'] == {}
