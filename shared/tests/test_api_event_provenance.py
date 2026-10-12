"""/mapi/event documents must record their submitter and never reuse pipeline record IDs."""

from collections import defaultdict
import os
from unittest.mock import Mock, patch

import pytest

import malcolm_utils

with patch.dict(
    os.environ, {'OPENSEARCH_URL': 'https://search.example:9200', 'OPENSEARCH_PRIMARY': 'opensearch-local'}
), patch.object(malcolm_utils, 'ParseCurlFile', return_value=defaultdict(lambda: None)), patch(
    'socket.create_connection', side_effect=AssertionError('Network access in offline tests')
):
    import project as api


@pytest.fixture(autouse=True)
def role_based_access_disabled(monkeypatch):
    monkeypatch.setitem(api.app.config, 'ROLE_BASED_ACCESS', 'false')


def post_event(body, headers, base_url='http://localhost/'):
    index = Mock(return_value={'result': 'created'})
    with patch.object(api.databaseClient, 'index', new=index):
        with api.app.test_client() as client:
            url = '/' + api.app.config['MALCOLM_API_PREFIX'].strip('/') + '/event'
            response = client.post(url, json=body, headers=headers, base_url=base_url)
    assert response.status_code == 200, response.data
    return index.call_args.kwargs


ZEEK_STYLE_ID = 'Cgnjsc2Tkdl38g25D6-cotp-5485'


def test_external_submission_records_forwarded_user_and_namespaced_id():
    body = {'alert': {'alert': ZEEK_STYLE_ID, 'period': {'start': '2021-03-01T12:00:00Z'}}}
    call = post_event(body, {'X-Forwarded-User': 'analyst', 'X-Forwarded-For': '192.0.2.10'})
    assert call['id'] == f'210301-alert.{ZEEK_STYLE_ID}'
    assert call['id'] != f'210301-{ZEEK_STYLE_ID}'
    assert call['body']['event']['submitter'] == 'analyst'


def test_internal_loopback_is_marked_internal():
    body = {'alert': {'alert': 'loopback-alert', 'period': {'start': '2021-03-01T12:00:00Z'}}}
    # what Dashboards Alerting's loopback destination looks like: Host api:5000, no X-Forwarded-For
    call = post_event(body, {}, base_url='http://api:5000/')
    assert call['body']['event']['submitter'] == 'internal'


@pytest.mark.parametrize(
    'spoofed', [{'event': {'submitter': 'internal'}}, {'event': {'submitter': 'someone-else'}}, {'event': 'internal'}]
)
def test_body_cannot_supply_the_submitter(spoofed):
    body = {'alert': {'alert': 'spoof-attempt', 'body': spoofed}}
    call = post_event(body, {'X-Forwarded-User': 'analyst', 'X-Forwarded-For': '192.0.2.10'})
    assert call['body']['event']['submitter'] == 'analyst'


def test_missing_forwarded_user_is_unknown():
    call = post_event({'alert': {'alert': 'no-user'}}, {'X-Forwarded-For': '192.0.2.10'})
    assert call['body']['event']['submitter'] == 'unknown'
