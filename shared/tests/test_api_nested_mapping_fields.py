"""The fields API must retain leaves inside mapping object properties."""

from copy import deepcopy
import importlib
import json
import os
from pathlib import Path
from unittest.mock import Mock, patch

import pytest
import requests

ROOT = Path(__file__).resolve().parents[2]

with patch.dict(
    os.environ,
    {
        'OPENSEARCH_URL': 'http://search.example:9200',
        'OPENSEARCH_PRIMARY': 'opensearch-local',
        'MALCOLM_API_PREFIX': 'mapi',
        'ROLE_BASED_ACCESS': 'false',
    },
), patch('malcolm_utils.ParseCurlFile', return_value={'user': None, 'password': None}), patch(
    'requests.sessions.Session.send', side_effect=AssertionError('network disabled')
):
    api = importlib.import_module('project')


@pytest.mark.parametrize('debug', [False, True])
@pytest.mark.parametrize('kind', [None, 'object', 'nested'])
def test_object_children_have_qualified_names_and_existing_type_mapping(monkeypatch, debug, kind):
    monkeypatch.setattr(api, 'debugApi', debug)
    definition = {'properties': {'ip': {'type': 'ip'}, 'port': {'type': 'integer'}}}
    if kind is not None:
        definition['type'] = kind
    result = api.extract_field_info({'endpoint': definition}, source='fixture')
    assert result['endpoint.ip']['type'] == 'ip'
    assert result['endpoint.port']['type'] == 'integer'
    assert ('endpoint' in result) is (kind is not None)
    assert 'ip' not in result and 'port' not in result
    if debug:
        assert result['endpoint.ip']['original'][0]['source'] == 'fixture'
        assert result['endpoint.ip']['original'][0]['type'] == 'ip'


def test_multiple_levels_keep_dotted_siblings_and_original_input(monkeypatch):
    monkeypatch.setattr(api, 'debugApi', False)
    mapping = {
        'source': {'properties': {'geo': {'properties': {'location': {'type': 'geo_point'}}}}},
        'event.risk_score': {'type': 'float'},
    }
    original = deepcopy(mapping)
    result = api.extract_field_info(mapping)
    assert result == {'source.geo.location': {'type': 'geo'}, 'event.risk_score': {'type': 'float'}}
    assert mapping == original


@pytest.mark.parametrize(
    'component,path,kind',
    [
        ('filescan', 'filescan.rules.scanner', 'string'),
        ('suricata', 'suricata.alert.severity', 'integer'),
        ('malcolm_common', 'destination.device.id', 'integer'),
    ],
)
def test_checked_in_component_templates_expose_nested_fields(monkeypatch, component, path, kind):
    monkeypatch.setattr(api, 'debugApi', False)
    document = json.loads((ROOT / f'dashboards/templates/composable/component/{component}.json').read_text())
    fields = api.extract_field_info(document['template']['mappings']['properties'])
    assert fields[path]['type'] == kind


def test_empty_objects_flat_fields_and_existing_parent_entries_remain_unchanged(monkeypatch):
    monkeypatch.setattr(api, 'debugApi', False)
    mapping = {
        'empty': {'properties': {}},
        'explicit': {'type': 'object', 'properties': {}},
        'flat': {'type': 'keyword'},
        '@timestamp': {'type': 'date'},
        'opaque': {'type': 'flat_object'},
    }
    assert api.extract_field_info(mapping) == {
        'explicit': {'type': 'string'},
        'flat': {'type': 'string'},
        '@timestamp': {'type': 'date'},
        'opaque': {'type': 'string'},
    }
    assert api.extract_field_info({}) == {}


@pytest.mark.parametrize('debug', [False, True])
def test_fields_endpoint_uses_nested_inline_and_component_mappings(monkeypatch, debug):
    monkeypatch.setattr(api, 'debugApi', debug)
    monkeypatch.setattr(api, 'get_dashboards_fields', Mock(return_value={}))
    monkeypatch.setattr(api, 'check_roles', Mock(return_value=True))
    payloads = {
        '/_index_template/fixture': {
            'index_templates': [
                {
                    'name': 'fixture',
                    'index_template': {
                        'template': {
                            'mappings': {
                                'properties': {
                                    'inline': {'properties': {'count': {'type': 'long'}}},
                                    '@version': {'type': 'keyword'},
                                }
                            }
                        },
                        'composed_of': ['component'],
                    },
                }
            ]
        },
        '/_component_template/component': {
            'component_templates': [
                {
                    'component_template': {
                        'template': {
                            'mappings': {
                                'properties': {
                                    'capture': {'properties': {'source': {'properties': {'ip': {'type': 'ip'}}}}}
                                }
                            }
                        }
                    }
                }
            ]
        },
    }

    def get(url, **kwargs):
        from urllib.parse import urlparse

        response = requests.Response()
        response.status_code = 200
        response._content = json.dumps(payloads[urlparse(url).path]).encode()
        return response

    monkeypatch.setattr(api.requests, 'get', Mock(side_effect=get))
    url = '/' + api.app.config['MALCOLM_API_PREFIX'].strip('/') + '/fields'
    response = api.app.test_client().get(url, query_string={'template': 'fixture'})
    assert response.status_code == 200, response.data
    data = response.get_json()
    assert data['fields']['inline.count']['type'] == 'integer'
    assert data['fields']['capture.source.ip']['type'] == 'ip'
    assert data['total'] == 2
    assert '@version' not in data['fields']
