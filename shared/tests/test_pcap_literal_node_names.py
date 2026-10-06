"""Node names used for PCAP duplicate checks are identifiers, not regexes."""

import json
import logging
from pathlib import Path
import re
import struct
import sys
from types import SimpleNamespace
from unittest.mock import Mock

import opensearchpy
import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / 'scripts'), str(ROOT / 'shared/bin')]
import pcap_watcher as watcher_module


@pytest.fixture
def capture(tmp_path):
    path = tmp_path / 'test.pcap'
    path.write_bytes(struct.pack('<IHHIIII', 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    return path


def process(monkeypatch, capture, node, stored_node):
    args = SimpleNamespace(
        minBytes=24, maxBytes=1000, baseDir=str(capture.parent), nodeName=node, includeAbsolutePath=False
    )
    monkeypatch.setattr(watcher_module, 'args', args)
    monkeypatch.setattr(watcher_module, 'SearchClass', opensearchpy.Search)
    client = opensearchpy.OpenSearch(hosts=['http://search.example:9200'])
    bodies = []

    def search(**kwargs):
        body = kwargs['body']
        bodies.append(body)
        predicate = body['query']['bool']['filter'][0]
        if 'terms' in predicate:
            matched = stored_node in predicate['terms']['node']
        else:
            # Fixture node patterns use regex operators shared by Lucene and Python.
            matched = re.fullmatch(predicate['regexp']['node'], stored_node) is not None
        hits = [{'_id': '1', '_source': {'node': stored_node, 'filesize': capture.stat().st_size}}] if matched else []
        return {'hits': {'hits': hits, 'total': {'value': len(hits), 'relation': 'eq'}}}

    monkeypatch.setattr(client, 'search', search)
    handler = object.__new__(watcher_module.EventWatcher)
    handler.logger = logging.getLogger(__name__)
    handler.openSearchClient = client
    handler.useOpenSearch = True
    handler.topic_socket = Mock()
    handler.processFile(str(capture))
    assert len(bodies) == 1
    return handler.topic_socket, bodies[0]


@pytest.mark.parametrize('node', ['sensor', 'sensor.1', 'sensor+east', 'sensor(blue)', 'sensor|blue'])
@pytest.mark.parametrize('suffix', ['', '-upload'])
def test_exact_node_and_upload_variant_are_still_duplicates(monkeypatch, capture, node, suffix):
    publisher, _ = process(monkeypatch, capture, node, node + suffix)
    publisher.send_string.assert_not_called()


@pytest.mark.parametrize(
    'node,other',
    [
        ('sensor.1', 'sensorX1'),
        ('sensor.1', 'sensorX1-upload'),
        ('sensor+east', 'sensoreast'),
        ('sensor(blue)', 'sensorblue'),
        ('sensor|blue', 'blue'),
        ('sensor', 'sensor-other'),
    ],
)
def test_other_nodes_do_not_suppress_a_new_capture(monkeypatch, capture, node, other):
    publisher, _ = process(monkeypatch, capture, node, other)
    publisher.send_string.assert_called_once()
    message = json.loads(publisher.send_string.call_args.args[0])
    assert message['name'] == 'test.pcap'
    assert message['node'] == node
    assert message['size'] == 24
