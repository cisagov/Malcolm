"""MISP manifest cutoff decisions must not depend on the host timezone."""

from datetime import datetime, timedelta, timezone
import io
import json
import os
import time
from unittest.mock import Mock, patch

import pytest
import requests

import zeek_threat_feed_utils as feeds
from malcolm_utils import AtomicInt

NOW = datetime(2026, 1, 2, 12, tzinfo=timezone.utc)
BASE = 'https://feed.example/'
EVENT = {
    'Event': {
        'info': 'offline manifest test',
        'timestamp': int(NOW.timestamp()),
        'Attribute': [
            {
                'type': 'domain',
                'value': 'indicator.example',
                'category': 'Network activity',
                'to_ids': True,
                'timestamp': int(NOW.timestamp()),
            }
        ],
    }
}


def response(value, html=False):
    result = requests.Response()
    result.status_code = 200
    result._content = (value if html else json.dumps(value)).encode()
    return result


def run_manifest(manifest, directory, since, printer=None):
    session = Mock()
    session.headers = {}
    manifest_url = BASE + 'manifest.json'
    first_url = BASE if directory else manifest_url
    answers = {manifest_url: response(manifest)}
    if directory:
        answers[BASE] = response('<a href="manifest.json">manifest</a>', html=True)
    for key in manifest:
        answers[BASE + key + '.json'] = response(EVENT)
    session.get.side_effect = lambda url, **kwargs: answers[url]
    session.__enter__ = Mock(return_value=session)
    session.__exit__ = Mock(return_value=False)
    printer = printer if printer is not None else Mock(ProcessMISP=Mock(return_value=True))
    count = AtomicInt()
    logger = Mock()
    logger.root.level = 30
    with patch.object(feeds.requests, 'Session', return_value=session):
        feeds.UpdateFromMISP({'url': first_url}, since, NOW, True, printer, logger, count, 0)
    requested = [call.args[0] for call in session.get.call_args_list]
    return requested, count.value(), logger


@pytest.fixture(params=['UTC0', 'EST5EDT,M3.2.0,M11.1.0', 'JST-9'])
def host_timezone(request):
    if not hasattr(time, 'tzset'):
        pytest.skip('Host timezone switching requires time.tzset')
    previous = os.environ.get('TZ')
    os.environ['TZ'] = request.param
    time.tzset()
    yield
    if previous is None:
        os.environ.pop('TZ', None)
    else:
        os.environ['TZ'] = previous
    time.tzset()


@pytest.mark.parametrize('directory', [False, True])
def test_cutoff_uses_utc_instants_and_includes_the_exact_boundary(host_timezone, directory):
    manifest = {
        name: {'timestamp': str(int((NOW + timedelta(seconds=offset)).timestamp()))}
        for name, offset in [('old', -1), ('boundary', 0), ('new', 1)]
    }
    requested, count, logger = run_manifest(manifest, directory, NOW)
    assert BASE + 'old.json' not in requested
    assert BASE + 'boundary.json' in requested
    assert BASE + 'new.json' in requested
    assert count == 2
    logger.warning.assert_not_called()


@pytest.mark.parametrize('directory', [False, True])
@pytest.mark.parametrize('since,expected', [(None, True), (NOW, True), (NOW + timedelta(seconds=1), False)])
def test_missing_timestamp_uses_the_supplied_run_time(host_timezone, directory, since, expected):
    requested, count, logger = run_manifest({'undated': {}}, directory, since)
    assert (BASE + 'undated.json' in requested) is expected
    assert count == int(expected)
    logger.warning.assert_not_called()


@pytest.mark.parametrize('directory', [False, True])
def test_bad_timestamp_does_not_hide_later_valid_entries(directory):
    manifest = {'broken': {'timestamp': 'bad'}, 'valid': {'timestamp': int(NOW.timestamp())}}
    requested, count, logger = run_manifest(manifest, directory, None)
    assert BASE + 'broken.json' not in requested
    assert BASE + 'valid.json' in requested
    assert count == 1
    assert logger.warning.call_count == 1


@pytest.mark.parametrize('directory', [False, True])
def test_undated_manifest_reaches_real_misp_parser_and_zeek_output(directory):
    output = io.StringIO()
    logger = Mock()
    logger.root.level = 30
    printer = feeds.FeedParserZeekPrinter(extended=False, notice=False, cif=False, file=output, logger=logger)
    _, count, update_logger = run_manifest({'undated': {}}, directory, None, printer)
    assert count == 1
    assert 'indicator.example\tIntel::DOMAIN\t' in output.getvalue()
    assert output.getvalue().startswith('#fields\t')
    logger.warning.assert_not_called()
    update_logger.warning.assert_not_called()
