"""API query instants must follow UTC defaults rather than the server timezone."""

from collections import defaultdict
from datetime import datetime, timezone
import os
from pathlib import Path
import sys
import time
from unittest.mock import Mock, patch

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / 'scripts'), str(ROOT / 'api')]
import malcolm_utils

# Client construction is local; credential files and network transport are not used.
with patch.dict(
    os.environ, {'OPENSEARCH_URL': 'https://search.example:9200', 'OPENSEARCH_PRIMARY': 'opensearch-local'}
), patch.object(malcolm_utils, 'ParseCurlFile', return_value=defaultdict(lambda: None)), patch(
    'socket.create_connection', side_effect=AssertionError('Network access in offline tests')
):
    import project as api

START = datetime(2026, 1, 2, 12, tzinfo=timezone.utc)
END = datetime(2026, 1, 2, 13, tzinfo=timezone.utc)


@pytest.fixture(params=['UTC', 'America/New_York', 'Asia/Tokyo'])
def host_timezone(request):
    if not hasattr(time, 'tzset'):
        pytest.skip('Requires time.tzset')
    original = os.environ.get('TZ')
    os.environ['TZ'] = request.param
    time.tzset()
    try:
        yield
    finally:
        if original is None:
            os.environ.pop('TZ', None)
        else:
            os.environ['TZ'] = original
        time.tzset()


@pytest.mark.parametrize('style', ['epoch', 'naive', 'utc', 'offset'])
def test_equivalent_query_times_produce_the_same_instants(host_timezone, style):
    values = {
        'epoch': (str(int(START.timestamp())), str(int(END.timestamp()))),
        'naive': ('2026-01-02 12:00:00', '2026-01-02 13:00:00'),
        'utc': ('2026-01-02T12:00:00Z', '2026-01-02T13:00:00Z'),
        'offset': ('2026-01-02T17:30:00+05:30', '2026-01-02T18:30:00+05:30'),
    }
    start, end = values[style]
    result = api.gettimes({'from': start, 'to': end})
    assert [value.timestamp() for value in result] == [START.timestamp(), END.timestamp()]
    query = api.SearchClass(index='offline')
    low, high, filtered = api.filtertime(query, {'from': start, 'to': end})
    assert (low, high) == (int(START.timestamp() * 1000), int(END.timestamp() * 1000))
    bounds = filtered.to_dict()['query']['bool']['filter'][0]['range'][api.timefield_from_args({})]
    assert bounds == {'gte': low, 'lte': high, 'format': 'epoch_millis'}


def test_absent_and_invalid_inputs_keep_existing_none_behavior():
    assert api.gettimes({}) == (None, None)
    assert api.gettimes({'from': '', 'to': 'not-a-date-value'}) == (None, None)


def test_custom_naive_defaults_are_utc(host_timezone):
    low, high, query = api.filtertime(None, {}, default_from='2026-01-02 12:00:00', default_to='2026-01-02 13:00:00')
    assert (low, high, query) == (int(START.timestamp() * 1000), int(END.timestamp() * 1000), None)


def test_relative_times_remain_relative_to_the_current_instant(host_timezone):
    before = time.time()
    low, high, _ = api.filtertime(None, {'from': '2 hours ago', 'to': 'now'})
    after = time.time()
    assert before - 7200 - 1 <= low / 1000 <= after - 7200 + 1
    assert before - 1 <= high / 1000 <= after + 1


@pytest.mark.parametrize('method', ['get', 'post'])
def test_public_aggregation_uses_the_correct_range(host_timezone, method):
    response_data = {
        'hits': {'hits': [], 'total': {'value': 0, 'relation': 'eq'}},
        'aggregations': {'event.provider': {'buckets': []}},
    }
    values = {'from': str(int(START.timestamp())), 'to': str(int(END.timestamp()))}
    search = Mock(return_value=response_data)
    with patch.object(api.databaseClient, 'search', new=search), patch.object(
        api.databaseClient.indices, 'get_field_mapping', return_value={}
    ):
        with api.app.test_client() as client:
            url = '/' + api.app.config['MALCOLM_API_PREFIX'].strip('/') + '/agg'
            response = getattr(client, method)(
                url, **({'query_string': values} if method == 'get' else {'json': values})
            )
    assert response.status_code == 200, response.data
    assert response.json['range'] == [int(START.timestamp()), int(END.timestamp())]
    search.assert_called_once()
    bounds = search.call_args.kwargs['body']['query']['bool']['filter'][0]['range'][api.timefield_from_args({})]
    assert bounds['gte'] == int(START.timestamp() * 1000)
    assert bounds['lte'] == int(END.timestamp() * 1000)
