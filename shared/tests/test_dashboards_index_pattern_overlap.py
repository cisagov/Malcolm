"""Overlapping selectors must count and prune each concrete index only once."""

from copy import deepcopy
import json
from types import SimpleNamespace
from unittest.mock import Mock, call, patch

import pytest
import requests

import opensearch_index_size_prune as prune

CAT = [
    {'i': 'logs-old', 'creation.date': '1000', 'store.size': '60mb', 'pri.store.size': '30mb'},
    {'i': 'logs-new', 'creation.date': '2000', 'store.size': '60mb', 'pri.store.size': '30mb'},
]


def args_for(patterns, primary=False, limit='140', dryrun=False):
    return SimpleNamespace(
        index=patterns,
        primary_totals=primary,
        name_sorted=False,
        opensearch_url='https://search.example',
        limit=limit,
        dryrun=dryrun,
    )


def response(data):
    result = requests.Response()
    result.status_code = 200
    result._content = json.dumps(data).encode()
    return result


def session_for():
    def get(url, **kwargs):
        del kwargs
        if url == 'https://search.example':
            return response({'version': {'number': '3.2.0'}})
        selector = url.split('/')[-1] if '/_cat/' in url else url.split('/')[-3]
        rows = CAT if selector == 'logs-*' else [row for row in CAT if row['i'] == selector]
        if '/_cat/' in url:
            return response(rows)
        indices = {
            row['i']: {
                'primaries': {'store': {'size_in_bytes': 30_000_000}},
                'total': {'store': {'size_in_bytes': 60_000_000}},
            }
            for row in rows
        }
        return response(
            {
                'indices': indices,
                '_all': {
                    'primaries': {'store': {'size_in_bytes': len(rows) * 30_000_000}},
                    'total': {'store': {'size_in_bytes': len(rows) * 60_000_000}},
                },
            }
        )

    return Mock(get=Mock(side_effect=get), delete=Mock(return_value=response({'acknowledged': True})))


@pytest.mark.parametrize('patterns', [['logs-*', 'logs-old'], ['logs-old', 'logs-*'], ['logs-*', 'logs-*']])
@pytest.mark.parametrize('primary', [False, True])
def test_total_size_and_count_describe_unique_indices(patterns, primary):
    original = deepcopy(patterns)
    assert prune.get_total_index_size(args_for(patterns, primary), session_for()) == (60 if primary else 120, 2)
    assert patterns == original


@pytest.mark.parametrize('primary', [False, True])
@pytest.mark.parametrize('name_sorted', [False, True])
def test_prune_candidates_free_distinct_indices(primary, name_sorted):
    args = args_for(['logs-*', 'logs-old'], primary)
    args.name_sorted = name_sorted
    selected = prune.get_indices_for_deletion(args, session_for(), 60 if primary else 120, 20 if primary else 50)
    expected = ['logs-new', 'logs-old'] if name_sorted else ['logs-old', 'logs-new']
    assert [row['i'] for row in selected] == expected


@pytest.mark.parametrize('dryrun', [False, True])
def test_main_does_not_prune_when_unique_usage_is_below_limit(dryrun, capsys):
    args = args_for(['logs-*', 'logs-old'], dryrun=dryrun)
    session = session_for()
    with patch.object(prune, 'parse_args', return_value=args), patch.object(
        prune, 'setup_environment', return_value=(args, session)
    ):
        prune.main()
    session.delete.assert_not_called()
    assert 'Nothing to do' in capsys.readouterr().out


@pytest.mark.parametrize('dryrun', [False, True])
def test_main_removes_only_the_required_unique_index(dryrun):
    args = args_for(['logs-*', 'logs-old'], limit='70', dryrun=dryrun)
    session = session_for()
    with patch.object(prune, 'parse_args', return_value=args), patch.object(
        prune, 'setup_environment', return_value=(args, session)
    ):
        prune.main()
    assert session.delete.call_args_list == ([] if dryrun else [call('https://search.example/logs-old')])


def test_nonoverlapping_patterns_and_empty_results_are_unchanged():
    session = session_for()
    assert prune.get_total_index_size(args_for(['logs-old', 'logs-new']), session) == (120, 2)
    assert prune.get_total_index_size(args_for(['missing']), session) == (0, 0)
    assert prune.get_indices_for_deletion(args_for(['missing']), session, 10, 0) == []
