"""Retention candidates must contribute their full byte sizes to the budget."""

from copy import deepcopy
import json
from pathlib import Path
import sys
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
import requests

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts'))
sys.path.insert(0, str(ROOT / 'dashboards' / 'scripts'))
import opensearch_index_size_prune as pruning  # noqa: E402 - standalone sources require their checkout paths


def options(primary=False, names=False, dryrun=False):
    return SimpleNamespace(
        index=['capture-*'],
        opensearch_url='https://search.example',
        primary_totals=primary,
        name_sorted=names,
        dryrun=dryrun,
        limit='1',
        node='',
    )


def response(data):
    result = requests.Response()
    result.status_code = 200
    result._content = json.dumps(data).encode()
    return result


def catalog(sizes):
    return [
        {
            'i': f'capture-{i:02d}',
            'id': str(i),
            'creation.date': str(100 + i),
            'bytes': size,
            'primary_bytes': size // 2,
        }
        for i, size in enumerate(sizes)
    ]


def session_for(rows):
    session = Mock()

    def get(url, params=None):
        assert '/_cat/indices/' in url
        return response(
            [
                {
                    'i': row['i'],
                    'id': row['id'],
                    'creation.date': row['creation.date'],
                    'store.size': str(row['bytes']) if params.get('bytes') == 'b' else f"{row['bytes']/1000}kb",
                    'pri.store.size': (
                        str(row['primary_bytes']) if params.get('bytes') == 'b' else f"{row['primary_bytes']/1000}kb"
                    ),
                }
                for row in rows
            ]
        )

    session.get.side_effect = get
    session.delete.return_value = response({'acknowledged': True})
    return session


@pytest.mark.parametrize(
    'sizes,budget',
    [
        ([600000] * 4, 1),
        ([1500000] * 4, 3),
        ([250000] * 8, 1),
        ([0, 600000, 600000, 600000], 1),
        ([499999, 500001, 1000000], 1),
    ],
)
@pytest.mark.parametrize('primary', [False, True])
@pytest.mark.parametrize('names', [False, True])
def test_selects_only_the_prefix_needed_for_the_existing_budget(sizes, budget, primary, names):
    rows = catalog(sizes)
    original = deepcopy(rows)
    byte_key = 'primary_bytes' if primary else 'bytes'
    remaining = budget * 1000000
    expected = []
    for row in rows:
        if remaining <= 0:
            break
        expected.append(row['i'])
        remaining -= row[byte_key]
    session = session_for(list(reversed(rows)))
    selected = pruning.get_indices_for_deletion(options(primary, names), session, 10, 10 - budget)
    assert [row['i'] for row in selected] == expected
    assert rows == original
    assert session.get.call_args.kwargs['params']['bytes'] == 'b'
    session.delete.assert_not_called()


@pytest.mark.parametrize('budget', [0, -1])
def test_no_candidates_are_selected_when_no_bytes_need_freeing(budget):
    session = session_for(catalog([600000] * 4))
    assert pruning.get_indices_for_deletion(options(), session, 10, 10 - budget) == []
    session.delete.assert_not_called()


@pytest.mark.parametrize('dryrun', [False, True])
def test_reported_total_uses_combined_bytes_and_dryrun_is_preserved(dryrun, capsys):
    session = session_for(catalog([600000, 600000]))
    args = options(dryrun=dryrun)
    selected = pruning.get_indices_for_deletion(args, session, 2, 1)
    pruning.delete_indices(args, session, selected)
    output = capsys.readouterr().out
    assert '1.2 MB' in output
    assert '2 indices' in output
    assert session.delete.call_count == (0 if dryrun else 2)


@pytest.mark.parametrize('dryrun', [False, True])
def test_main_honors_the_current_megabyte_budget_without_deleting_every_small_index(monkeypatch, dryrun):
    rows = catalog([600000] * 4)
    session = session_for(rows)
    original_get = session.get.side_effect

    def get(url, params=None):
        if url.endswith('/_stats/store'):
            return response(
                {
                    '_all': {'total': {'store': {'size_in_bytes': 2400000}}},
                    'indices': {row['i']: {'total': {'store': {'size_in_bytes': row['bytes']}}} for row in rows},
                }
            )
        if url == 'https://search.example':
            return response({'version': {'number': '3.2.0'}})
        return original_get(url, params)

    session.get.side_effect = get
    args = options(dryrun=dryrun)
    monkeypatch.setattr(pruning, 'parse_args', lambda: args)
    monkeypatch.setattr(pruning, 'setup_environment', lambda value: (value, session))
    pruning.main()
    assert [call.args[0].rsplit('/', 1)[-1] for call in session.delete.call_args_list] == (
        [] if dryrun else ['capture-00', 'capture-01']
    )
