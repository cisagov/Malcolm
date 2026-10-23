"""Retention candidates must contribute their full byte sizes to the budget."""

from copy import deepcopy
import json
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
import requests

import opensearch_index_size_prune as pruning


def options(primary=False, names=False, dryrun=False, index=None, limit='1', node=''):
    return SimpleNamespace(
        index=index or ['capture-*'],
        opensearch_url='https://search.example',
        primary_totals=primary,
        name_sorted=names,
        dryrun=dryrun,
        limit=limit,
        node=node,
    )


def response(data):
    result = requests.Response()
    result.status_code = 200
    result._content = json.dumps(data).encode()
    return result


def catalog(sizes):
    # Creation dates run opposite to names so the two sort modes choose different prefixes.
    return [
        {
            'i': f'capture-{i:02d}',
            'id': str(i),
            'creation.date': str(900 - i),
            'bytes': size,
            'primary_bytes': size // 2,
        }
        for i, size in enumerate(sizes)
    ]


def ordered(rows, names):
    return sorted(rows, key=lambda row: row['i'] if names else row['creation.date'])


def expected_prefix(rows, budget_bytes, byte_key):
    remaining = budget_bytes
    expected = []
    for row in rows:
        if remaining <= 0:
            break
        expected.append(row['i'])
        remaining -= row[byte_key]
    return expected


def human(size):
    # Mimic OpenSearch's default cat output, which labels 1024-based values as "kb".
    return f'{size / 1024:.1f}kb'


def session_for(rows):
    session = Mock()

    def get(url, params=None):
        assert '/_cat/indices/' in url
        exact = params.get('bytes') == 'b'
        return response(
            [
                {
                    'i': row['i'],
                    'id': row['id'],
                    'creation.date': row['creation.date'],
                    'store.size': str(row['bytes']) if exact else human(row['bytes']),
                    'pri.store.size': str(row['primary_bytes']) if exact else human(row['primary_bytes']),
                }
                for row in rows
            ]
        )

    session.get.side_effect = get
    session.delete.return_value = response({'acknowledged': True})
    return session


def stats_session(rows):
    session = session_for(rows)
    cat_get = session.get.side_effect

    def get(url, params=None):
        if url.endswith('/_stats/store'):
            return response(
                {
                    'indices': {
                        row['i']: {
                            'primaries': {'store': {'size_in_bytes': row['primary_bytes']}},
                            'total': {'store': {'size_in_bytes': row['bytes']}},
                        }
                        for row in rows
                    },
                }
            )
        if url == 'https://search.example':
            return response({'version': {'number': '3.2.0'}})
        return cat_get(url, params)

    session.get.side_effect = get
    return session


def run_main(monkeypatch, args, session):
    monkeypatch.setattr(pruning, 'parse_args', lambda: args)
    monkeypatch.setattr(pruning, 'setup_environment', lambda value: (value, session))
    pruning.main()
    return [call.args[0].rsplit('/', 1)[-1] for call in session.delete.call_args_list]


@pytest.mark.parametrize(
    'sizes,budget',
    [
        ([600000] * 4, 1),
        ([1500000] * 4, 3),
        ([250000] * 8, 1),
        ([0, 600000, 600000, 600000], 1),
        ([499999, 500001, 1000000], 1),
        ([333333, 333333, 333334, 500000], 1),
        ([333333, 333333, 333333, 500000], 1),
    ],
)
@pytest.mark.parametrize('primary', [False, True])
@pytest.mark.parametrize('names', [False, True])
def test_selects_only_the_prefix_needed_for_the_existing_budget(sizes, budget, primary, names):
    rows = catalog(sizes)
    original = deepcopy(rows)
    byte_key = 'primary_bytes' if primary else 'bytes'
    expected = expected_prefix(ordered(rows, names), budget * 1000000, byte_key)
    session = session_for(list(reversed(rows)))
    selected = pruning.get_indices_for_deletion(options(primary, names), session, 10, 10 - budget)
    assert [row['i'] for row in selected] == expected
    assert rows == original
    assert session.get.call_args.kwargs['params']['bytes'] == 'b'
    session.delete.assert_not_called()


def test_sort_modes_choose_different_indices():
    rows = catalog([600000] * 4)
    by_name = pruning.get_indices_for_deletion(options(names=True), session_for(rows), 10, 9)
    by_date = pruning.get_indices_for_deletion(options(names=False), session_for(rows), 10, 9)
    assert [row['i'] for row in by_name] == ['capture-00', 'capture-01']
    assert [row['i'] for row in by_date] == ['capture-03', 'capture-02']


def test_overlapping_patterns_count_each_candidate_once():
    session = session_for(catalog([600000] * 4))
    args = options(index=['capture-*', 'capture-0*'])
    selected = pruning.get_indices_for_deletion(args, session, 10, 9)
    assert session.get.call_count == 2
    assert [row['i'] for row in selected] == ['capture-03', 'capture-02']


@pytest.mark.parametrize('budget', [0, -1])
def test_no_candidates_are_selected_when_no_bytes_need_freeing(budget):
    session = session_for(catalog([600000] * 4))
    assert pruning.get_indices_for_deletion(options(), session, 10, 10 - budget) == []
    session.delete.assert_not_called()


@pytest.mark.parametrize('dryrun', [False, True])
def test_reported_totals_use_exact_bytes_and_dryrun_is_preserved(dryrun, capsys):
    session = session_for(catalog([600000, 600000]))
    args = options(dryrun=dryrun)
    selected = pruning.get_indices_for_deletion(args, session, 2, 1)
    pruning.delete_indices(args, session, selected)
    output = capsys.readouterr().out
    assert '1.2 MB' in output
    assert '2 indices' in output
    assert '(capture-01 to capture-00 ordered by creation date)' in output
    assert session.delete.call_count == (0 if dryrun else 2)
    delete_lines = [line for line in output.splitlines() if line.startswith('DELETE ')]
    assert delete_lines == ([] if dryrun else ['DELETE capture-01 (600 KB): ok', 'DELETE capture-00 (600 KB): ok'])


@pytest.mark.parametrize('dryrun', [False, True])
@pytest.mark.parametrize(
    'primary,expected',
    [
        (False, ['capture-03', 'capture-02', 'capture-01']),
        (True, ['capture-03', 'capture-02']),
    ],
)
def test_main_honors_the_megabyte_budget_for_totals_and_primaries(monkeypatch, dryrun, primary, expected):
    # Totals are 4.8 MB (3 MB over), primaries are 2.4 MB (1 MB over).
    rows = catalog([1200000] * 4)
    args = options(primary=primary, dryrun=dryrun)
    assert run_main(monkeypatch, args, stats_session(rows)) == ([] if dryrun else expected)


def test_main_does_nothing_under_the_limit(monkeypatch, capsys):
    session = stats_session(catalog([400000] * 2))
    assert run_main(monkeypatch, options(), session) == []
    assert 'Nothing to do' in capsys.readouterr().out
    assert not any('/_cat/indices/' in call.args[0] for call in session.get.call_args_list)


@pytest.mark.parametrize(
    'limit,expected',
    [
        ('100', 100),
        ('512mb', 512),
        ('100gb', 100000),
        ('100g', 100000),
        ('1.5tb', 1500000),
    ],
)
def test_size_limits_parse_as_decimal_megabytes(limit, expected):
    session = Mock()
    assert pruning.parse_limit_megabytes(options(limit=limit), session) == expected
    session.get.assert_not_called()


@pytest.mark.parametrize('limit', ['', '0%', '100%', '-5%', 'lots'])
def test_invalid_limits_are_rejected(limit):
    with pytest.raises(ValueError):
        pruning.parse_limit_megabytes(options(limit=limit), Mock())


def allocation_session(entries):
    session = Mock()
    session.get.return_value = response(entries)
    return session


@pytest.mark.parametrize('node', ['', 'node1'])
def test_percent_limit_uses_exact_disk_bytes(node):
    session = allocation_session(
        [
            {'node': 'node1', 'disk.total': '1099511627776', 'disk.used': '549755813888'},
            {'node': 'UNASSIGNED', 'shards': '2'},
        ]
    )
    assert pruning.parse_limit_megabytes(options(limit='25%', node=node), session) == 274877
    url = session.get.call_args.args[0]
    assert url.split('?')[0].endswith('/_cat/allocation' + (f'/{node}' if node else ''))
    assert session.get.call_args.kwargs['params']['bytes'] == 'b'


@pytest.mark.parametrize(
    'entries',
    [
        [{'node': 'node1', 'disk.total': '1000000000'}, {'node': 'node2', 'disk.total': '1000000000'}],
        [{'node': 'node1'}],
        [{'node': 'UNASSIGNED', 'shards': '2'}],
    ],
)
def test_percent_limit_requires_exactly_one_node_with_disk_total(entries):
    with pytest.raises(RuntimeError):
        pruning.parse_limit_megabytes(options(limit='25%'), allocation_session(entries))
