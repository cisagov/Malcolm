"""Offline regression tests for the GitHub release and GHCR statistics CLI."""

from datetime import datetime, timezone
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from unittest.mock import Mock

import pytest


SCRIPT = Path(__file__).resolve().parents[2] / 'scripts/github-download-counts/github_download_counts.py'
SPEC = importlib.util.spec_from_file_location('malcolm_github_download_counts', SCRIPT)
stats = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(stats)


class FakeResponse:
    def __init__(self, data=None, html=None):
        self.content = json.dumps(data).encode() if data is not None else b''
        self.text = html if html is not None else ''

    def raise_for_status(self):
        return None


class FakeSession:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def get(self, url, **kwargs):
        self.calls.append((url, kwargs))
        return self.responses.pop(0)


def bounds():
    return datetime(2026, 10, 1, tzinfo=timezone.utc), datetime(2026, 10, 15, tzinfo=timezone.utc)


def test_entrypoint_exits_successfully_when_no_repositories(capsys):
    env = dict(os.environ, GITHUB_TOKEN='', GITHUB_OAUTH_TOKEN='', GITHUB_TOKEN_FILE='')
    result = subprocess.run(
        [sys.executable, str(SCRIPT), '-r'],
        cwd=SCRIPT.parents[2], env=env, capture_output=True, text=True, check=False,
    )
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == {}


@pytest.mark.parametrize('text', ['not-a-date', '???'])
def test_invalid_date_returns_clear_error(text):
    with pytest.raises(ValueError, match='date'):
        stats.parse_date_range(text, '2026-10-15')


def test_release_asset_matches_regex_and_inclusive_bounds():
    early, late = bounds()
    wanted = re.compile(r'.*\.tar\.gz$')
    rejected = re.compile(r'^no-match$')
    releases = [
        Mock(published_at=early, tag_name='v1'),
        Mock(published_at=late, tag_name='v2'),
        Mock(published_at=datetime(2026, 9, 30, tzinfo=timezone.utc), tag_name='v3'),
        Mock(published_at=late, tag_name='test'),
    ]
    for release in releases:
        release.assets.return_value = [
            Mock(name='release.tar.gz', download_count=3),
            Mock(name='release.zip', download_count=5),
        ]
        release.assets.return_value[0].name = 'release.tar.gz'
        release.assets.return_value[1].name = 'release.zip'
    repo = Mock(full_name='example/demo')
    repo.releases.return_value = releases
    result = {}
    stats.collect_release_downloads(
        repo, 'example', early, late,
        {'asset-regex': wanted, 'unused': rejected},
        {'release': re.compile('^v')}, result,
    )
    assert result == {'example/asset-regex': 6}


def test_paginated_api_stops_at_first_short_page():
    rows = [{'name': f'record-{i}'} for i in range(31)]
    session = FakeSession([FakeResponse(rows[:30]), FakeResponse(rows[30:])])
    assert list(stats.iter_api_pages(session, 'https://api.github.com/example')) == rows
    assert [call[1]['params']['page'] for call in session.calls] == [1, 2]
    assert all(call[1]['params']['per_page'] == 30 for call in session.calls)


def test_paginated_api_handles_unexpected_body_and_http_errors():
    session = FakeSession([FakeResponse({'error': 'permission denied'})])
    assert list(stats.iter_api_pages(session, 'https://api.github.com/example')) == []
    failed_session = Mock()
    failed_session.get.side_effect = ConnectionError('mocked offline failure')
    assert list(stats.iter_api_pages(failed_session, 'https://api.github.com/example')) == []


def test_ghcr_scrape_filters_tags_time_and_package_name():
    early, late = bounds()
    packages = [
        {'name': 'malcolm', 'owner': {'login': 'cisagov'}},
        {'name': 'other-image', 'owner': {'login': 'cisagov'}},
    ]
    versions = [
        {
            'name': 'sha-abc', 'html_url': 'https://github.com/orgs/cisagov/packages/container/malcolm/abc',
            'created_at': '2026-10-10T12:00:00Z',
            'metadata': {'container': {'tags': ['26.10', 'latest']}},
        },
        {
            'name': 'sha-old', 'html_url': 'https://github.com/orgs/cisagov/packages/container/malcolm/old',
            'created_at': '2026-09-01T12:00:00Z',
            'metadata': {'container': {'tags': ['26.09']}},
        },
    ]
    api = FakeSession([FakeResponse(packages), FakeResponse(versions)])
    html = FakeSession([FakeResponse(html='<span>Total downloads</span><span>1,234</span>')])
    counts = stats.collect_image_downloads(
        ['cisagov', 'cisagov'], api, html, {'malcolm': re.compile('^malcolm$')},
        {'version': re.compile('^26\\.10$')}, early, late,
    )
    assert counts == {'cisagov/malcolm:(26.10|latest)': 1234}
    assert len(api.calls) == 2  # do not request the same organisation twice
    assert len(html.calls) == 1


def test_fallback_version_name_when_no_tags():
    early, late = bounds()
    package = {'name': 'malcolm', 'owner': {'login': 'cisagov'}}
    version = {
        'name': 'sha-abc', 'html_url': 'https://github.com/example',
        'created_at': '2026-10-10T12:00:00Z', 'metadata': {'container': {'tags': []}},
    }
    api = FakeSession([FakeResponse([package]), FakeResponse([version])])
    html = FakeSession([FakeResponse(html='<span>Total downloads</span><span>7</span>')])
    counts = stats.collect_image_downloads(
        ['cisagov'], api, html, {'^m': re.compile('^m')}, {}, early, late
    )
    assert counts == {'cisagov/malcolm@sha-abc': 7}


def test_combined_statistics_are_json_serializable_and_totaled():
    results = stats.combine_statistics({'org/^a': 6, 'org/^b': 2}, {'org/img:v1': 7})
    assert json.loads(json.dumps(results)) == {
        'release_assets': {'org/^a': 6, 'org/^b': 2, 'total': 8},
        'image_pulls': {'org/img:v1': 7, 'total': 7},
    }
    assert stats.combine_statistics({}, {}) == {}


def test_cli_does_not_log_github_token(monkeypatch, capsys):
    monkeypatch.setattr(sys, 'argv', ['download-counts', '--token', 'example-private-token', '-r'])
    login = Mock(return_value=Mock())
    monkeypatch.setattr(stats.github, 'login', login)
    monkeypatch.setattr(stats.mmguero, 'set_logging', lambda *a, **kw: 0)
    messages = []
    monkeypatch.setattr(stats.logging, 'info', lambda value, *args: messages.append(str(value)))
    monkeypatch.setattr(stats.requests, 'Session', lambda: Mock(headers={}))
    assert stats.main() == 0
    assert 'example-private-token' not in '\n'.join(messages)
    login.assert_called_once_with(token='example-private-token')
    assert json.loads(capsys.readouterr().out) == {}
