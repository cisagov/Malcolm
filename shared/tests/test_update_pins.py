# Copyright (c) 2026 Battelle Energy Alliance, LLC.  All rights reserved.

"""Tests for scripts/update_pins.py against a small synthetic source tree, with no network access."""

import hashlib
import io
import sys
import textwrap
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'scripts'))

from pinning import cli  # noqa: E402
from pinning.base import Context  # noqa: E402
from pinning.catalog import Catalog  # noqa: E402
from pinning.checkers import (
    Binaries,
    DockerImages,
    GithubActions,
    Other,
    PythonRequirements,
    SourcePins,
    ZeekPackages,
)  # noqa: E402
from pinning.core import (  # noqa: E402
    SCOPE_ANY,
    SCOPE_MAJOR,
    SCOPE_MINOR,
    Avail,
    Candidate,
    Edit,
    FileIndex,
    PinError,
    apply_edits,
    find_assignments,
    pick_candidates,
)
from pinning.checkers.docker_images import parse_ref  # noqa: E402
from pinning.net import Net  # noqa: E402
from pinning.ui import Chooser, Style  # noqa: E402


def fake_sha(*parts, n=40):
    return hashlib.sha256('|'.join(map(str, parts)).encode()).hexdigest()[:n]


OLD_CHECKOUT = 'de0fac2e4500dabe0009e67214ff5f5447ce83dd'
OLD_LDAP = 'b5e8bce7c102588b033cf69eb349fd34bb9cd43c'
OLD_HTTP = '4ab4269cf442ba52507aa2c718f606054452fcad'
OLD_DIGEST = 'sha256:' + 'c' * 64


class StubNet(Net):
    """Deterministic upstream: every lookup is answered from the tables below."""

    TAGS = {
        'https://github.com/actions/checkout': ['v6.0.2', 'v6.0.3', 'v6.1.0', 'v7.0.0', 'v6'],
        'https://github.com/ledgetech/lua-resty-http': ['v0.17.1', 'v0.17.2', 'v0.18.0'],
        'https://github.com/elastic/ecs': ['v9.5.0', 'v9.5.1', 'v9.6.0'],
        'https://github.com/zeek/spicy-tftp': ['v0.0.1', 'v0.0.2'],
        'https://github.com/cisagov/icsnpp-dnp3': [],
        'https://github.com/netbox-community/netbox-topology-views.git': ['v4.5.1', 'v4.5.2'],
    }
    TAGS['https://github.com/actions/checkout'] = TAGS['https://github.com/actions/checkout']

    def __init__(self):
        super().__init__()
        self.downloads = []

    def ls_remote(self, url):
        refs = {'HEAD': fake_sha(url, 'HEAD'), 'refs/heads/main': fake_sha(url, 'main')}
        for t in self.TAGS.get(url, []):
            refs[f'refs/tags/{t}'] = fake_sha(url, t)
        if url == 'https://github.com/actions/checkout':
            refs['refs/tags/v6.0.2'] = OLD_CHECKOUT
        if url == 'https://github.com/mmguero-dev/nginx-auth-ldap':
            refs['HEAD'] = OLD_LDAP  # already current
        return refs

    def gh_releases(self, repo, pages=3):
        if repo == 'krallin/tini':
            return [
                {'tag_name': 'v0.19.0', 'prerelease': False},
                {'tag_name': 'v0.20.0', 'prerelease': False},
                {'tag_name': 'v0.21.0-rc1', 'prerelease': True},
                {'tag_name': 'v0.21.0', 'prerelease': True},
            ]
        return [{'tag_name': t, 'prerelease': False} for t in ('v4.54.3', 'v4.54.4', 'v4.55.0', 'v5.0.0')]

    def gh_latest_release_tag(self, repo):
        return 'v0.0.2' if repo == 'zeek/spicy-tftp' else None

    def gh_asset_sha256(self, repo, tag, asset):
        return fake_sha(repo, tag, asset, n=64)

    def url_sha256(self, url):
        self.downloads.append(url)
        return fake_sha(url, n=64)

    def registry_tags(self, registry, repo):
        return {
            'library/debian': ['13-slim', '14-slim', '13.1-slim', 'latest'],
            'zeek/zeek': ['9.0.1', '9.0.2', '9.1.0', '9.0.1-arm64', 'lts'],
        }.get(repo, [])

    def registry_digest(self, registry, repo, tag):
        return 'sha256:' + fake_sha(registry, repo, tag, n=64)

    def npm(self, name):
        return {'versions': {'6.3.0': {}, '6.3.1': {}, '7.0.0': {}, '7.1.0': {'deprecated': 'broken'}}}

    def pypi(self, name):
        return {
            'releases': {
                '2.33.1': [{}],
                '2.33.2': [{'requires_python': '>=3.9'}],
                '2.34.0': [{}],
                '3.0.0rc1': [{}],
                '2.35.0': [{'yanked': True}],
            },
            'info': {'project_urls': {'Changelog': f'https://example.com/{name}/HISTORY'}},
        }


FILES = {
    'Dockerfiles/zeek.Dockerfile': """\
        FROM zeek/zeek:9.0.1
        COPY --from=ghcr.io/mmguero-dev/gostatic:latest@{OLD_DIGEST} /goStatic /usr/bin/goStatic
        ENV YQ_VERSION="4.54.3"
        ENV TINI_VERSION=v0.19.0
        RUN pip install --no-cache-dir flake8==7.2.0 && \\
            npm install redis@6.3.0
        """,
    'Dockerfiles/nginx.Dockerfile': """\
        FROM debian:13-slim AS builder
        FROM builder
        ARG NGINX_AUTH_LDAP_REVISION={OLD_LDAP}
        # pin ledgetech/lua-resty-http v0.17.1
        ARG LUA_RESTY_HTTP_REVISION={OLD_HTTP}
        ADD --checksum=sha256:{AAA} https://codeload.github.com/ledgetech/lua-resty-http/tar.gz/$LUA_RESTY_HTTP_REVISION /lua-src/http.tar.gz
        ADD --checksum=sha256:{BBB} https://codeload.github.com/mmguero-dev/nginx-auth-ldap/tar.gz/$NGINX_AUTH_LDAP_REVISION /ldap.tar.gz
        ENV ECS_VERSION="9.5.0"
        ENV ECS_COMMIT="{ECS_OLD}"
        ENV ECS_SHA256="{CCC}"
        ENV NETBOX_TOPOLOGY_VERSION="4.5.1"
        """,
    'scripts/hook.sh': """\
        YQ_VERSION="4.54.3"
        """,
    '.github/workflows/build.yml': """\
        jobs:
          docker:
            steps:
              - uses: actions/checkout@{OLD_CHECKOUT} # v6.0.2
              - uses: ./.github/workflows/local.yml
        """,
    'shared/pins/binaries.sha256': """\
        # SHA-256 checksums for pinned release assets; filenames are artifact keys.
        {AAA}  tini_v0.19.0_linux_amd64
        {BBB}  tini_v0.19.0_linux_arm64
        {CCC}  yq_4.54.3_linux_amd64
        {AAA}  yq_4.54.3_linux_arm64
        """,
    'api/requirements.txt': """\
        requests==2.33.1
        psutil>=2.0   # floor only
        colorama>=2.34.0
        """,
    'filescan/requirements.txt': """\
        requests==2.33.1
        """,
    'netbox/requirements.txt': """\
        git+https://github.com/netbox-community/netbox-topology-views@v${{NETBOX_TOPOLOGY_VERSION}}
        """,
    'zeek/zeek-packages.list': """\
        https://github.com/zeek/spicy-tftp
        https://github.com/cisagov/icsnpp-dnp3|main
        """,
    'zeek/zeek-packages.lock': """\
        # Generated by scripts/zeek_packages_lock_refresh.sh from zeek/zeek-packages.list; do not edit by hand.
        # Format: URL|commit|resolved ref|environment variables|method
        https://github.com/zeek/spicy-tftp|{OLD_TFTP}|v0.0.1||
        https://github.com/cisagov/icsnpp-dnp3|{OLD_DNP3}|main||
        https://github.com/example/gone|{OLD_GONE}|HEAD||
        """,
    'shared/pins/pins.yml': """\
        docker_images:
          zeek/zeek:
            release_notes: https://github.com/zeek/zeek/releases/tag/v{{version}}
        binaries:
          yq:
            version_var: YQ_VERSION
            repo: mikefarah/yq
            key: yq_{{version}}_linux_{{arch}}
            asset: yq_linux_{{arch}}
          tini:
            version_var: TINI_VERSION
            var_format: v{{version}}
            repo: krallin/tini
            key: tini_v{{version}}_linux_{{arch}}
            asset: tini-{{arch}}
        source_pins:
          ecs:
            repo: elastic/ecs
            ref: v9.5.0
            commit_var: ECS_COMMIT
            version_var: ECS_VERSION
            sha256_var: ECS_SHA256
          lua-resty-http:
            repo: ledgetech/lua-resty-http
            ref: v0.17.1
            commit_var: LUA_RESTY_HTTP_REVISION
            add_checksum: true
            hold: bump on its own commit
          nginx-auth-ldap:
            repo: mmguero-dev/nginx-auth-ldap
            track: branch
            commit_var: NGINX_AUTH_LDAP_REVISION
            add_checksum: true
        python:
          netbox-topology-views: {{group: netbox}}
        """,
}

VALUES = {
    'OLD_DIGEST': OLD_DIGEST,
    'OLD_LDAP': OLD_LDAP,
    'OLD_HTTP': OLD_HTTP,
    'OLD_CHECKOUT': OLD_CHECKOUT,
    'AAA': 'a' * 64,
    'BBB': 'b' * 64,
    'CCC': 'c' * 64,
    'ECS_OLD': fake_sha('https://github.com/elastic/ecs', 'v9.5.0'),
    'OLD_TFTP': fake_sha('old', 'tftp'),
    'OLD_DNP3': fake_sha('https://github.com/cisagov/icsnpp-dnp3', 'main'),
    'OLD_GONE': fake_sha('old', 'gone'),
}


@pytest.fixture
def tree(tmp_path):
    for rel, body in FILES.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(textwrap.dedent(body).format(**VALUES))
    return tmp_path


def make_ctx(root, net=None):
    catalog = Catalog(root / 'shared' / 'pins' / 'pins.yml', root)
    return Context(
        root=root, catalog=catalog, net=net or StubNet(), index=FileIndex(root, catalog.exclude_dirs), jobs=2
    )


def run(checker_cls, root, net=None):
    ctx = make_ctx(root, net)
    checker = checker_cls(ctx)
    items, errors = checker.run()
    assert not errors
    return checker, {i.name: i for i in items}


def edit_and_apply(checker, item, cand):
    edits = checker.finalize([(item, cand)])
    apply_edits(checker.ctx.root, edits)
    return edits


###################################################################################################


def test_pick_candidates_scopes():
    avail = [
        Avail(v, tuple(map(int, v.split('.'))), tuple(map(int, v.split('.'))))
        for v in ('1.2.3', '1.2.9', '1.5.0', '2.0.0', '0.9.0')
    ]
    cands = pick_candidates((1, 2, 3), (1, 2, 3), avail, lambda a: Candidate(a.version))
    assert [(c.version, c.scope) for c in cands] == [
        ('2.0.0', SCOPE_ANY),
        ('1.5.0', SCOPE_MAJOR),
        ('1.2.9', SCOPE_MINOR),
    ]
    assert pick_candidates((2, 0, 0), (2, 0, 0), avail, lambda a: Candidate(a.version)) == []


def test_assignments_skip_reexports(tree):
    (tree / 'x.Dockerfile').write_text('ARG FOO_VERSION=1.2.3\nENV FOO_VERSION=$FOO_VERSION\nRUN echo ${FOO_VERSION}\n')
    (tree / 'Makefile').write_text('FOO_VERSION ?= 1.2.3\n')
    found = find_assignments(FileIndex(tree, []), 'FOO_VERSION')
    assert sorted((rel, m.group('val')) for rel, m in found) == [('Makefile', '1.2.3'), ('x.Dockerfile', '1.2.3')]


def test_parse_ref():
    assert parse_ref('debian:13-slim')[1:] == ('docker.io', 'library/debian', '13-slim', None)
    assert parse_ref('ghcr.io/a/b:latest@sha256:' + 'f' * 64)[1:4] == ('ghcr.io', 'a/b', 'latest')
    assert parse_ref('localhost:5000/x/y:1.0')[1:4] == ('localhost:5000', 'x/y', '1.0')


def test_docker_images(tree):
    checker, items = run(DockerImages, tree)
    assert set(items) == {'zeek/zeek', 'ghcr.io/mmguero-dev/gostatic', 'debian'}  # 'builder' is a stage
    zeek = items['zeek/zeek']
    assert [c.version for c in zeek.candidates] == ['9.1.0', '9.0.2']  # 9.0.1-arm64 has another shape
    assert zeek.candidates[0].links[0][1] == 'https://github.com/zeek/zeek/releases/tag/v9.1.0'
    assert [c.version for c in items['debian'].candidates] == ['14-slim']
    gostatic = items['ghcr.io/mmguero-dev/gostatic']
    assert gostatic.data['mode'] == 'digest' and len(gostatic.candidates) == 1
    edit_and_apply(checker, gostatic, gostatic.candidates[0])
    text = (tree / 'Dockerfiles/zeek.Dockerfile').read_text()
    assert 'gostatic:latest@' + StubNet().registry_digest('ghcr.io', 'mmguero-dev/gostatic', 'latest') in text


def test_github_actions(tree):
    checker, items = run(GithubActions, tree)
    item = items['actions/checkout']
    assert [c.version for c in item.candidates] == ['v7.0.0', 'v6.1.0', 'v6.0.3']
    edit_and_apply(checker, item, item.candidates[2])
    text = (tree / '.github/workflows/build.yml').read_text()
    new_sha = fake_sha('https://github.com/actions/checkout', 'v6.0.3')
    assert f'actions/checkout@{new_sha} # v6.0.3' in text
    assert './.github/workflows/local.yml' in text


def test_binaries_update_manifest_and_vars(tree):
    checker, items = run(Binaries, tree)
    yq, tini = items['yq'], items['tini']
    assert yq.current == '4.54.3' and len(yq.locations) == 2
    assert [c.version for c in yq.candidates] == ['5.0.0', '4.55.0', '4.54.4']
    assert [c.version for c in tini.candidates] == ['0.20.0']  # the rc is a prerelease
    edits = checker.edits(yq, yq.candidates[1]) + checker.edits(tini, tini.candidates[0])
    apply_edits(tree, edits)
    manifest = (tree / 'shared/pins/binaries.sha256').read_text().splitlines()
    assert manifest[0].startswith('# SHA-256')
    keys = [l.split()[1] for l in manifest[1:]]
    assert keys == [
        'tini_v0.20.0_linux_amd64',
        'tini_v0.20.0_linux_arm64',
        'yq_4.55.0_linux_amd64',
        'yq_4.55.0_linux_arm64',
    ]
    assert manifest[3].split()[0] == fake_sha('mikefarah/yq', 'v4.55.0', 'yq_linux_amd64', n=64)
    assert 'ENV YQ_VERSION="4.55.0"' in (tree / 'Dockerfiles/zeek.Dockerfile').read_text()
    assert 'ENV TINI_VERSION=v0.20.0' in (tree / 'Dockerfiles/zeek.Dockerfile').read_text()
    assert (tree / 'scripts/hook.sh').read_text() == 'YQ_VERSION="4.55.0"\n'


def test_binaries_current_from_manifest(tree):
    (tree / 'Vagrantfile').write_text('YQ_VERSION="4.50.0"\n')
    (tree / 'Other.Dockerfile').write_text('ENV YQ_VERSION="4.50.0"\n')  # more common, but not in the manifest
    _, items = run(Binaries, tree)
    yq = items['yq']
    assert yq.current == '4.54.3'
    assert not any('missing from manifest' in n for n in yq.notes)
    assert any(n.startswith('inconsistent values: 4.54.3 in ') and 'Vagrantfile' in n for n in yq.notes)


def test_changelog_link_prefers_source_over_tracker():
    from pinning.checkers.python_reqs import changelog_link

    info = {'project_urls': {'Bug Tracker': 'https://github.com/x/y/issues', 'Source': 'https://github.com/x/y'}}
    assert changelog_link(info) == ('Source', 'https://github.com/x/y')
    assert changelog_link({'project_urls': {'Bug Tracker': 'https://github.com/x/y/issues'}}) is None


def test_source_pins(tree):
    net = StubNet()
    checker, items = run(SourcePins, tree, net)
    assert items['lua-resty-http'].status == 'held'
    assert items['nginx-auth-ldap'].status == 'current'
    ecs = items['ecs']
    assert [c.version for c in ecs.candidates] == ['v9.6.0', 'v9.5.1']
    edit_and_apply(checker, ecs, ecs.candidates[0])
    text = (tree / 'Dockerfiles/nginx.Dockerfile').read_text()
    new_commit = fake_sha('https://github.com/elastic/ecs', 'v9.6.0')
    assert f'ENV ECS_COMMIT="{new_commit}"' in text and 'ENV ECS_VERSION="9.6.0"' in text
    url = f'https://codeload.github.com/elastic/ecs/tar.gz/{new_commit}'
    assert net.downloads == [url] and f'ENV ECS_SHA256="{fake_sha(url, n=64)}"' in text
    assert '    ref: v9.6.0\n' in (tree / 'shared/pins/pins.yml').read_text()


def test_source_pins_add_checksum_and_comment(tree):
    checker, items = run(SourcePins, tree)
    http = items['lua-resty-http']
    edit_and_apply(checker, http, http.candidates[-1])  # v0.17.2
    text = (tree / 'Dockerfiles/nginx.Dockerfile').read_text()
    new_commit = fake_sha('https://github.com/ledgetech/lua-resty-http', 'v0.17.2')
    assert f'ARG LUA_RESTY_HTTP_REVISION={new_commit}' in text
    assert '# pin ledgetech/lua-resty-http v0.17.2' in text
    url = f'https://codeload.github.com/ledgetech/lua-resty-http/tar.gz/{new_commit}'
    assert f'ADD --checksum=sha256:{fake_sha(url, n=64)} https://codeload.github.com/ledgetech/lua-resty-http' in text
    assert 'sha256:' + 'b' * 64 in text  # the LDAP line is untouched


def test_python(tree):
    checker, items = run(PythonRequirements, tree)
    by_key = {(i.name, i.current): i for i in checker.discover()}
    assert ('psutil', '>=2.0') in by_key and by_key[('psutil', '>=2.0')].report_only
    floor = [i for i in checker.run()[0] if i.name == 'psutil'][0]
    assert floor.notes == ['newest on PyPI: 2.34.0 (not == pinned, report only)']
    at_floor = [i for i in checker.run()[0] if i.name == 'colorama'][0]
    assert at_floor.notes == [] and at_floor.status == 'current'  # nothing newer than the floor
    requests_items = [i for i in checker.run()[0] if i.name == 'requests']
    assert len(requests_items) == 1 and len(requests_items[0].locations) == 2
    req = requests_items[0]
    assert [c.version for c in req.candidates] == ['2.34.0', '2.33.2']
    assert ('Changelog', 'https://example.com/requests/HISTORY') in req.links
    flake8 = [i for i in checker.discover() if i.name == 'flake8']
    assert flake8 and flake8[0].current == '==7.2.0'
    edit_and_apply(checker, req, req.candidates[0])
    assert (tree / 'api/requirements.txt').read_text().startswith('requests==2.34.0\n')
    assert (tree / 'filescan/requirements.txt').read_text() == 'requests==2.34.0\n'
    topo = [i for i in checker.run()[0] if i.name.endswith('netbox-topology-views')][0]
    assert topo.group == 'netbox' and topo.current == 'v4.5.1'
    edit_and_apply(checker, topo, topo.candidates[0])
    assert 'ENV NETBOX_TOPOLOGY_VERSION="4.5.2"' in (tree / 'Dockerfiles/nginx.Dockerfile').read_text()


def test_npm_discovered(tree):
    _, items = run(Other, tree, StubNet())
    assert items['npm:redis'].current == '6.3.0'
    assert [c.version for c in items['npm:redis'].candidates] == ['7.0.0', '6.3.1']  # deprecated skipped


def test_zeek_lock(tree):
    checker, items = run(ZeekPackages, tree)
    tftp = items['zeek/spicy-tftp']
    assert tftp.candidates[0].version.startswith('v0.0.2@')
    assert items['cisagov/icsnpp-dnp3'].status == 'current'
    gone = items['example/gone']
    assert gone.candidates[0].version == '(remove)'
    # accept the tftp update, decline the removal: the stale entry stays, at the end
    edit_and_apply(checker, tftp, tftp.candidates[0])
    lines = (tree / 'zeek/zeek-packages.lock').read_text().splitlines()
    assert lines[0].startswith('# Generated by scripts/update_pins.py')
    assert (
        lines[2]
        == f'https://github.com/zeek/spicy-tftp|{fake_sha("https://github.com/zeek/spicy-tftp", "v0.0.2")}|v0.0.2||'
    )
    assert lines[3].startswith('https://github.com/cisagov/icsnpp-dnp3|') and lines[4].startswith(
        'https://github.com/example/gone|'
    )


def test_apply_edits_rejects_stale_and_overlapping(tree):
    rel = 'scripts/hook.sh'
    with pytest.raises(PinError):
        apply_edits(tree, [Edit(rel, 0, 4, 'NOPE', 'X')])
    with pytest.raises(PinError):
        apply_edits(tree, [Edit(rel, 0, 4, 'YQ_V', 'a'), Edit(rel, 2, 6, '_VER', 'b')])
    assert (tree / rel).read_text() == 'YQ_VERSION="4.54.3"\n'


def test_chooser_scripted():
    from pinning.core import Item

    item = Item(
        'binaries', 'yq', '4.54.3', candidates=[Candidate('5.0.0', SCOPE_ANY), Candidate('4.55.0', SCOPE_MAJOR)]
    )
    answers = iter(['x', '2'])
    out = io.StringIO()
    chooser = Chooser(Style(False), inp=lambda _: next(answers), out=out)
    assert chooser.choose(item).version == '4.55.0'
    assert 'please answer' in out.getvalue()
    assert Chooser(Style(False), yes=True, policy='major').choose(item).version == '4.55.0'
    assert Chooser(Style(False), yes=True, policy='minor').choose(item) is None


def test_cli_apply_yes_policy_minor(tree, monkeypatch, capsys):
    monkeypatch.setattr(cli, 'Net', lambda **kw: StubNet())
    rc = cli.main(
        ['--root', str(tree), '--apply', '--yes', '--policy', 'minor', '--no-color', '--binaries', '--source-pins']
    )
    assert rc == 0
    text = (tree / 'Dockerfiles/nginx.Dockerfile').read_text()
    assert 'ENV ECS_VERSION="9.5.1"' in text  # same minor
    assert f'LUA_RESTY_HTTP_REVISION={OLD_HTTP}' in text  # held
    assert 'ENV YQ_VERSION="4.54.4"' in (tree / 'Dockerfiles/zeek.Dockerfile').read_text()
    assert 'TINI_VERSION=v0.19.0' in (tree / 'Dockerfiles/zeek.Dockerfile').read_text()  # 0.20.0 is a new minor


def test_cli_dry_run_writes_nothing(tree, monkeypatch, capsys):
    before = {p: p.read_text() for p in tree.rglob('*') if p.is_file()}
    monkeypatch.setattr(cli, 'Net', lambda **kw: StubNet())
    rc = cli.main(['--root', str(tree), '--no-color'])
    assert rc == 0
    assert {p: p.read_text() for p in tree.rglob('*') if p.is_file()} == before
    out = capsys.readouterr().out
    assert 'zeek/zeek' in out and 'https://github.com/zeek/zeek/releases/tag/v9.1.0' in out
