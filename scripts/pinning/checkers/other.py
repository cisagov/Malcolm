# Copyright (c) 2026 Battelle Energy Alliance, LLC.  All rights reserved.

"""
Everything else:
  - npm package@version pins in Dockerfile npm install commands (discovered automatically)
  - catalog 'version-var' entries: a *_VERSION variable checked against rubygems, npm, PyPI,
    GitHub releases or git tags
  - catalog 'git-ref' entries: a literal tag or branch name in specific files (live-build, the
    Raspberry Pi kernel branch)
  - catalog 'apt-glob' entries: an apt version pattern like 1:8.0.* checked with Debian's madison
"""

import re

from packaging.version import InvalidVersion, Version

from ..base import Checker, entry_flags
from ..core import (
    Avail,
    Candidate,
    Edit,
    Item,
    PinError,
    fill,
    find_assignments,
    instruction_blocks,
    is_dockerfile,
    pick_candidates,
    template_regex,
)

NPM_PIN_RE = re.compile(
    r'(?<![\w@/.-])(?P<name>(?:@[a-z0-9][\w.-]*/)?[a-z0-9][\w.-]*)@(?P<ver>\d+\.\d+\.\d+)(?![\w.-])'
)
DEB_VERSION_RE = re.compile(r'^(?:(?P<epoch>\d+):)?(?P<upstream>\d+(?:\.\d+)*)')


def nums(v):
    return tuple(int(x) for x in v.split('.'))


class Other(Checker):
    category = 'other'
    title = 'Other pins (npm, gems, apt globs, literal refs)'

    def discover(self):
        items = self._discover_npm()
        for name, entry in sorted(self.catalog.section('other').items()):
            if name == 'npm':  # per-package overrides for the discovered npm pins
                continue
            entry = entry or {}
            item = Item(self.category, name, '?')
            entry_flags(item, entry)
            item.data['entry'] = entry
            kind = entry.get('type')
            item.data['kind'] = kind
            try:
                if kind == 'version-var':
                    self._discover_var(item, entry)
                elif kind == 'git-ref':
                    self._discover_git_ref(item, entry)
                elif kind == 'apt-glob':
                    self._discover_apt(item, entry)
                else:
                    raise PinError(f'unknown type {kind!r} (expected version-var, git-ref or apt-glob)')
            except PinError as e:
                item.error = str(e)
            items.append(item)
        return items

    # npm ------------------------------------------------------------------------------------------

    def _discover_npm(self):
        pins = {}
        for rel in self.index.text_files(is_dockerfile):
            text = self.index.text(rel)
            for start, end in instruction_blocks(text):
                block = text[start:end]
                if 'npm' not in block or 'install' not in block:
                    continue
                for m in NPM_PIN_RE.finditer(block):
                    a, b = m.span('ver')
                    pins.setdefault((m.group('name'), m.group('ver')), []).append((rel, start + a, start + b))
        overrides = self.catalog.section('other').get('npm') or {}
        items = []
        for (name, ver), spans in sorted(pins.items()):
            item = Item(self.category, f'npm:{name}', ver)
            item.locations = [self.index.location(rel, a) for rel, a, _ in spans]
            item.data.update(kind='npm', pkg=name, spans=spans)
            item.links.append(('npm', f'https://www.npmjs.com/package/{name}?activeTab=versions'))
            entry_flags(item, overrides.get(name) if isinstance(overrides, dict) else None)
            items.append(item)
        return items

    # version-var ----------------------------------------------------------------------------------

    def _discover_var(self, item, entry):
        var = entry.get('version_var')
        if not var:
            raise PinError('version-var entry needs version_var')
        found = find_assignments(self.index, var)
        if not found:
            raise PinError(f'no assignment of {var} found in the tree')
        vm = template_regex(entry.get('var_format', '{version}')).match(found[0][1].group('val'))
        if not vm:
            raise PinError(f'{var}={found[0][1].group("val")} does not match var_format')
        item.current = vm.group('version')
        item.locations = [self.index.location(rel, m.start()) for rel, m in found]
        item.data['found'] = found

    # git-ref --------------------------------------------------------------------------------------

    def _discover_git_ref(self, item, entry):
        for k in ('url', 'pattern', 'ref', 'files'):
            if not entry.get(k):
                raise PinError(f'git-ref entry needs {k}')
        ref = str(entry['ref'])
        m = template_regex(entry['pattern']).match(ref)
        if not m:
            raise PinError(f'ref {ref!r} does not match pattern {entry["pattern"]!r}')
        item.current = ref
        item.data['version'] = m.group('version')
        spans = []
        for rel in entry['files']:
            text = self.index.text(rel)
            if text is None:
                raise PinError(f'{rel} not found')
            hits = [mm.start() for mm in re.finditer(re.escape(ref) + r'(?![\w.-])', text)]
            if not hits:
                raise PinError(f'{ref} not found in {rel}')
            spans += [(rel, h, h + len(ref)) for h in hits]
        item.data['spans'] = spans
        item.locations = [self.index.location(rel, a) for rel, a, _ in spans]

    # apt-glob -------------------------------------------------------------------------------------

    def _discover_apt(self, item, entry):
        for k in ('package', 'suite', 'version_var'):
            if not entry.get(k):
                raise PinError(f'apt-glob entry needs {k}')
        found = find_assignments(self.index, entry['version_var'])
        if not found:
            raise PinError(f'no assignment of {entry["version_var"]} found')
        value = found[0][1].group('val')
        m = re.match(r'^(?:(?P<epoch>\d+):)?(?P<series>\d+(?:\.\d+)*)\.\*$', value)
        if not m:
            raise PinError(f'{entry["version_var"]}={value} is not like [epoch:]X.Y.*')
        item.current = value
        item.data.update(found=found, epoch=m.group('epoch'), series=m.group('series'))
        item.locations = [self.index.location(rel, mm.start()) for rel, mm in found]
        item.links.append(('tracker', f'https://tracker.debian.org/pkg/{entry["package"]}'))

    # lookups --------------------------------------------------------------------------------------

    def lookup(self, item):
        kind = item.data['kind']
        if kind == 'npm':
            self._lookup_npm(item)
        elif kind == 'version-var':
            self._lookup_var(item)
        elif kind == 'git-ref':
            self._lookup_git_ref(item)
        elif kind == 'apt-glob':
            self._lookup_apt(item)

    def _semver_avail(self, versions):
        avail = []
        for v in versions:
            if re.fullmatch(r'\d+(?:\.\d+)*', v):
                avail.append(Avail(v, nums(v), nums(v)))
            elif self.ctx.include_prereleases and re.match(r'\d+(?:\.\d+)*', v):
                n = nums(re.match(r'\d+(?:\.\d+)*', v).group(0))
                avail.append(Avail(v, n + (-1,), n))
        return avail

    def _lookup_npm(self, item):
        pkg, cur = item.data['pkg'], item.current
        info = self.net.npm(pkg)
        avail = self._semver_avail(
            [v for v, meta in (info.get('versions') or {}).items() if not (meta or {}).get('deprecated')]
        )
        item.candidates = pick_candidates(
            nums(cur),
            nums(cur),
            avail,
            lambda a: Candidate(a.version, links=[('npm', f'https://www.npmjs.com/package/{pkg}/v/{a.version}')]),
        )

    def _lookup_var(self, item):
        entry, cur = item.data['entry'], item.current
        source = entry.get('source')
        if source == 'rubygems':
            gem = entry['package']
            versions = [v['number'] for v in self.net.rubygems_versions(gem) if not v.get('prerelease')]
            avail = self._semver_avail(versions)
            make = lambda a: Candidate(
                a.version, links=[('gem', f'https://rubygems.org/gems/{gem}/versions/{a.version}')]
            )
        elif source == 'npm':
            pkg = entry['package']
            avail = self._semver_avail(list((self.net.npm(pkg).get('versions') or {}).keys()))
            make = lambda a: Candidate(a.version, links=[('npm', f'https://www.npmjs.com/package/{pkg}/v/{a.version}')])
        elif source == 'pypi':
            pkg = entry['package']
            avail = []
            for v in self.net.pypi(pkg).get('releases') or {}:
                try:
                    pv = Version(v)
                except InvalidVersion:
                    continue
                if not (pv.is_prerelease or pv.is_devrelease) or self.ctx.include_prereleases:
                    avail.append(Avail(v, pv, pv.release))
            make = lambda a: Candidate(a.version, links=[('release', f'https://pypi.org/project/{pkg}/{a.version}/')])
            item.candidates = pick_candidates(Version(cur).release, Version(cur), avail, make)
            return
        elif source in ('github-release', 'git-tags'):
            repo = entry.get('repo')
            tag_tpl = entry.get('tag', 'v{version}')
            tag_re = template_regex(tag_tpl)
            if source == 'github-release':
                tags = [
                    r['tag_name']
                    for r in self.net.gh_releases(repo)
                    if not r.get('prerelease') or self.ctx.include_prereleases
                ]
            else:
                tags = list(self.net.tags(entry.get('git_url') or f'https://github.com/{repo}'))
            avail = [
                Avail(m.group('version'), nums(m.group('version')), nums(m.group('version')), {'tag': t})
                for t in tags
                if (m := tag_re.match(t))
            ]
            make = lambda a: Candidate(
                a.version,
                links=[('release', f'https://github.com/{repo}/releases/tag/{a.data["tag"]}')] if repo else [],
            )
        else:
            raise PinError(f'unknown version-var source {source!r}')
        item.candidates = pick_candidates(nums(cur), nums(cur), avail, make)

    def _lookup_git_ref(self, item):
        entry = item.data['entry']
        refs = self.net.heads(entry['url']) if entry.get('refs', 'tags') == 'heads' else self.net.tags(entry['url'])
        pat = template_regex(entry['pattern'])
        avail = [
            Avail(r, nums(m.group('version')), nums(m.group('version')), {'commit': c})
            for r, c in refs.items()
            if (m := pat.match(r))
        ]
        cur = nums(item.data['version'])
        current_commit = refs.get(item.current)
        if current_commit:
            item.notes.append(f'{item.current} is at {current_commit[:12]}')
        page = entry.get('page')
        item.candidates = pick_candidates(
            cur, cur, avail, lambda a: Candidate(a.version, links=[('page', fill(page, ref=a.version))] if page else [])
        )

    def _lookup_apt(self, item):
        entry, d = item.data['entry'], item.data
        rows = self.net.madison(entry['package'], entry['suite'])
        if not rows:
            raise PinError(f'madison has no {entry["package"]} in {entry["suite"]}')
        depth = len(d['series'].split('.'))
        series = {}
        for version, _, _ in rows:
            m = DEB_VERSION_RE.match(version)
            if not m or (m.group('epoch') or None) != (d['epoch'] or None):
                continue
            parts = m.group('upstream').split('.')
            if len(parts) >= depth:
                s = '.'.join(parts[:depth])
                series.setdefault(s, version)
        item.notes.append('available: ' + ', '.join(sorted({v for v, _, _ in rows}, reverse=True)))
        avail = [Avail(s, nums(s), nums(s), {'example': v}) for s, v in series.items()]
        prefix = f'{d["epoch"]}:' if d['epoch'] else ''
        cur = nums(d['series'])
        item.candidates = pick_candidates(
            cur,
            cur,
            avail,
            lambda a: Candidate(
                f'{prefix}{a.version}.*', label=f'e.g. {a.data["example"]}', data={'value': f'{prefix}{a.version}.*'}
            ),
        )

    # edits ----------------------------------------------------------------------------------------

    def edits(self, item, cand):
        d = item.data
        kind = d['kind']
        out = []
        if kind in ('npm', 'git-ref'):
            for rel, a, b in d['spans']:
                out.append(Edit(rel, a, b, self.index.text(rel)[a:b], cand.version))
            if kind == 'git-ref':
                out.append(self.catalog.value_edit(('other', item.name, 'ref'), cand.version))
            return out
        if kind == 'version-var':
            value = fill(d['entry'].get('var_format', '{version}'), version=cand.version)
        elif kind == 'apt-glob':
            value = cand.data['value']
        else:
            raise PinError(f'cannot update {kind}')
        for rel, m in d['found']:
            a, b = m.span('val')
            out.append(Edit(rel, a, b, self.index.text(rel)[a:b], value))
        return out
