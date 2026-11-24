# Copyright (c) 2026 Battelle Energy Alliance, LLC.  All rights reserved.

"""
Release assets verified by install-verified-binary.sh: the *_VERSION variables that select them
and their entries in shared/pins/binaries.sha256.
"""

import collections
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
    line_span,
    pick_candidates,
    template_regex,
)

DEFAULT_ARCHS = ['amd64', 'arm64']


def artifacts_of(entry):
    arts = entry.get('artifacts')
    if arts:
        return arts
    return [{k: entry[k] for k in ('key', 'asset', 'url') if k in entry}]


class Binaries(Checker):
    category = 'binaries'
    title = 'Release binaries (binaries.sha256)'

    @property
    def manifest_rel(self):
        return self.catalog.setting('binaries_manifest', 'shared/pins/binaries.sha256')

    def discover(self):
        items = []
        manifest = self.index.text(self.manifest_rel)
        if manifest is None:
            raise PinError(f'manifest not found: {self.manifest_rel}')
        manifest_keys = {
            parts[1]
            for parts in (l.split() for l in manifest.splitlines())
            if len(parts) == 2 and not parts[0].startswith('#')
        }
        for name, entry in sorted(self.catalog.section('binaries').items()):
            entry = entry or {}
            var = entry.get('version_var')
            item = Item(self.category, name, '?')
            entry_flags(item, entry)
            item.data['entry'] = entry
            if not var:
                item.error = 'catalog entry has no version_var'
                items.append(item)
                continue
            found = find_assignments(self.index, var)
            if not found:
                item.error = f'no assignment of {var} found in the tree'
                items.append(item)
                continue
            var_re = template_regex(entry.get('var_format', '{version}'))
            versions = []
            for rel, m in found:
                vm = var_re.match(m.group('val'))
                if not vm:
                    item.error = f'{rel}: {var}={m.group("val")} does not match var_format'
                    break
                versions.append(vm.group('version'))
            item.locations = [self.index.location(rel, m.start()) for rel, m in found]
            if item.error:
                items.append(item)
                continue
            counts = collections.Counter(versions)
            # the version with entries in the manifest is the one the build verifies; the most
            # common value breaks ties, then the highest
            ranked = sorted(
                counts,
                key=lambda v: (
                    all(k in manifest_keys for k in self._keys(entry, v)),
                    counts[v],
                    tuple(map(int, v.split('.'))),
                ),
                reverse=True,
            )
            current = ranked[0]
            if len(counts) > 1:
                where = {v: sorted({rel for (rel, m), ver in zip(found, versions) if ver == v}) for v in counts}
                item.notes.append('inconsistent values: ' + '; '.join(f'{v} in {", ".join(where[v])}' for v in ranked))
            item.current = current
            item.data.update(var=var, found=found, versions=sorted(counts))
            missing = [k for k in self._keys(entry, current) if k not in manifest_keys]
            if missing:
                item.notes.append('missing from manifest: ' + ', '.join(missing))
            if entry.get('repo'):
                item.links.append(('releases', f'https://github.com/{entry["repo"]}/releases'))
            items.append(item)
        return items

    def _keys(self, entry, version):
        out = []
        for art in artifacts_of(entry):
            for arch in entry.get('archs', DEFAULT_ARCHS) or [None]:
                out.append(self._fill(entry, art['key'], version, arch))
        return out

    @staticmethod
    def _fill(entry, template, version, arch):
        values = {'version': version, 'var': fill(entry.get('var_format', '{version}'), version=version)}
        if arch:
            values['arch'] = arch
            values['aname'] = (entry.get('arch_names') or {}).get(arch, arch)
        return fill(template, **values)

    def lookup(self, item):
        entry = item.data['entry']
        source = entry.get('source', 'github')
        current = item.current
        if source == 'pypi':
            pkg = entry.get('package', item.name)
            info = self.net.pypi(pkg)
            avail = []
            for v, files in info.get('releases', {}).items():
                try:
                    pv = Version(v)
                except InvalidVersion:
                    continue
                if (pv.is_prerelease or pv.is_devrelease) and not self.ctx.include_prereleases:
                    continue
                if not files or all(f.get('yanked') for f in files):
                    continue
                avail.append(Avail(v, pv, pv.release))
            cur = Version(current)

            def make(a):
                return Candidate(a.version, links=[('release', f'https://pypi.org/project/{pkg}/{a.version}/')])

            item.candidates = pick_candidates(cur.release, cur, avail, make)
            return
        if source != 'github':
            raise PinError(f'unknown source {source!r}')
        repo = entry['repo']
        tag_tpl = entry.get('tag', 'v{version}')
        tag_re = template_regex(tag_tpl)
        avail = []
        for rel in self.net.gh_releases(repo):
            if rel.get('prerelease') and not self.ctx.include_prereleases:
                continue
            m = tag_re.match(rel.get('tag_name', ''))
            if m:
                v = m.group('version')
                avail.append(
                    Avail(v, tuple(map(int, v.split('.'))), tuple(map(int, v.split('.'))), {'tag': rel['tag_name']})
                )
        cur = tuple(map(int, current.split('.')))
        old_tag = fill(tag_tpl, version=current)

        def make(a):
            return Candidate(
                a.version,
                data={'tag': a.data['tag']},
                links=[
                    ('release', f'https://github.com/{repo}/releases/tag/{a.data["tag"]}'),
                    ('compare', f'https://github.com/{repo}/compare/{old_tag}...{a.data["tag"]}'),
                ],
            )

        item.candidates = pick_candidates(cur, cur, avail, make)

    def _sha256(self, entry, art, version, arch, cand):
        source = entry.get('source', 'github')
        if 'url' in art:
            return self.net.url_sha256(self._fill(entry, art['url'], version, arch))
        asset = self._fill(entry, art.get('asset', art['key']), version, arch)
        if source == 'pypi':
            pkg = entry.get('package', '')
            for f in self.net.pypi_version(pkg, version).get('urls', []):
                if f.get('filename') == asset and f.get('digests', {}).get('sha256'):
                    return f['digests']['sha256']
            raise PinError(f'PyPI {pkg} {version} has no file named {asset}')
        return self.net.gh_asset_sha256(entry['repo'], cand.data['tag'], asset)

    def edits(self, item, cand):
        entry = item.data['entry']
        new = cand.version
        var_fmt = entry.get('var_format', '{version}')
        out = []
        for rel, m in item.data['found']:
            a, b = m.span('val')
            out.append(Edit(rel, a, b, self.index.text(rel)[a:b], fill(var_fmt, version=new)))
        rel = self.manifest_rel
        text = self.index.text(rel)
        for art in artifacts_of(entry):
            for arch in entry.get('archs', DEFAULT_ARCHS) or [None]:
                new_key = self._fill(entry, art['key'], new, arch)
                sha = self._sha256(entry, art, new, arch, cand)
                new_line = f'{sha}  {new_key}'
                old_lines = []
                for old_version in item.data['versions']:
                    old_key = self._fill(entry, art['key'], old_version, arch)
                    for lm in re.finditer(r'(?m)^[0-9a-fA-F]{64}[ \t]+' + re.escape(old_key) + r'[ \t]*$', text):
                        old_lines.append(lm)
                if old_lines:
                    first, rest = old_lines[0], old_lines[1:]
                    out.append(Edit(rel, first.start(), first.end(), first.group(0), new_line))
                    for lm in rest:
                        s, e = line_span(text, lm.start())
                        out.append(Edit(rel, s, e, text[s:e], ''))
                else:
                    prefix = '' if text.endswith('\n') or not text else '\n'
                    out.append(Edit(rel, len(text), len(text), '', f'{prefix}{new_line}\n'))
        return out
