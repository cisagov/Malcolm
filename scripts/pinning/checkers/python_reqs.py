# Copyright (c) 2026 Battelle Energy Alliance, LLC.  All rights reserved.

"""requirements*.txt files, inline pip installs in Dockerfiles, and git+ requirement references."""

import os
import re

from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version

from ..base import Checker, entry_flags
from ..core import (
    SHA1_RE,
    Avail,
    Candidate,
    Edit,
    Item,
    PinError,
    find_assignments,
    instruction_blocks,
    is_dockerfile,
    pick_candidates,
)

SPEC_RE = re.compile(
    r'^(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*(?P<op>===|==|>=|<=|~=|!=|>|<)\s*(?P<ver>[^\s,;#]+)'
)
BARE_RE = re.compile(r'^(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*(?:;|$)')
GIT_RE = re.compile(r'git\+(?P<url>https?://[^@\s#]+?)(?:\.git)?@(?P<ref>[^\s#;]+)')
INLINE_PIN_RE = re.compile(r'(?<![\w.=/-])(?P<name>[A-Za-z][A-Za-z0-9._-]*)==(?P<ver>\d[A-Za-z0-9.!+-]*)')
VAR_REF_RE = re.compile(r'\$\{(?P<var>[A-Za-z_][A-Za-z0-9_]*)\}')
TAG_SHAPE_RE = re.compile(r'^(?P<prefix>[^\d]*)(?P<nums>\d+(?:\.\d+)*)(?P<suffix>.*)$')
CHANGELOG_KEYS = ('changelog', 'changes', 'release notes', 'releases', 'history', 'news', "what's new")


def is_requirements(rel):
    name = os.path.basename(rel)
    return name.startswith('requirements') and name.endswith('.txt')


def strip_comment(line):
    m = re.search(r'(^|\s)#', line)
    return line[: m.start()] if m else line


SOURCE_KEYS = ('source', 'repository', 'code', 'homepage', 'home')
SKIP_KEYS = ('issue', 'bug', 'tracker', 'funding', 'donate', 'sponsor', 'documentation', 'docs', 'chat', 'discord')


def changelog_link(info):
    """The most useful project link for release notes: a changelog, else the source."""
    urls = {k: v for k, v in (info.get('project_urls') or {}).items() if v}
    for k, v in urls.items():
        if any(key in k.lower() for key in CHANGELOG_KEYS):
            return (k, v)
    for k, v in urls.items():
        if any(key in k.lower() for key in SOURCE_KEYS):
            return (k, v)
    for k, v in urls.items():
        if 'github.com' in v and '/issues' not in v and not any(key in k.lower() for key in SKIP_KEYS):
            return (k, v)
    return None


class PythonRequirements(Checker):
    category = 'python'
    title = 'Python requirements'

    def discover(self):
        pypi, git = {}, {}
        for rel in self.index.text_files(is_requirements):
            text = self.index.text(rel)
            offset = 0
            for raw in text.splitlines(keepends=True):
                line = strip_comment(raw.rstrip('\r\n')).strip()
                lead = len(raw) - len(raw.lstrip())
                base = offset + lead
                offset += len(raw)
                if not line or line.startswith(('-', '.', '/')):
                    continue
                gm = GIT_RE.search(line)
                if gm:
                    a, b = gm.span('ref')
                    git.setdefault((gm.group('url'), gm.group('ref')), []).append((rel, base + a, base + b))
                    continue
                sm = SPEC_RE.match(line)
                if sm:
                    a, b = sm.span('ver')
                    key = (canonicalize_name(sm.group('name')), sm.group('op'), sm.group('ver'))
                    pypi.setdefault(key, []).append((rel, base + a, base + b, sm.group('name')))
                elif BARE_RE.match(line):
                    key = (canonicalize_name(BARE_RE.match(line).group('name')), '', '')
                    pypi.setdefault(key, []).append((rel, base, base, BARE_RE.match(line).group('name')))
        for rel in self.index.text_files(is_dockerfile):
            text = self.index.text(rel)
            for start, end in instruction_blocks(text):
                block = text[start:end]
                if 'pip' not in block or 'install' not in block:
                    continue
                for m in INLINE_PIN_RE.finditer(block):
                    a, b = m.span('ver')
                    key = (canonicalize_name(m.group('name')), '==', m.group('ver'))
                    pypi.setdefault(key, []).append((rel, start + a, start + b, m.group('name')))

        overrides = {canonicalize_name(k): v or {} for k, v in self.catalog.section('python').items()}
        items = []
        for (name, op, ver), spans in sorted(pypi.items()):
            display = spans[0][3]
            item = Item(self.category, display, f'{op}{ver}' if op else '(unpinned)')
            item.locations = [self.index.location(rel, a) for rel, a, _, _ in spans]
            item.data.update(kind='pypi', pkg=name, op=op, ver=ver, spans=[(r, a, b) for r, a, b, _ in spans])
            entry = overrides.get(name) or {}
            self._apply_entry(item, entry, [s[0] for s in spans])
            if op != '==':
                item.report_only = True
            item.links.append(('PyPI', f'https://pypi.org/project/{name}/#history'))
            items.append(item)
        for (url, ref), spans in sorted(git.items()):
            path = re.sub(r'^https?://[^/]+/', '', url)
            item = Item(self.category, path, ref[:12] if SHA1_RE.match(ref) else ref)
            item.locations = [self.index.location(rel, a) for rel, a, _ in spans]
            item.data.update(kind='git', url=url, ref=ref, spans=spans, github='github.com/' in url, path=path)
            entry = overrides.get(canonicalize_name(path.split('/')[-1])) or overrides.get(path) or {}
            self._apply_entry(item, entry, [s[0] for s in spans])
            if item.data['github']:
                item.links.append(('repo', f'https://github.com/{path}'))
            vm = VAR_REF_RE.search(ref)
            if vm:
                found = find_assignments(self.index, vm.group('var'))
                if not found:
                    item.error = f'no assignment of {vm.group("var")} found'
                else:
                    value = found[0][1].group('val')
                    item.data.update(var=vm.group('var'), var_found=found, var_value=value)
                    item.data['tag'] = ref.replace(vm.group(0), value)
                    item.current = item.data['tag']
                    item.locations += [self.index.location(r, m.start()) for r, m in found]
            items.append(item)
        return items

    def _apply_entry(self, item, entry, rels):
        if entry.get('paths') and not any(r in entry['paths'] for r in rels):
            return
        entry_flags(item, entry)
        item.data['entry'] = entry

    def lookup(self, item):
        if item.data['kind'] == 'pypi':
            self._lookup_pypi(item)
        else:
            self._lookup_git(item)

    def _lookup_pypi(self, item):
        d = item.data
        info = self.net.pypi(d['pkg'])
        avail = []
        for v, files in (info.get('releases') or {}).items():
            try:
                pv = Version(v)
            except InvalidVersion:
                continue
            if (pv.is_prerelease or pv.is_devrelease) and not self.ctx.include_prereleases:
                continue
            if not files or all(f.get('yanked') for f in files):
                continue
            rp = next((f.get('requires_python') for f in files if f.get('requires_python')), None)
            avail.append(Avail(v, pv, pv.release, {'requires_python': rp}))
        cl = changelog_link(info.get('info') or {})
        if cl:
            item.links.append(cl)
        if d['op'] != '==':
            latest = max(avail, key=lambda a: a.key, default=None)
            try:
                floor = Version(d['ver']) if d['ver'] else None
            except InvalidVersion:
                floor = None
            if latest and (floor is None or latest.key > floor):
                item.notes.append(f'newest on PyPI: {latest.version} (not == pinned, report only)')
            return
        try:
            cur = Version(d['ver'])
        except InvalidVersion:
            raise PinError(f'cannot parse version {d["ver"]}')

        def make(a):
            return Candidate(
                a.version,
                links=[('release', f'https://pypi.org/project/{d["pkg"]}/{a.version}/')],
                data={'requires_python': a.data.get('requires_python')},
            )

        item.candidates = pick_candidates(cur.release, cur, avail, make)
        for c in item.candidates:
            if c.data.get('requires_python'):
                c.label += f'; requires_python {c.data["requires_python"]}'

    def _lookup_git(self, item):
        d = item.data
        entry = d.get('entry') or {}
        url = d['url'] + ('.git' if d['github'] and not d['url'].endswith('.git') else '')
        if SHA1_RE.match(d['ref']):
            branch = entry.get('branch', 'HEAD')
            head = self.net.ref_commit(url, branch)
            if head != d['ref']:
                links = (
                    [('compare', f'https://github.com/{d["path"]}/compare/{d["ref"]}...{head}')] if d['github'] else []
                )
                item.candidates = [
                    Candidate(
                        head[:12],
                        label='default branch head' if branch == 'HEAD' else f'{branch} head',
                        links=links,
                        data={'ref': head},
                    )
                ]
            return
        tag = d.get('tag', d['ref'])
        shape = TAG_SHAPE_RE.match(tag)
        if not shape:
            item.notes.append('ref is not a commit or version tag; nothing to compare')
            item.report_only = True
            return
        prefix, nums, suffix = shape.group('prefix'), shape.group('nums'), shape.group('suffix')
        depth = len(nums.split('.'))
        avail = []
        for t, sha in self.net.tags(url).items():
            m = TAG_SHAPE_RE.match(t)
            if (
                m
                and m.group('prefix') == prefix
                and m.group('suffix') == suffix
                and len(m.group('nums').split('.')) == depth
            ):
                n = tuple(map(int, m.group('nums').split('.')))
                avail.append(Avail(t, n, n, {'tag': t}))
        cur = tuple(map(int, nums.split('.')))

        def make(a):
            links = []
            if d['github']:
                links = [
                    ('release', f'https://github.com/{d["path"]}/releases/tag/{a.version}'),
                    ('compare', f'https://github.com/{d["path"]}/compare/{tag}...{a.version}'),
                ]
            return Candidate(a.version, links=links, data={'tag': a.version})

        item.candidates = pick_candidates(cur, cur, avail, make)

    def edits(self, item, cand):
        d = item.data
        out = []
        if d['kind'] == 'pypi':
            for rel, a, b in d['spans']:
                out.append(Edit(rel, a, b, self.index.text(rel)[a:b], cand.version))
            return out
        if 'var' in d:
            # the ref is <literal>${VAR}<literal>; the variable gets whatever the literals don't cover
            lit_prefix, lit_suffix = d['ref'].split('${' + d['var'] + '}', 1)
            new_tag = cand.data['tag']
            if not (new_tag.startswith(lit_prefix) and new_tag.endswith(lit_suffix)):
                raise PinError(f'tag {new_tag} does not fit {d["ref"]}')
            value = new_tag[len(lit_prefix) : len(new_tag) - len(lit_suffix) if lit_suffix else None]
            for rel, m in d['var_found']:
                a, b = m.span('val')
                out.append(Edit(rel, a, b, self.index.text(rel)[a:b], value))
            return out
        new_ref = cand.data.get('ref') or cand.data['tag']
        for rel, a, b in d['spans']:
            out.append(Edit(rel, a, b, self.index.text(rel)[a:b], new_ref))
        return out
