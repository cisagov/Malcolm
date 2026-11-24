# Copyright (c) 2026 Battelle Energy Alliance, LLC.  All rights reserved.

"""uses: owner/repo[/path]@<sha> # vX.Y.Z in workflows and composite actions."""

import os
import re

from ..base import Checker, entry_flags
from ..core import SHA1_RE, Avail, Candidate, Edit, Item, pick_candidates

USES_RE = re.compile(
    r'(?m)^[ \t]*(?:-[ \t]+)?uses:[ \t]*["\']?(?P<action>[\w.-]+/[\w.-]+(?:/[\w./-]+)?)@(?P<ref>[\w./-]+)["\']?'
    r'(?P<rest>[^\n]*)'
)
COMMENT_VER_RE = re.compile(r'#\s*(?P<ver>v?\d+(?:\.\d+)*)\b')
SEMVER_TAG_RE = re.compile(r'^(?P<prefix>v?)(?P<nums>\d+(?:\.\d+)*)$')


def is_action_file(rel):
    gh = '.github' + os.sep
    return rel.startswith(gh) and rel.endswith(('.yml', '.yaml'))


class GithubActions(Checker):
    category = 'github-actions'
    title = 'GitHub Actions'

    def discover(self):
        groups = {}
        for rel, m in self.index.find(USES_RE, predicate=is_action_file, needle='uses:'):
            action, ref = m.group('action'), m.group('ref')
            cm = COMMENT_VER_RE.search(m.group('rest'))
            comment_ver = cm.group('ver') if cm else None
            span = {
                'rel': rel,
                'ref': m.span('ref'),
                'comment': (m.start('rest') + cm.start('ver'), m.start('rest') + cm.end('ver')) if cm else None,
            }
            groups.setdefault((action, ref, comment_ver), []).append((span, m.start()))
        overrides = self.catalog.section('github_actions')
        items = []
        for (action, ref, comment_ver), spans in sorted(groups.items()):
            repo = '/'.join(action.split('/')[:2])
            item = Item(self.category, action, f'{comment_ver or "?"} ({ref[:12]})' if SHA1_RE.match(ref) else ref)
            item.locations = [self.index.location(s['rel'], off) for s, off in spans]
            item.data.update(repo=repo, ref=ref, comment_ver=comment_ver, spans=[s for s, _ in spans])
            item.links.append(('releases', f'https://github.com/{repo}/releases'))
            entry_flags(item, overrides.get(repo) or overrides.get(action))
            if not SHA1_RE.match(ref):
                item.notes.append('not pinned to a commit SHA; updating will pin it')
            items.append(item)
        return items

    def lookup(self, item):
        d = item.data
        tags = self.net.tags(f'https://github.com/{d["repo"]}')
        # infer the current version when the comment is missing, from a tag at the pinned commit
        current = d['comment_ver']
        if SHA1_RE.match(d['ref']):
            at_ref = [t for t, sha in tags.items() if sha == d['ref'] and SEMVER_TAG_RE.match(t)]
            if current and tags.get(current) and tags[current] != d['ref']:
                item.notes.append(f'pinned SHA does not match tag {current} ({tags[current][:12]})')
            if not current and at_ref:
                current = max(at_ref, key=lambda t: (len(t.split('.')), t))
        elif SEMVER_TAG_RE.match(d['ref']):
            current = d['ref']
        cm = SEMVER_TAG_RE.match(current or '')
        prefix = cm.group('prefix') if cm else 'v'
        depth = len(cm.group('nums').split('.')) if cm else 3
        cur_nums = tuple(int(x) for x in cm.group('nums').split('.')) if cm else None
        avail = []
        for t, sha in tags.items():
            m = SEMVER_TAG_RE.match(t)
            if m and m.group('prefix') == prefix and len(m.group('nums').split('.')) == depth:
                nums = tuple(int(x) for x in m.group('nums').split('.'))
                avail.append(Avail(t, nums, nums, {'tag': t, 'sha': sha}))

        def make(a):
            return Candidate(
                a.version,
                data=a.data,
                links=[
                    ('release', f'https://github.com/{d["repo"]}/releases/tag/{a.version}'),
                    ('compare', f'https://github.com/{d["repo"]}/compare/{d["ref"]}...{a.data["sha"]}'),
                ],
            )

        cands = pick_candidates(cur_nums, cur_nums, avail, make)
        if not SHA1_RE.match(d['ref']) and not cands and current in tags:
            cands = [
                Candidate(current, label='pin current tag to its SHA', data={'tag': current, 'sha': tags[current]})
            ]
        item.candidates = cands

    def edits(self, item, cand):
        out = []
        for s in item.data['spans']:
            text = self.index.text(s['rel'])
            a, b = s['ref']
            out.append(Edit(s['rel'], a, b, text[a:b], cand.data['sha']))
            if s['comment']:
                a, b = s['comment']
                out.append(Edit(s['rel'], a, b, text[a:b], cand.data['tag']))
            else:
                # no version comment yet: append one after the ref
                line_end = text.find('\n', b)
                line_end = len(text) if line_end < 0 else line_end
                out.append(Edit(s['rel'], line_end, line_end, '', f' # {cand.data["tag"]}'))
        return out
