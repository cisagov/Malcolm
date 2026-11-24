# Copyright (c) 2026 Battelle Energy Alliance, LLC.  All rights reserved.

"""
Upstream source consumed by commit or release tag and verified by SHA-256: *_COMMIT/*_REVISION
variables with a *_SHA256 variable or ADD --checksum line, release tarballs selected by a
*_VERSION variable, and commit pins verified by git alone.
"""

import re

from ..base import Checker, entry_flags
from ..core import (
    SHA1_RE,
    Avail,
    Candidate,
    Edit,
    Item,
    PinError,
    fill,
    find_assignments,
    pick_candidates,
    template_regex,
)

DEFAULT_ARCHIVE = 'https://codeload.github.com/{repo}/tar.gz/{commit}'


def add_checksum_regex(var):
    return re.compile(
        r'(?m)^[ \t]*ADD\b[^\n]*?--checksum=sha256:(?P<sha>[0-9a-f]{64})[^\n]*\$\{?' + re.escape(var) + r'\b[^\n]*$'
    )


class SourcePins(Checker):
    category = 'source-pins'
    title = 'Source archives and commits'

    def _single(self, item, var, required=True):
        found = find_assignments(self.index, var)
        if not found:
            if required:
                raise PinError(f'no assignment of {var} found in the tree')
            return [], None
        values = sorted({m.group('val') for _, m in found})
        if len(values) > 1:
            item.notes.append(f'{var} has inconsistent values: {", ".join(values)}')
        return found, found[0][1].group('val')

    def discover(self):
        items = []
        for name, entry in sorted(self.catalog.section('source_pins').items()):
            entry = entry or {}
            item = Item(self.category, name, '?')
            entry_flags(item, entry)
            item.data['entry'] = entry
            try:
                self._discover_one(item, entry)
            except PinError as e:
                item.error = str(e)
            items.append(item)
        return items

    def _discover_one(self, item, entry):
        d = item.data
        if not (entry.get('repo') or entry.get('git_url')):
            raise PinError('catalog entry needs repo or git_url')
        d['git_url'] = entry.get('git_url') or f'https://github.com/{entry["repo"]}'
        track = entry.get('track', 'tag')
        if track not in ('tag', 'branch'):
            raise PinError(f'unknown track {track!r}')
        d['track'] = track
        locs = []
        d['commit_found'], d['commit'] = ([], None)
        if entry.get('commit_var'):
            d['commit_found'], d['commit'] = self._single(item, entry['commit_var'])
            if not SHA1_RE.match(d['commit'] or ''):
                raise PinError(f'{entry["commit_var"]}={d["commit"]} is not a 40-character commit')
            locs += d['commit_found']
        d['version_found'], d['version_value'] = ([], None)
        if entry.get('version_var'):
            d['version_found'], d['version_value'] = self._single(item, entry['version_var'])
            locs += d['version_found']
        if not (entry.get('commit_var') or entry.get('version_var')):
            raise PinError('catalog entry needs commit_var or version_var')
        d['sha_found'] = []
        if entry.get('sha256_var'):
            d['sha_found'], _ = self._single(item, entry['sha256_var'])
            locs += d['sha_found']
        d['add_found'] = []
        if entry.get('add_checksum'):
            var = entry.get('commit_var') or entry.get('version_var')
            d['add_found'] = list(self.index.find(add_checksum_regex(var), needle=var))
            if not d['add_found']:
                raise PinError(f'no ADD --checksum line referencing ${var} found')
            locs += d['add_found']
        if (
            track == 'tag'
            and not entry.get('sha256_var')
            and not entry.get('add_checksum')
            and not entry.get('commit_var')
        ):
            raise PinError('a tag-tracked pin with no commit needs sha256_var or add_checksum')
        item.locations = [self.index.location(rel, m.start()) for rel, m in locs]

        tag_tpl = entry.get('tag', 'v{version}')
        d['tag_tpl'] = tag_tpl
        var_fmt = entry.get('var_format', '{version}')
        if track == 'tag':
            cur_version = None
            if d['version_value'] is not None:
                vm = template_regex(var_fmt).match(d['version_value'])
                if not vm:
                    raise PinError(f'{entry["version_var"]}={d["version_value"]} does not match var_format {var_fmt!r}')
                cur_version = vm.group('version')
            elif entry.get('ref'):
                vm = template_regex(tag_tpl).match(str(entry['ref']))
                if not vm:
                    raise PinError(f'ref {entry["ref"]!r} does not match tag template {tag_tpl!r}')
                cur_version = vm.group('version')
            else:
                raise PinError('a tag-tracked pin needs ref or version_var')
            d['cur_version'] = cur_version
            d['cur_tag'] = fill(tag_tpl, version=cur_version)
            if entry.get('ref') and str(entry['ref']) != d['cur_tag']:
                item.notes.append(
                    f'catalog ref {entry["ref"]} disagrees with {entry.get("version_var")} ({d["cur_tag"]})'
                )
            item.current = d['cur_tag'] + (f' ({d["commit"][:12]})' if d['commit'] else '')
        else:
            d['branch'] = str(entry.get('ref') or 'HEAD')
            item.current = f'{d["branch"]}@{d["commit"][:12]}' if d['commit'] else d['branch']
            if not d['commit']:
                raise PinError('a branch-tracked pin needs commit_var')
        if entry.get('repo'):
            item.links.append(('repo', f'https://github.com/{entry["repo"]}'))

    def lookup(self, item):
        d, entry = item.data, item.data['entry']
        repo = entry.get('repo')
        if d['track'] == 'branch':
            head = self.net.ref_commit(d['git_url'], d['branch'])
            if head != d['commit']:
                links = [('compare', f'https://github.com/{repo}/compare/{d["commit"]}...{head}')] if repo else []
                item.candidates = [
                    Candidate(
                        head[:12],
                        label='default branch head' if d['branch'] == 'HEAD' else f'{d["branch"]} head',
                        links=links,
                        data={'commit': head},
                    )
                ]
            return
        tags = self.net.tags(d['git_url'])
        if d['commit'] and d['cur_tag'] in tags and tags[d['cur_tag']] != d['commit']:
            item.notes.append(
                f'{entry["commit_var"]} is not the commit tagged {d["cur_tag"]} ({tags[d["cur_tag"]][:12]})'
            )
        tag_re = template_regex(d['tag_tpl'])
        avail = []
        for t, sha in tags.items():
            m = tag_re.match(t)
            if m:
                nums = tuple(map(int, m.group('version').split('.')))
                avail.append(Avail(m.group('version'), nums, nums, {'tag': t, 'commit': sha}))
        cur = tuple(map(int, d['cur_version'].split('.')))

        def make(a):
            links = []
            if repo:
                links = [
                    ('release', f'https://github.com/{repo}/releases/tag/{a.data["tag"]}'),
                    ('compare', f'https://github.com/{repo}/compare/{d["cur_tag"]}...{a.data["tag"]}'),
                ]
            return Candidate(a.data['tag'], data=dict(a.data, version=a.version), links=links)

        item.candidates = pick_candidates(cur, cur, avail, make)

    def edits(self, item, cand):
        d, entry = item.data, item.data['entry']
        out = []
        new_commit = cand.data.get('commit')
        new_version = cand.data.get('version')
        new_tag = cand.data.get('tag')

        def var_edits(found, value):
            for rel, m in found:
                a, b = m.span('val')
                out.append(Edit(rel, a, b, self.index.text(rel)[a:b], value))

        if d['commit_found'] and new_commit:
            var_edits(d['commit_found'], new_commit)
        if d['version_found'] and new_version:
            var_edits(d['version_found'], fill(entry.get('var_format', '{version}'), version=new_version))
        if d['sha_found'] or d['add_found']:
            url = fill(
                entry.get('archive', DEFAULT_ARCHIVE),
                repo=entry.get('repo', ''),
                commit=new_commit or '',
                tag=new_tag or '',
                version=new_version or '',
            )
            if '{' in url:
                raise PinError(f'archive URL has unfilled placeholders: {url}')
            sha = self.net.url_sha256(url)
            var_edits(d['sha_found'], sha)
            for rel, m in d['add_found']:
                a, b = m.span('sha')
                out.append(Edit(rel, a, b, self.index.text(rel)[a:b], sha))
        if d['track'] == 'tag' and entry.get('ref') is not None:
            out.append(self.catalog.value_edit(('source_pins', item.name, 'ref'), new_tag))
        # keep "owner/repo <ref>" comments next to the pin in step with it
        if d['track'] == 'tag' and entry.get('repo'):
            old_lit, new_lit = f'{entry["repo"]} {d["cur_tag"]}', f'{entry["repo"]} {new_tag}'
            for rel in sorted({rel for rel, _ in d['commit_found'] + d['version_found']}):
                text = self.index.text(rel)
                for m in re.finditer(re.escape(old_lit) + r'(?![\w.-])', text):
                    out.append(Edit(rel, m.start(), m.end(), old_lit, new_lit))
        return out
