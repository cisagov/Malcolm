# Copyright (c) 2026 Battelle Energy Alliance, LLC.  All rights reserved.

"""FROM / COPY --from image references in Dockerfiles, and image= references in workflows."""

import re

from ..base import Checker, entry_flags
from ..core import Avail, Candidate, Edit, Item, PinError, is_dockerfile, is_workflow, pick_candidates

FROM_RE = re.compile(r'(?mi)^[ \t]*FROM[ \t]+(?:--platform=\S+[ \t]+)?(?P<ref>[^\s]+)(?:[ \t]+AS[ \t]+(?P<stage>\S+))?')
COPY_FROM_RE = re.compile(r'(?mi)^[ \t]*COPY\b[^\n]*?--from=(?P<ref>[^\s]+)')
WORKFLOW_IMAGE_RE = re.compile(r'\bimage=(?P<ref>[^\s"\',]+)')
TAG_SHAPE_RE = re.compile(r'^(?P<prefix>[^\d]*)(?P<nums>\d+(?:\.\d+)*)(?P<suffix>.*)$')


def parse_ref(ref):
    """'ghcr.io/x/y:tag@sha256:...' -> (name_as_written, registry, repo, tag, digest)"""
    digest = None
    if '@' in ref:
        ref, digest = ref.split('@', 1)
    tag = None
    last = ref.rsplit('/', 1)[-1]
    if ':' in last:
        ref, tag = ref.rsplit(':', 1)
    first = ref.split('/', 1)[0]
    if '/' in ref and ('.' in first or ':' in first or first == 'localhost'):
        registry, repo = ref.split('/', 1)
    else:
        registry, repo = 'docker.io', ref
    if registry == 'docker.io' and '/' not in repo:
        repo = f'library/{repo}'
    return ref, registry, repo, tag, digest


def tag_shape(tag):
    m = TAG_SHAPE_RE.match(tag or '')
    if not m:
        return None
    return m.group('prefix'), tuple(int(x) for x in m.group('nums').split('.')), m.group('suffix')


def registry_page(registry, repo):
    if registry == 'docker.io':
        return (
            f'https://hub.docker.com/_/{repo[8:]}/tags'
            if repo.startswith('library/')
            else f'https://hub.docker.com/r/{repo}/tags'
        )
    if registry == 'ghcr.io':
        return f'https://ghcr.io/{repo}'
    if registry == 'quay.io':
        return f'https://quay.io/repository/{repo}?tab=tags'
    if registry == 'docker.elastic.co':
        return f'https://www.docker.elastic.co/r/{repo}'
    return None


class DockerImages(Checker):
    category = 'docker-images'
    title = 'Container images (FROM, COPY --from, BuildKit)'

    def discover(self):
        occurrences = {}
        for rel in self.index.text_files(lambda p: is_dockerfile(p) or is_workflow(p)):
            text = self.index.text(rel)
            found = []
            if is_dockerfile(rel):
                stages = {m.group('stage').lower() for m in FROM_RE.finditer(text) if m.group('stage')}
                for regex in (FROM_RE, COPY_FROM_RE):
                    for m in regex.finditer(text):
                        ref = m.group('ref')
                        if ref.lower() in stages or ref.isdigit() or ref == 'scratch' or '$' in ref:
                            continue
                        found.append((m.start('ref'), m.end('ref'), ref))
            else:
                for m in WORKFLOW_IMAGE_RE.finditer(text):
                    ref = m.group('ref')
                    if '$' not in ref and ('/' in ref or ':' in ref):
                        found.append((m.start('ref'), m.end('ref'), ref))
            for start, end, ref in found:
                occurrences.setdefault(ref, []).append((rel, start, end))

        overrides = self.catalog.section('docker_images')
        items = []
        for ref, spans in sorted(occurrences.items()):
            name, registry, repo, tag, digest = parse_ref(ref)
            entry = overrides.get(name) or {}
            item = Item(self.category, name, (tag or '(no tag)') + (f'@{digest[:19]}…' if digest else ''))
            item.locations = [self.index.location(rel, start) for rel, start, _ in spans]
            item.data.update(ref=ref, spans=spans, registry=registry, repo=repo, tag=tag, digest=digest, entry=entry)
            entry_flags(item, entry)
            page = registry_page(registry, repo)
            if page:
                item.links.append(('registry', page))
            if entry.get('ignore'):
                item.data['ignored'] = str(entry['ignore'])
                item.notes.append(f'ignored: {entry["ignore"]}')
            mode = entry.get('track')
            shape = tag_shape(tag)
            if not mode:
                if digest:
                    mode = 'exact+digest' if shape and len(shape[1]) >= 3 else 'digest'
                elif not tag or tag == 'latest' or not shape:
                    mode = 'unpinned'
                elif len(shape[1]) >= 3:
                    mode = 'exact'
                else:
                    mode = 'floating'
            item.data['mode'] = mode
            if mode == 'unpinned' and not item.data.get('ignored'):
                item.notes.append('no version tag or digest; add a pin or an ignore entry in pins.yml')
                item.report_only = True
            if mode == 'floating':
                item.notes.append(
                    'floating tag (updates within it already flow in); a candidate here is a new release line'
                )
            items.append(item)
        return items

    def lookup(self, item):
        d = item.data
        if d.get('ignored') or d['mode'] == 'unpinned':
            return
        registry, repo, tag, digest, mode = d['registry'], d['repo'], d['tag'], d['digest'], d['mode']
        entry = d['entry']
        notes_tpl = entry.get('release_notes')
        shape = tag_shape(tag)
        cands = []
        if mode in ('exact', 'floating', 'exact+digest') and shape:
            prefix, nums, suffix = shape
            avail = []
            for t in self.net.registry_tags(registry, repo):
                s = tag_shape(t)
                if s and s[0] == prefix and s[2] == suffix and len(s[1]) == len(nums):
                    avail.append(Avail(t, s[1], s[1], {'tag': t}))

            def make(a):
                c = Candidate(a.version, data={'tag': a.data['tag']})
                if notes_tpl:
                    ver = '.'.join(map(str, a.key))
                    c.links.append(('release notes', notes_tpl.format(tag=a.data['tag'], version=ver)))
                return c

            cands = pick_candidates(nums, nums, avail, make)
        if mode in ('digest', 'exact+digest') and tag:
            live = self.net.registry_digest(registry, repo, tag)
            d['live_digest'] = live
            if digest and live != digest:
                cands.append(
                    Candidate(f'{tag}@{live[:19]}…', label='same tag, new digest', data={'tag': tag, 'digest': live})
                )
        item.candidates = cands

    def edits(self, item, cand):
        d = item.data
        new_tag = cand.data['tag']
        new_ref = f'{item.name}:{new_tag}'
        if d['mode'] in ('digest', 'exact+digest'):
            digest = cand.data.get('digest') or self.net.registry_digest(d['registry'], d['repo'], new_tag)
            new_ref += f'@{digest}'
        out = []
        for rel, start, end in d['spans']:
            old = self.index.text(rel)[start:end]
            if old != d['ref']:
                raise PinError(f'{rel}: expected {d["ref"]} at offset {start}')
            out.append(Edit(rel, start, end, old, new_ref))
        return out
