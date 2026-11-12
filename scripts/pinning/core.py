# Copyright (c) 2026 Battelle Energy Alliance, LLC.  All rights reserved.

"""Data model and shared helpers for update_pins.py."""

import fnmatch
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Optional

SHA1_RE = re.compile(r'^[0-9a-f]{40}$')
SHA256_RE = re.compile(r'^[0-9a-f]{64}$')

# scopes a candidate can satisfy, narrowest last
SCOPE_ANY = 'any'
SCOPE_MAJOR = 'major'
SCOPE_MINOR = 'minor'
SCOPE_ORDER = {SCOPE_ANY: 0, SCOPE_MAJOR: 1, SCOPE_MINOR: 2}


class PinError(Exception):
    """A lookup or update failed for one item; reported without aborting the run."""


@dataclass
class Location:
    path: str  # relative to the source root
    line: int  # 1-based
    text: str  # the matched line, stripped

    def __str__(self):
        return f'{self.path}:{self.line}'


@dataclass
class Edit:
    path: str
    start: int  # character offsets into the original file text
    end: int
    old: str
    new: str


@dataclass
class Candidate:
    version: str  # what the user sees
    scope: str = SCOPE_ANY  # narrowest scope this candidate stays within
    label: str = ''
    links: list = field(default_factory=list)  # [(label, url)]
    data: dict = field(default_factory=dict)  # checker-specific resolution


@dataclass
class Item:
    category: str
    name: str
    current: str
    locations: list = field(default_factory=list)
    candidates: list = field(default_factory=list)
    links: list = field(default_factory=list)
    notes: list = field(default_factory=list)
    hold: Optional[str] = None
    group: Optional[str] = None
    report_only: bool = False
    error: Optional[str] = None
    data: dict = field(default_factory=dict)

    @property
    def status(self):
        if self.error:
            return 'error'
        if self.candidates and self.hold:
            return 'held'
        if self.candidates:
            return 'update'
        return 'current'

    def to_json(self):
        return {
            'category': self.category,
            'name': self.name,
            'current': self.current,
            'status': self.status,
            'hold': self.hold,
            'group': self.group,
            'report_only': self.report_only,
            'error': self.error,
            'notes': self.notes,
            'links': [{'label': l, 'url': u} for l, u in self.links],
            'locations': [str(l) for l in self.locations],
            'candidates': [
                {
                    'version': c.version,
                    'scope': c.scope,
                    'label': c.label,
                    'links': [{'label': l, 'url': u} for l, u in c.links],
                }
                for c in self.candidates
            ],
        }


###################################################################################################
# versions


@dataclass
class Avail:
    """One available upstream version."""

    version: str  # display string (bare version, tag, etc.)
    key: Any  # sortable
    release: tuple  # numeric components used for major/minor scoping
    data: dict = field(default_factory=dict)


def num_tuple(version):
    """'v1.2.10-1' -> (1, 2, 10, 1); used for ordering non-PEP 440 version strings."""
    return tuple(int(x) for x in re.findall(r'\d+', version or ''))


def avail_from_strings(pairs):
    """[(version_string, data)] -> [Avail] keyed by numeric tuple."""
    return [Avail(v, num_tuple(v), num_tuple(v), d) for v, d in pairs]


def pick_candidates(current_release, current_key, available, make_candidate):
    """
    From the available versions newer than the current one, offer the newest overall, the newest
    within the current major, and the newest within the current minor (whichever are distinct).
    make_candidate(avail) -> Candidate; scope and default label are filled in here.
    """
    newer = [a for a in available if current_key is None or a.key > current_key]
    if not newer:
        return []
    newer.sort(key=lambda a: a.key, reverse=True)
    cur = tuple(current_release or ())

    def scope_of(a):
        if len(cur) >= 2 and tuple(a.release[:2]) == cur[:2]:
            return SCOPE_MINOR
        if cur and tuple(a.release[:1]) == cur[:1]:
            return SCOPE_MAJOR
        return SCOPE_ANY

    picks = [(newer[0], 'newest')]
    in_major = next((a for a in newer if scope_of(a) in (SCOPE_MAJOR, SCOPE_MINOR)), None)
    in_minor = next((a for a in newer if scope_of(a) == SCOPE_MINOR), None)
    for avail, label in ((in_major, 'newest in current major'), (in_minor, 'newest in current minor')):
        if avail is not None and all(avail is not p for p, _ in picks):
            picks.append((avail, label))
    out = []
    for avail, label in picks:
        cand = make_candidate(avail)
        cand.scope = scope_of(avail)
        cand.label = cand.label or label
        out.append(cand)
    return out


def template_regex(template, field_name='version'):
    """'v{version}' -> regex matching 'v1.2.3' with a named group for the numeric version."""
    parts = re.split(r'(\{' + field_name + r'\})', template)
    out = []
    for p in parts:
        if p == '{' + field_name + '}':
            out.append(r'(?P<' + field_name + r'>\d+(?:\.\d+)*)')
        else:
            out.append(re.escape(p))
    return re.compile('^' + ''.join(out) + '$')


def fill(template, **values):
    """str.format-style fill that leaves unknown {placeholders} alone."""

    def repl(m):
        k = m.group(1)
        return str(values[k]) if k in values else m.group(0)

    return re.sub(r'\{(\w+)\}', repl, template)


###################################################################################################
# source tree


BINARY_EXTENSIONS = {
    '.7z',
    '.bin',
    '.bmp',
    '.deb',
    '.eot',
    '.gif',
    '.gz',
    '.ico',
    '.iso',
    '.jpeg',
    '.jpg',
    '.pcap',
    '.pcapng',
    '.pdf',
    '.pf2',
    '.png',
    '.pyc',
    '.so',
    '.tar',
    '.tgz',
    '.ttf',
    '.webp',
    '.whl',
    '.woff',
    '.woff2',
    '.xz',
    '.zip',
}


class FileIndex:
    """Lazy index of the text files under the source root."""

    def __init__(self, root, exclude_dirs, exclude_paths=(), max_bytes=2 * 1024 * 1024):
        self.root = Path(root)
        self.exclude_dirs = set(exclude_dirs)
        self.exclude_paths = list(exclude_paths)
        self.max_bytes = max_bytes
        self._paths = None
        self._text = {}

    def paths(self):
        if self._paths is None:
            found = []
            for dirpath, dirnames, filenames in os.walk(self.root):
                rel_dir = os.path.relpath(dirpath, self.root)
                dirnames[:] = sorted(
                    d
                    for d in dirnames
                    if d not in self.exclude_dirs
                    and os.path.normpath(os.path.join(rel_dir, d)) not in self.exclude_dirs
                )
                for name in sorted(filenames):
                    full = os.path.join(dirpath, name)
                    rel = os.path.normpath(os.path.relpath(full, self.root))
                    if os.path.splitext(name)[1].lower() in BINARY_EXTENSIONS:
                        continue
                    if any(fnmatch.fnmatchcase(rel, pat) for pat in self.exclude_paths):
                        continue
                    try:
                        if os.path.islink(full) or os.path.getsize(full) > self.max_bytes:
                            continue
                    except OSError:
                        continue
                    found.append(rel)
            self._paths = found
        return self._paths

    def text(self, rel):
        if rel not in self._text:
            try:
                raw = (self.root / rel).read_bytes()
                self._text[rel] = None if b'\0' in raw[:8192] else raw.decode('utf-8')
            except (OSError, UnicodeDecodeError):
                self._text[rel] = None
        return self._text[rel]

    def text_files(self, predicate=None):
        for rel in self.paths():
            if predicate and not predicate(rel):
                continue
            if self.text(rel) is not None:
                yield rel

    def find(self, regex, predicate=None, needle=None):
        """Yield (rel, match) for every regex match in the indexed text files."""
        for rel in self.text_files(predicate):
            text = self.text(rel)
            if needle and needle not in text:
                continue
            for m in regex.finditer(text):
                yield rel, m

    def location(self, rel, offset):
        text = self.text(rel)
        line_no = text.count('\n', 0, offset) + 1
        start = text.rfind('\n', 0, offset) + 1
        end = text.find('\n', offset)
        end = len(text) if end < 0 else end
        return Location(rel, line_no, text[start:end].strip())


def is_dockerfile(rel):
    name = os.path.basename(rel)
    return name == 'Dockerfile' or name.endswith('.Dockerfile') or name.startswith('Dockerfile.')


def is_workflow(rel):
    return rel.startswith(os.path.join('.github', 'workflows') + os.sep) and rel.endswith(('.yml', '.yaml'))


def assignment_regex(var):
    """
    Matches an assignment of var in a Dockerfile (ENV/ARG), shell script, env file or Makefile,
    with the value (minus any surrounding quotes) in the 'val' group.
    """
    return re.compile(
        r'(?m)^[ \t]*(?:(?:ENV|ARG|export|readonly|local|declare)[ \t]+)?'
        + re.escape(var)
        + r'[ \t]*[?:]?=[ \t]*(?P<q>["\']?)(?P<val>[^"\'\s\\]*)(?P=q)'
    )


def find_assignments(index, var):
    """
    [(rel, match)] for every assignment of var across the tree, skipping assignments that only
    re-export another variable (ENV FOO=$FOO after ARG FOO=...).
    """
    return [(rel, m) for rel, m in index.find(assignment_regex(var), needle=var) if not m.group('val').startswith('$')]


def instruction_blocks(text):
    """
    Yield (start, end) spans of logical lines: a line plus any lines joined to it by a trailing
    backslash. Works for Dockerfile instructions and shell commands.
    """
    pos = 0
    n = len(text)
    while pos < n:
        start = pos
        while True:
            nl = text.find('\n', pos)
            line_end = n if nl < 0 else nl
            pos = n if nl < 0 else nl + 1
            if not text[start:line_end].rstrip().endswith('\\') or pos >= n:
                break
        yield start, line_end


###################################################################################################
# applying edits


def apply_edits(root, edits, dry_run=False):
    """Apply edits grouped by file. Every edit is checked against the original text first."""
    by_path = {}
    for e in edits:
        by_path.setdefault(e.path, []).append(e)
    changed = []
    for rel, file_edits in sorted(by_path.items()):
        full = Path(root) / rel
        text = full.read_text(encoding='utf-8') if full.exists() else ''
        # de-duplicate identical edits (the same span reached through two items)
        unique = {(e.start, e.end, e.new): e for e in file_edits}.values()
        ordered = sorted(unique, key=lambda e: (e.start, e.end))
        for a, b in zip(ordered, ordered[1:]):
            if b.start < a.end:
                raise PinError(f'overlapping edits in {rel} at offsets {a.start} and {b.start}')
        for e in ordered:
            if text[e.start : e.end] != e.old:
                raise PinError(f'{rel} changed since it was scanned (expected {e.old!r} at offset {e.start})')
        new_text = text
        for e in reversed(ordered):
            new_text = new_text[: e.start] + e.new + new_text[e.end :]
        if new_text != text:
            changed.append(rel)
            if not dry_run:
                full.write_text(new_text, encoding='utf-8')
    return changed


def unified_diff(root, edits):
    """Render the edits as a unified diff without touching the files."""
    import difflib

    by_path = {}
    for e in edits:
        by_path.setdefault(e.path, []).append(e)
    chunks = []
    for rel, file_edits in sorted(by_path.items()):
        full = Path(root) / rel
        text = full.read_text(encoding='utf-8') if full.exists() else ''
        unique = sorted({(e.start, e.end, e.new): e for e in file_edits}.values(), key=lambda e: e.start)
        new_text = text
        for e in reversed(unique):
            new_text = new_text[: e.start] + e.new + new_text[e.end :]
        chunks.extend(
            difflib.unified_diff(
                text.splitlines(keepends=True),
                new_text.splitlines(keepends=True),
                fromfile=f'a/{rel}',
                tofile=f'b/{rel}',
            )
        )
    return ''.join(chunks)


def line_span(text, offset):
    """(start, end) of the full line containing offset, including its newline."""
    start = text.rfind('\n', 0, offset) + 1
    end = text.find('\n', offset)
    return start, (len(text) if end < 0 else end + 1)


def make_value_edit(index, rel, match, group, new_value):
    start, end = match.span(group)
    return Edit(rel, start, end, index.text(rel)[start:end], new_value)


Resolver = Callable[[Item, Candidate], list]
