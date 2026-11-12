# Copyright (c) 2026 Battelle Energy Alliance, LLC.  All rights reserved.

"""Run context and the Checker interface every category implements."""

import concurrent.futures
from dataclasses import dataclass, field

from .core import PinError


@dataclass
class Context:
    root: object
    catalog: object
    net: object
    index: object
    include_prereleases: bool = False
    jobs: int = 8
    verbose: bool = False
    only: object = None  # compiled regex or None
    extras: dict = field(default_factory=dict)


class Checker:
    category = ''
    title = ''

    def __init__(self, ctx):
        self.ctx = ctx

    @property
    def catalog(self):
        return self.ctx.catalog

    @property
    def net(self):
        return self.ctx.net

    @property
    def index(self):
        return self.ctx.index

    def discover(self):
        """Find the pins in the source tree (no network)."""
        raise NotImplementedError

    def lookup(self, item):
        """Fill item.candidates from upstream, or raise PinError."""
        raise NotImplementedError

    def edits(self, item, candidate):
        """Edits that move item to candidate (may download to compute digests)."""
        raise NotImplementedError

    def finalize(self, selections):
        """[(item, candidate)] -> edits; categories that rewrite whole files override this."""
        out = []
        for item, cand in selections:
            out.extend(self.edits(item, cand))
        return out

    def run(self):
        try:
            items = self.discover()
        except PinError as e:
            return [], [f'{self.category}: {e}']
        if self.ctx.only is not None:
            items = [i for i in items if self.ctx.only.search(i.name)]

        def work(item):
            if item.error:
                return
            try:
                self.lookup(item)
            except PinError as e:
                item.error = str(e)
            except Exception as e:  # keep one bad lookup from ending the run
                item.error = f'{type(e).__name__}: {e}'

        with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, self.ctx.jobs)) as pool:
            list(pool.map(work, items))
        return items, []


def entry_flags(item, entry):
    """Apply the hold/group/report_only/note keys common to every catalog entry."""
    if not entry:
        return
    if entry.get('hold'):
        item.hold = str(entry['hold'])
    if entry.get('group'):
        item.group = str(entry['group'])
    if entry.get('report_only'):
        item.report_only = True
    if entry.get('note'):
        item.notes.append(str(entry['note']))
