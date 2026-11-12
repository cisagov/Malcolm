# Copyright (c) 2026 Battelle Energy Alliance, LLC.  All rights reserved.

"""Dry-run report and the interactive chooser for --apply."""

import sys

from .core import SCOPE_MAJOR, SCOPE_MINOR


class Style:
    def __init__(self, enabled):
        self.enabled = enabled

    def _c(self, code, s):
        return f'\033[{code}m{s}\033[0m' if self.enabled else s

    def bold(self, s):
        return self._c('1', s)

    def dim(self, s):
        return self._c('2', s)

    def green(self, s):
        return self._c('32', s)

    def yellow(self, s):
        return self._c('33', s)

    def red(self, s):
        return self._c('31', s)

    def cyan(self, s):
        return self._c('36', s)


def render_item(item, st, out, show_locations=True):
    tag = ''
    if item.hold:
        tag = st.yellow(f'  [held: {item.hold}]')
    elif item.report_only:
        tag = st.dim('  [report only]')
    if item.group:
        tag += st.dim(f'  [group: {item.group}]')
    print(f'  {st.bold(item.name)}  {item.current}{tag}', file=out)
    if item.error:
        print(f'    {st.red("error:")} {item.error}', file=out)
    for c in item.candidates:
        label = f'  {st.dim(c.label)}' if c.label else ''
        print(f'    {st.green("->")} {c.version}{label}', file=out)
        for name, url in c.links:
            print(f'         {name}: {st.cyan(url)}', file=out)
    for name, url in item.links:
        print(f'    {name}: {st.cyan(url)}', file=out)
    for note in item.notes:
        print(f'    {st.dim("note:")} {note}', file=out)
    if show_locations:
        for loc in sorted(item.locations, key=lambda l: (l.path, l.line)):
            print(f'    {st.dim(str(loc))}', file=out)


def render_report(results, st, show_current=False, out=None):
    """results: [(checker, items, errors)]"""
    out = out or sys.stdout
    totals = {'update': 0, 'held': 0, 'current': 0, 'error': 0}
    for checker, items, errors in results:
        for i in items:
            totals[i.status] += 1
        shown = [i for i in items if show_current or i.status != 'current' or (i.notes and i.report_only)]
        if not shown and not errors:
            if show_current:
                print(f'\n{st.bold("== " + checker.title + " ==")}\n  (nothing found)', file=out)
            continue
        print(f'\n{st.bold("== " + checker.title + " ==")}', file=out)
        for e in errors:
            print(f'  {st.red("error:")} {e}', file=out)
        for item in sorted(shown, key=lambda i: (i.group or '~', i.name.lower(), i.current)):
            render_item(item, st, out)
    print(
        f'\n{totals["update"]} with updates, {totals["held"]} held, {totals["current"]} up to date, {totals["error"]} errors',
        file=out,
    )
    return totals


def auto_choice(item, policy):
    for c in item.candidates:
        if policy == 'latest':
            return c
        if policy == 'major' and c.scope in (SCOPE_MAJOR, SCOPE_MINOR):
            return c
        if policy == 'minor' and c.scope == SCOPE_MINOR:
            return c
    return None


class Chooser:
    """Asks per item which candidate to apply. 'a' applies the newest to the rest of a category."""

    def __init__(self, st, yes=False, policy='latest', inp=input, out=None):
        self.st = st
        self.yes = yes
        self.policy = policy
        self.inp = inp
        self.out = out or sys.stdout
        self.auto_categories = set()
        self.quit = False

    def choose(self, item):
        if self.quit:
            return None
        if self.yes or item.category in self.auto_categories:
            return auto_choice(item, self.policy)
        print('', file=self.out)
        render_item(item, self.st, self.out)
        options = '  '.join(f'[{n}] {c.version}' for n, c in enumerate(item.candidates, 1))
        prompt = f'  {options}  [n] skip  [a] newest for rest of {item.category}  [q] quit  (n): '
        while True:
            try:
                answer = self.inp(prompt).strip().lower()
            except EOFError:
                answer = 'q'
            if answer in ('', 'n'):
                return None
            if answer == 'q':
                self.quit = True
                return None
            if answer == 'a':
                self.auto_categories.add(item.category)
                return auto_choice(item, 'latest')
            if answer.isdigit() and 1 <= int(answer) <= len(item.candidates):
                return item.candidates[int(answer) - 1]
            print('  please answer with a number, n, a or q', file=self.out)
