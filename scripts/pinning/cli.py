# Copyright (c) 2026 Battelle Energy Alliance, LLC.  All rights reserved.

import argparse
import json
import os
import re
import sys
from pathlib import Path

from .base import Checker, Context
from .catalog import Catalog
from .checkers import CHECKERS
from .core import FileIndex, PinError, apply_edits, unified_diff
from .net import Net
from .ui import Chooser, Style, render_report

CATEGORY_FLAGS = {
    'docker-images': ['--docker-images', '--docker-from'],
    'github-actions': ['--github-actions'],
    'binaries': ['--binaries'],
    'source-pins': ['--source-pins'],
    'zeek-packages': ['--zeek-packages'],
    'python': ['--python', '--python-requirements'],
    'other': ['--other'],
}

EPILOG = """
Without --apply nothing is written: the report lists every pin with an update, the files it
lives in, and links to the upstream release notes and diffs.

With --apply you're asked, one pin at a time, which version to move to; the version strings,
commit SHAs and SHA-256 digests in every affected file are then updated together. --yes skips
the questions and takes the newest version allowed by --policy. Held pins (hold: in pins.yml)
are never applied unless --include-held is given.

examples:
  update_pins.py                              # report everything
  update_pins.py --binaries --source-pins     # report two categories
  update_pins.py --python --only '^requests$' # one package
  update_pins.py --github-actions --apply     # choose action updates interactively
  update_pins.py --zeek-packages --apply --yes   # what zeek_packages_lock_refresh.sh did
"""


def parse_args(argv):
    default_root = Path(__file__).resolve().parents[2]
    p = argparse.ArgumentParser(
        prog='update_pins.py',
        description="Find (and optionally apply) updates for Malcolm's pinned third-party dependencies.",
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument('--root', type=Path, default=default_root, help=f'source tree root (default: {default_root})')
    p.add_argument('--catalog', type=Path, help='pin catalog (default: <root>/shared/pins/pins.yml)')
    cats = p.add_argument_group('categories (default: all)')
    for cat, flags in CATEGORY_FLAGS.items():
        cats.add_argument(*flags, dest='cat_' + cat.replace('-', '_'), action='store_true', help=f'check {cat}')
    p.add_argument('--only', metavar='REGEX', help='only pins whose name matches REGEX')
    p.add_argument('--apply', action='store_true', help='choose and write updates (default is a dry-run report)')
    p.add_argument('--yes', action='store_true', help='with --apply, take updates without asking (see --policy)')
    p.add_argument(
        '--policy',
        choices=['latest', 'major', 'minor'],
        default='latest',
        help='with --yes: newest overall, newest in the current major, or newest in the current minor (default: latest)',
    )
    p.add_argument('--include-held', action='store_true', help='allow held pins to be applied')
    p.add_argument('--preview', action='store_true', help='with --apply, print the changes as a diff and write nothing')
    p.add_argument('--pre', action='store_true', help='consider pre-releases')
    p.add_argument('--show-current', action='store_true', help='also list pins that are up to date')
    p.add_argument('--json', action='store_true', help='print the report as JSON')
    p.add_argument('--exit-code', action='store_true', help='exit 10 when any update is available (for CI)')
    p.add_argument('--jobs', type=int, default=8, help='parallel lookups (default: 8)')
    p.add_argument(
        '--github-token',
        default=os.environ.get('GITHUB_TOKEN') or os.environ.get('GH_TOKEN'),
        help='GitHub token (default: $GITHUB_TOKEN or $GH_TOKEN)',
    )
    p.add_argument('--no-color', action='store_true', help='plain output')
    p.add_argument('-v', '--verbose', action='store_true', help='log network requests to stderr')
    args = p.parse_args(argv)
    if args.yes and not args.apply:
        p.error('--yes needs --apply')
    if args.preview and not args.apply:
        p.error('--preview needs --apply')
    return args


def main(argv=None):
    try:
        return _main(argv)
    except KeyboardInterrupt:
        print('\ninterrupted; nothing was written', file=sys.stderr)
        return 130


def _main(argv):
    args = parse_args(argv)
    root = args.root.resolve()
    st = Style(sys.stdout.isatty() and not args.no_color and not args.json)
    try:
        catalog = Catalog(args.catalog or root / 'shared' / 'pins' / 'pins.yml', root)
    except (PinError, OSError) as e:
        print(f'error: {e}', file=sys.stderr)
        return 2
    if not args.github_token and not args.json:
        print('note: no GitHub token set; API lookups are limited to 60 requests per hour', file=sys.stderr)
    dockerhub = None
    if os.environ.get('DOCKERHUB_USERNAME') and os.environ.get('DOCKERHUB_TOKEN'):
        dockerhub = (os.environ['DOCKERHUB_USERNAME'], os.environ['DOCKERHUB_TOKEN'])
    ctx = Context(
        root=root,
        catalog=catalog,
        net=Net(github_token=args.github_token, dockerhub_auth=dockerhub, verbose=args.verbose),
        index=FileIndex(root, catalog.exclude_dirs, catalog.exclude_paths),
        include_prereleases=args.pre,
        jobs=args.jobs,
        verbose=args.verbose,
        only=re.compile(args.only) if args.only else None,
    )
    selected = [c for c in CHECKERS if getattr(args, 'cat_' + c.category.replace('-', '_'))] or CHECKERS

    results = []
    for cls in selected:
        checker = cls(ctx)
        if not args.json:
            print(f'checking {checker.title}...', file=sys.stderr)
        items, errors = checker.run()
        results.append((checker, items, errors))

    any_errors = any(errors or any(i.error for i in items) for _, items, errors in results)
    any_updates = any(i.status == 'update' for _, items, _ in results for i in items)

    if args.json:
        print(
            json.dumps(
                {c.category: {'errors': e, 'items': [i.to_json() for i in items]} for c, items, e in results}, indent=2
            )
        )
        return 10 if args.exit_code and any_updates else (1 if any_errors else 0)

    if not args.apply:
        render_report(results, st, show_current=args.show_current)
        return 10 if args.exit_code and any_updates else (1 if any_errors else 0)

    if not args.yes and not sys.stdin.isatty():
        print('error: --apply asks questions on a terminal; use --yes to run unattended', file=sys.stderr)
        return 2

    chooser = Chooser(st, yes=args.yes, policy=args.policy)
    all_edits, applied, failures = [], [], []
    for checker, items, errors in results:
        for e in errors:
            failures.append(e)
        eligible = [
            i for i in items if i.candidates and not i.error and not i.report_only and (args.include_held or not i.hold)
        ]
        if not eligible:
            continue
        print(f'\n{st.bold("== " + checker.title + " ==")}')
        selections = []
        for item in sorted(eligible, key=lambda i: (i.group or '~', i.name.lower(), i.current)):
            cand = chooser.choose(item)
            if cand is not None:
                selections.append((item, cand))
            if chooser.quit:
                break
        if not selections:
            if chooser.quit:
                break
            continue
        if type(checker).finalize is not Checker.finalize:
            try:
                all_edits.extend(checker.finalize(selections))
                applied.extend(selections)
            except Exception as e:
                failures.append(f'{checker.category}: {e}')
        else:
            for item, cand in selections:
                try:
                    all_edits.extend(checker.edits(item, cand))
                    applied.append((item, cand))
                except Exception as e:  # report it and keep the other selections
                    failures.append(f'{item.name}: {e}')
        if chooser.quit:
            break

    if not all_edits:
        print('\nnothing to change')
        for f in failures:
            print(f'{st.red("error:")} {f}')
        return 1 if failures else 0

    if args.preview:
        sys.stdout.write(unified_diff(root, all_edits))
        changed = sorted({e.path for e in all_edits})
    else:
        try:
            changed = apply_edits(root, all_edits)
        except PinError as e:
            print(f'{st.red("error:")} {e}; nothing was written', file=sys.stderr)
            return 1

    print(f'\n{"would update" if args.preview else "updated"} {len(applied)} pin(s) in {len(changed)} file(s):')
    for rel in changed:
        print(f'  {rel}')
    follow_ups = [(i, n) for i, _ in applied for n in i.notes if i.data.get('entry', {}).get('note') == n]
    for item, note in follow_ups:
        print(f'  {st.yellow("follow-up")} {item.name}: {note}')
    for f in failures:
        print(f'{st.red("error:")} {f}')
    if not args.preview:
        print('\nreview with git diff, then build and run malcolm-test before committing')
    return 1 if failures else 0
