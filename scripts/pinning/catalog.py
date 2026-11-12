# Copyright (c) 2026 Battelle Energy Alliance, LLC.  All rights reserved.

"""Loads shared/pins/pins.yml and locates scalar values in it so they can be edited in place."""

import os
from pathlib import Path

import yaml

from .core import Edit, PinError

DEFAULT_EXCLUDE_DIRS = ['.git', 'node_modules', '_site', '.venv', 'venv', '__pycache__', '.pytest_cache', 'docs']
SECTIONS = (
    'settings',
    'docker_images',
    'github_actions',
    'binaries',
    'source_pins',
    'python',
    'zeek_packages',
    'other',
)


class Catalog:
    def __init__(self, path, root):
        self.path = Path(path)
        self.root = Path(root)
        try:
            self.rel = os.path.relpath(self.path, self.root)
        except ValueError:
            self.rel = str(self.path)
        if self.path.exists():
            self.text = self.path.read_text(encoding='utf-8')
            self.data = yaml.safe_load(self.text) or {}
        else:
            self.text, self.data = '', {}
        unknown = set(self.data) - set(SECTIONS)
        if unknown:
            raise PinError(f'{self.path}: unknown top-level section(s): {", ".join(sorted(unknown))}')
        for s in SECTIONS:
            if self.data.get(s) is None:
                self.data[s] = {}
        self._node = yaml.compose(self.text) if self.text.strip() else None

    def section(self, name):
        return self.data.get(name) or {}

    def setting(self, key, default=None):
        return self.section('settings').get(key, default)

    @property
    def exclude_paths(self):
        return self.setting('exclude_paths', [])

    @property
    def exclude_dirs(self):
        return self.setting('exclude_dirs', DEFAULT_EXCLUDE_DIRS)

    def _find(self, node, keys):
        for k in keys:
            if node is None or not isinstance(node, yaml.MappingNode):
                return None
            match = None
            for knode, vnode in node.value:
                if knode.value == k:
                    match = vnode
                    break
            node = match
        return node

    def value_edit(self, keys, new_value):
        """Edit replacing the scalar at keys (e.g. ('source_pins', 'ecs', 'ref')) with new_value."""
        node = self._find(self._node, keys)
        if node is None or not isinstance(node, yaml.ScalarNode):
            raise PinError(f'{self.rel}: no scalar at {".".join(keys)}')
        start, end = node.start_mark.index, node.end_mark.index
        old = self.text[start:end]
        if old[:1] in ('"', "'"):
            quote = old[0]
            new = f'{quote}{new_value}{quote}'
        else:
            new = str(new_value)
            try:
                same = yaml.safe_load(new) == new_value
            except yaml.YAMLError:
                same = False
            # quote anything YAML would read differently, or that could start a comment or mapping
            if not same or ' #' in new or ': ' in new or new[:1] in '!&*?|>%@`{[,-#':
                new = '"' + new.replace('\\', '\\\\').replace('"', '\\"') + '"'
        return Edit(self.rel, start, end, old, new)
