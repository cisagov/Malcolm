#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (c) 2025 Battelle Energy Alliance, LLC.  All rights reserved.

# fstab interpreter

import os


class Fstab:
    """This class extends file in order to implement a file reader/writer
    for file `/etc/fstab`
    """

    class Entry(object):
        """Entry class represents a non-comment line on the `/etc/fstab` file"""

        def __init__(self, device, mountpoint, filesystem, options, fs_freq=0, fs_passno=0):
            self.device = device
            self.mountpoint = mountpoint
            self.filesystem = filesystem

            if not options:
                options = "defaults"

            self.options = options
            self.fs_freq = fs_freq
            self.fs_passno = fs_passno

        def __eq__(self, o):
            return str(self) == str(o)

        def __str__(self):
            return "{} {} {} {} {} {}".format(
                self.device, self.mountpoint, self.filesystem, self.options, self.fs_freq, self.fs_passno
            )

    DEFAULT_PATH = os.path.join(os.path.sep, 'etc', 'fstab')

    def __init__(self, path=None):
        if path:
            self._path = path
        else:
            self._path = self.DEFAULT_PATH
        self.f = open(self._path, 'r+')

    def __enter__(self):
        return self.f

    def __exit__(self, exc_type, exc_value, traceback):
        self.f.close()

    def _hydrate_entry(self, line):
        return Fstab.Entry(*[x for x in line.replace("\t", " ").strip("\n").split(" ") if x not in ('', None)])

    @property
    def entries(self):
        self.f.seek(0)
        for line in self.f.readlines():
            try:
                if not line.startswith("#"):
                    yield self._hydrate_entry(line)
            except ValueError:
                pass

    def get_entry_by_attr(self, attr, value):
        for entry in self.entries:
            e_attr = getattr(entry, attr)
            if e_attr == value:
                return entry
        return None

    def add_entry(self, entry):
        if self.get_entry_by_attr('device', entry.device):
            return False

        self.f.write(str(entry) + '\n')
        self.f.truncate()
        return entry

    def remove_entry(self, entry):
        self.f.seek(0)

        lines = self.f.readlines()

        found = False
        for index, line in enumerate(lines):
            if not line.startswith("#"):
                if self._hydrate_entry(line) == entry:
                    found = True
                    break

        if not found:
            return False

        lines.remove(line)

        self.f.seek(0)
        self.f.write(''.join(lines))
        self.f.truncate()
        return True

    @classmethod
    def remove_by_mountpoint(cls, mountpoint, path=None):
        fstab = cls(path=path)
        entry = fstab.get_entry_by_attr('mountpoint', mountpoint)
        if entry:
            return fstab.remove_entry(entry)
        return False

    @classmethod
    def add(cls, device, mountpoint, filesystem, options=None, fs_freq=0, fs_passno=0, path=None):
        return cls(path=path).add_entry(
            Fstab.Entry(device, mountpoint, filesystem, options=options, fs_freq=fs_freq, fs_passno=fs_passno)
        )
