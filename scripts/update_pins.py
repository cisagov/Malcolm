#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2026 Battelle Energy Alliance, LLC.  All rights reserved.

"""
Find and apply updates for the third-party dependencies Malcolm pins: container images, GitHub
Actions, release binaries and their SHA-256 digests, source archives pinned by commit, Zeek
packages, Python requirements, and a few others. Upstream metadata lives in shared/pins/pins.yml.

Requires Python 3.10+, git, and the requests, packaging and PyYAML packages.
Run with --help for usage.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from pinning.cli import main  # noqa: E402

if __name__ == '__main__':
    sys.exit(main())
