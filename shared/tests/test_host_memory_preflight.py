#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2026 Battelle Energy Alliance, LLC.  All rights reserved.

"""Tests for the installer's read-only host memory warning."""

import sys
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from scripts.installer.utils import host_memory_preflight as preflight  # noqa: E402
from scripts.malcolm_constants import (  # noqa: E402
    DATABASE_MODE_LABELS,
    PROFILE_HEDGEHOG,
    PROFILE_MALCOLM,
    DatabaseMode,
    OrchestrationFramework,
)

GIB = 1024**3


@pytest.mark.parametrize('gib', [4, 8, 16, 21.9])
def test_clearly_undersized_host_warns(gib):
    warning = preflight.low_memory_warning(int(gib * GIB), swap_kib=0)
    assert f'about {round(gib)} GiB' in warning
    assert 'at least 24 GiB' in warning
    assert 'No swap space is configured' in warning


@pytest.mark.parametrize('gib', [22, 23.4, 24, 32, 96])
def test_host_at_or_near_minimum_does_not_warn(gib):
    # a host with 24 GiB installed reports somewhat less (e.g. ~23.4 GiB MemTotal on Linux)
    assert preflight.low_memory_warning(int(gib * GIB), swap_kib=0) is None


@pytest.mark.parametrize('value', [0, -1, None, 'not-a-number'])
def test_unknown_memory_does_not_warn(value):
    assert preflight.low_memory_warning(value, swap_kib=0) is None


def test_swap_wording():
    assert 'does not substitute' in preflight.low_memory_warning(8 * GIB, swap_kib=2048)
    unknown = preflight.low_memory_warning(8 * GIB, swap_kib=None)
    assert 'swap' not in unknown.lower()


def test_linux_swap_detection_and_read_errors(tmp_path):
    meminfo = tmp_path / 'meminfo'
    with mock.patch.object(preflight.sys, 'platform', 'linux'):
        meminfo.write_text('MemTotal:       8192000 kB\nSwapTotal: 0 kB\n')
        assert preflight.linux_swap_total_kib(str(meminfo)) == 0
        meminfo.write_text('SwapTotal: 2048000 kB\n')
        assert preflight.linux_swap_total_kib(str(meminfo)) == 2048000
        meminfo.write_text('SwapTotal: not-a-number kB\n')
        assert preflight.linux_swap_total_kib(str(meminfo)) is None
        assert preflight.linux_swap_total_kib(str(meminfo) + '-missing') is None
    with mock.patch.object(preflight.sys, 'platform', 'darwin'):
        assert preflight.linux_swap_total_kib(str(meminfo)) is None


LOCAL = DATABASE_MODE_LABELS[DatabaseMode.OpenSearchLocal]
REMOTE = DATABASE_MODE_LABELS[DatabaseMode.OpenSearchRemote]
ELASTIC = DATABASE_MODE_LABELS[DatabaseMode.ElasticsearchRemote]


@pytest.mark.parametrize(
    'profile,orchestration,os_mode,expected',
    [
        (PROFILE_MALCOLM, OrchestrationFramework.DOCKER_COMPOSE, LOCAL, True),
        (PROFILE_MALCOLM, OrchestrationFramework.DOCKER_COMPOSE, None, True),
        (PROFILE_MALCOLM, OrchestrationFramework.DOCKER_COMPOSE, DatabaseMode.OpenSearchLocal, True),
        (PROFILE_MALCOLM, OrchestrationFramework.DOCKER_COMPOSE, REMOTE, False),
        (PROFILE_MALCOLM, OrchestrationFramework.DOCKER_COMPOSE, ELASTIC, False),
        (PROFILE_MALCOLM, OrchestrationFramework.KUBERNETES, LOCAL, False),
        (PROFILE_HEDGEHOG, OrchestrationFramework.DOCKER_COMPOSE, LOCAL, False),
    ],
)
def test_check_applies_only_to_full_local_stack(profile, orchestration, os_mode, expected):
    assert preflight.host_memory_check_applies(profile, orchestration, os_mode) is expected
