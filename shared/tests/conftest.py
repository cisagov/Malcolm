"""Put each component's source directory on sys.path for the tests in shared/tests."""

import importlib.machinery
import importlib.util
import logging
import sys
import types
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]

# highest precedence first
SOURCE_DIRS = (
    REPO_ROOT / 'zeek' / 'scripts',
    REPO_ROOT / 'netbox' / 'control-scripts',
    REPO_ROOT / 'shared' / 'bin',
    REPO_ROOT / 'scripts',
    REPO_ROOT / 'filescan' / 'python-filescan',
    REPO_ROOT / 'dashboards' / 'scripts',
    REPO_ROOT / 'api',
)

sys.path[0:0] = [str(p) for p in SOURCE_DIRS if str(p) not in sys.path]


FILESCAN_WATCHER_PATH = REPO_ROOT / 'filescan' / 'python-filescan' / 'bin' / 'filescan_watcher'


class _AnyFSType(type):
    # FSType members are only used as dict keys at import time
    def __getattr__(cls, name):
        if name.startswith('__'):
            raise AttributeError(name)
        return name


def _statfs_stub():
    module = types.ModuleType('statfs')
    module.FSType = _AnyFSType('FSType', (), {})
    module.statfs = Mock(side_effect=AssertionError('statfs stub called'))
    return module


def _asyncclick_stub():
    def decorator_factory(*args, **kwargs):
        return lambda fn: fn

    module = types.ModuleType('asyncclick')
    module.ParamType = type('ParamType', (), {})
    module.Path = module.File = Mock()
    module.command = module.option = module.version_option = decorator_factory
    module.exceptions = types.SimpleNamespace(Exit=SystemExit)
    return module


@pytest.fixture(scope='module')
def filescan_watcher():
    """filescan/python-filescan/bin/filescan_watcher, loaded as a module.

    It's a script, so it's loaded from its path. Its statfs (a Cython extension built into the
    filescan image) and asyncclick imports are stubbed when they aren't installed; the rest of
    what it imports is in shared/tests/requirements.txt.
    """
    stubs = {}
    if importlib.util.find_spec('statfs') is None:
        stubs['statfs'] = _statfs_stub()
    if importlib.util.find_spec('asyncclick') is None:
        stubs['asyncclick'] = _asyncclick_stub()

    # the script calls basicConfig() at import time
    root = logging.getLogger()
    saved_handlers, saved_level = root.handlers[:], root.level
    # patch.dict restores sys.modules at teardown, so the stubs (and the filescan modules
    # imported against them) don't leak into other tests. Submodules imported in between are
    # also set as attributes on an already-imported filescan package, so remove those too.
    package = sys.modules.get('filescan')
    package_names = set(vars(package)) if package is not None else set()
    with patch.dict(sys.modules, stubs):
        loader = importlib.machinery.SourceFileLoader('filescan_watcher_under_test', str(FILESCAN_WATCHER_PATH))
        module = importlib.util.module_from_spec(importlib.util.spec_from_loader(loader.name, loader))
        # pydantic resolves the script's string annotations (AnyWatch and friends) through
        # sys.modules[cls.__module__], so the module has to be registered before it runs and
        # stay registered while these tests use it
        sys.modules[loader.name] = module
        try:
            loader.exec_module(module)
        finally:
            root.handlers[:] = saved_handlers
            root.setLevel(saved_level)
        yield module
    if package is not None:
        for name in set(vars(package)) - package_names:
            delattr(package, name)
