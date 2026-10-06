"""Cleanup runners must coordinate through a stable, kernel-locked file."""

import fcntl
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
from unittest.mock import Mock

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts'))
SCRIPT = ROOT / 'filebeat' / 'scripts' / 'clean-processed-folder.py'
SPEC = importlib.util.spec_from_file_location('cleanup_lock_subject', SCRIPT)
cleaner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(cleaner)


@pytest.fixture
def cleanup(monkeypatch, tmp_path):
    lock = tmp_path / 'cleanup.lock'
    prune = Mock()
    monkeypatch.setattr(cleaner, 'lock_filename', str(lock))
    monkeypatch.setattr(cleaner, 'prune_files', prune)
    monkeypatch.setattr(cleaner, 'set_logging', lambda *args, **kwargs: None)
    return lock, prune


def test_contender_does_not_unlink_another_runners_lock(cleanup):
    lock, prune = cleanup
    with lock.open('a') as owner:
        fcntl.flock(owner, fcntl.LOCK_EX | fcntl.LOCK_NB)
        inode = os.fstat(owner.fileno()).st_ino
        cleaner.main()
        prune.assert_not_called()
        assert lock.exists()
        assert lock.stat().st_ino == inode


def test_repeated_contenders_cannot_bypass_a_live_lock(cleanup):
    lock, prune = cleanup
    with lock.open('a') as owner:
        fcntl.flock(owner, fcntl.LOCK_EX | fcntl.LOCK_NB)
        for _ in range(3):
            cleaner.main()
        prune.assert_not_called()


def test_successful_runs_reuse_the_same_inode_and_hold_the_lock(cleanup):
    lock, prune = cleanup
    inode = None

    def check_held():
        with lock.open('a') as contender:
            with pytest.raises(BlockingIOError):
                fcntl.flock(contender, fcntl.LOCK_EX | fcntl.LOCK_NB)

    prune.side_effect = check_held
    for _ in range(3):
        cleaner.main()
        assert lock.exists()
        if inode is None:
            inode = lock.stat().st_ino
        assert lock.stat().st_ino == inode
    assert prune.call_count == 3


def test_pruning_exception_releases_lock_without_removing_inode(cleanup):
    lock, prune = cleanup
    lock.touch()
    inode = lock.stat().st_ino
    prune.side_effect = RuntimeError('isolated cleanup error')
    with pytest.raises(RuntimeError, match='isolated cleanup error'):
        cleaner.main()
    assert lock.exists()
    assert lock.stat().st_ino == inode
    with lock.open('a') as next_owner:
        fcntl.flock(next_owner, fcntl.LOCK_EX | fcntl.LOCK_NB)
    prune.side_effect = None
    cleaner.main()
    assert prune.call_count == 2


def test_separate_process_excluded_after_failed_contender(cleanup, tmp_path):
    lock, prune = cleanup
    marker = tmp_path / 'pruned'
    code = """
import importlib.util
from pathlib import Path
import sys
script, lock, marker = sys.argv[1:]
sys.path.insert(0, str(Path(script).resolve().parents[2] / 'scripts'))
spec = importlib.util.spec_from_file_location('isolated_cleanup', script)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
module.lock_filename = lock
module.set_logging = lambda *a, **kw: None
module.prune_files = lambda: Path(marker).write_text('ran')
module.main()
"""
    command = [sys.executable, '-c', code, str(SCRIPT), str(lock), str(marker)]
    with lock.open('a') as owner:
        fcntl.flock(owner, fcntl.LOCK_EX | fcntl.LOCK_NB)
        cleaner.main()
        completed = subprocess.run(command, capture_output=True, text=True, timeout=20, check=False)
        assert completed.returncode == 0, completed.stderr
        assert not marker.exists()
        prune.assert_not_called()
    completed = subprocess.run(command, capture_output=True, text=True, timeout=20, check=False)
    assert completed.returncode == 0, completed.stderr
    assert marker.read_text() == 'ran'


def test_uncontended_run_calls_cleanup_once(cleanup):
    _, prune = cleanup
    cleaner.main()
    prune.assert_called_once_with()


def test_first_contender_skips_cleanup(cleanup):
    lock, prune = cleanup
    with lock.open('a') as owner:
        fcntl.flock(owner, fcntl.LOCK_EX | fcntl.LOCK_NB)
        cleaner.main()
        prune.assert_not_called()
