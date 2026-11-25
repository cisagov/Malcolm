"""Check subprocess lifetime during single-stream lzip extraction."""

import importlib.util
from pathlib import Path
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def extractor(monkeypatch):
    pytest.importorskip("libarchive.extract")
    pytest.importorskip("magic")
    monkeypatch.syspath_prepend(str(ROOT / "scripts"))
    spec = importlib.util.spec_from_file_location("safe_extract_lzip_test", ROOT / "scripts/safe-extract.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def child_process(extractor, monkeypatch):
    """Substitute a real, controlled child for the external lzip executable."""
    processes = []
    real_popen = subprocess.Popen

    def install(source):
        def spawn(command, **kwargs):
            assert command[:3] == ["lzip", "-d", "-c"]
            proc = real_popen([sys.executable, "-c", source], **kwargs)
            processes.append(proc)
            return proc

        monkeypatch.setattr(extractor.subprocess, "Popen", spawn)
        return processes

    yield install
    # Even a failing regression must not leave a real child behind.
    for proc in processes:
        if proc.poll() is None:
            proc.kill()
        proc.wait(timeout=5)
        proc.stdout.close()


def assert_reaped(processes):
    assert len(processes) == 1
    proc = processes[0]
    assert proc.returncode is not None
    assert proc.stdout.closed


def test_size_limit_reaps_child(extractor, child_process, tmp_path, monkeypatch):
    monkeypatch.setattr(extractor, "ARCHIVE_EXTRACT_MAX_TOTAL_BYTES", 10)
    processes = child_process("import sys; sys.stdout.buffer.write(b'x' * 32); sys.exit(0)")
    dest = tmp_path / "out"
    dest.mkdir()

    with pytest.raises(extractor.ArchiveBombError):
        extractor._extract_lzip(str(tmp_path / "sample.lz"), str(dest))

    assert_reaped(processes)


def test_output_error_reaps_child(extractor, child_process, tmp_path):
    processes = child_process("import time; time.sleep(30)")
    dest = tmp_path / "out"
    dest.mkdir()
    (dest / "sample").mkdir()

    with pytest.raises(IsADirectoryError):
        extractor._extract_lzip(str(tmp_path / "sample.lz"), str(dest))

    assert_reaped(processes)


def test_success_reaps_child(extractor, child_process, tmp_path):
    processes = child_process("import sys; sys.stdout.buffer.write(b'contents')")
    dest = tmp_path / "out"
    dest.mkdir()

    extractor._extract_lzip(str(tmp_path / "sample.lz"), str(dest))

    assert (dest / "sample").read_bytes() == b"contents"
    assert_reaped(processes)


def test_decoder_failure_reaps_child(extractor, child_process, tmp_path):
    processes = child_process("import sys; sys.exit(7)")
    dest = tmp_path / "out"
    dest.mkdir()

    with pytest.raises(subprocess.CalledProcessError) as error:
        extractor._extract_lzip(str(tmp_path / "sample.lz"), str(dest))

    assert error.value.returncode == 7
    assert_reaped(processes)
