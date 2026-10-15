"""Uploaded Zeek logs must not overwrite earlier uploads with the same name."""

import ast
import logging
import os
import pathlib
from pathlib import Path
import re
import shutil
from unittest import mock

import pytest

_SOURCE = Path(__file__).resolve().parents[2] / "filebeat/scripts/filebeat-watch-zeeklogs-uploads-folder.py"


def _load_file_processor():
    """Execute the actual worker function without container-only dependencies."""
    parsed = ast.parse(_SOURCE.read_text())
    function = next(node for node in parsed.body if isinstance(node, ast.FunctionDef) and node.name == "file_processor")
    modules = {
        "os": os,
        "re": re,
        "shutil": shutil,
        "time": mock.Mock(sleep=lambda _: None),
        "pathlib": pathlib,
        "magic": mock.Mock(
            from_file=lambda path, mime=False: (
                ("application/zip" if str(path).lower().endswith(".zip") else "application/gzip")
                if mime
                else "compressed archive"
            )
        ),
        "logging": logging,
        "scriptName": "filebeat-watch-zeeklogs-uploads-folder.py",
    }
    exec(compile(ast.Module(body=[function], type_ignores=[]), str(_SOURCE), "exec"), modules)
    return modules["file_processor"]


@pytest.fixture
def uploader(tmp_path):
    uploads = tmp_path / "upload"
    incoming = tmp_path / "staged"
    uploads.mkdir()
    incoming.mkdir()
    logger = mock.Mock()
    worker = _load_file_processor()

    def invoke(name, data, mime_types=("application/gzip", "application/zip")):
        source = incoming / name
        source.write_bytes(data)
        with mock.patch.object(os, "chown"):
            worker(
                str(source),
                mime_types=mime_types,
                file_types=[],
                uid=os.getuid(),
                gid=os.getgid(),
                destination=str(uploads),
                logger=logger,
            )
        return source

    return uploads, logger, invoke


def test_no_collision_preserves_original_filename_and_content(uploader):
    uploads, logger, invoke = uploader
    source = invoke("session.tar.gz", b"first")
    assert not source.exists()
    assert (uploads / "session.tar.gz").read_bytes() == b"first"
    logger.critical.assert_not_called()


@pytest.mark.parametrize("name", ["session.tar.gz", "conn.log.gz", "events.2026-10-15.zip"])
def test_existing_archive_is_not_overwritten(uploader, name):
    uploads, logger, invoke = uploader
    original = uploads / name
    original.write_bytes(b"first-upload")
    source = invoke(name, b"second-upload")
    assert not source.exists()
    assert original.read_bytes() == b"first-upload"
    extra = [p for p in uploads.iterdir() if p != original]
    assert len(extra) == 1
    assert extra[0].read_bytes() == b"second-upload"
    suffix = "".join(Path(name).suffixes)
    prefix = name[: -len(suffix)]
    # an all-digit segment is dropped by the tag splitting in filebeat-process-zeek-folder.sh
    assert re.fullmatch(re.escape(prefix) + r"\.[0-9]+" + re.escape(suffix), extra[0].name)
    logger.critical.assert_not_called()


def test_three_same_named_uploads_keep_all_three_payloads(uploader):
    uploads, logger, invoke = uploader
    name = "zeek-trace.tar.gz"
    (uploads / name).write_bytes(b"first")
    invoke(name, b"second")
    invoke(name, b"third")
    assert sorted(p.read_bytes() for p in uploads.iterdir()) == [b"first", b"second", b"third"]
    assert len(set(p.name for p in uploads.iterdir())) == 3
    logger.critical.assert_not_called()


def test_existing_same_named_directory_is_not_used_as_destination(uploader):
    uploads, logger, invoke = uploader
    directory = uploads / "capture.tar.gz"
    directory.mkdir()
    marker = directory / "keep.txt"
    marker.write_bytes(b"untouched")
    incoming = invoke("capture.tar.gz", b"new-archive")
    assert not incoming.exists()
    assert marker.read_bytes() == b"untouched"
    candidates = [p for p in uploads.iterdir() if p.is_file()]
    assert len(candidates) == 1
    assert candidates[0].name.endswith(".tar.gz")
    assert candidates[0].read_bytes() == b"new-archive"
    logger.critical.assert_not_called()


def test_dangling_symlink_destination_is_not_replaced(uploader):
    uploads, logger, invoke = uploader
    original = uploads / "conn.log.gz"
    original.symlink_to("nonexistent-target")
    source = invoke("conn.log.gz", b"capture")
    assert not source.exists()
    assert original.is_symlink()
    extra = [p for p in uploads.iterdir() if p != original]
    assert len(extra) == 1
    assert extra[0].name.endswith(".log.gz")
    assert extra[0].read_bytes() == b"capture"
    logger.critical.assert_not_called()


def test_unsupported_upload_is_deleted_without_touching_archive(uploader):
    uploads, logger, invoke = uploader
    existing = uploads / "trace.zip"
    existing.write_bytes(b"retained")
    source = invoke("trace.zip", b"unsupported", mime_types=())
    assert not source.exists()
    assert existing.read_bytes() == b"retained"
    logger.warning.assert_called_once()
