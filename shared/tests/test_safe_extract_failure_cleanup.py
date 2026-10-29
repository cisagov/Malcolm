"""Failed extraction must not leave partial log files available for ingestion."""

import bz2
import gzip
import io
import lzma
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import zipfile

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / 'scripts' / 'safe-extract.py'


def extract(archive, destination, **environment):
    return subprocess.run(
        [sys.executable, str(SCRIPT), str(archive), str(destination)],
        env={**os.environ, **environment},
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )


@pytest.mark.parametrize('extension,compress', [('gz', gzip.compress), ('bz2', bz2.compress), ('xz', lzma.compress)])
def test_truncated_stream_removes_partial_output(tmp_path, extension, compress):
    # Large enough to write output before discovering the missing stream footer.
    archive = tmp_path / f'conn.log.{extension}'
    damaged = compress(os.urandom(150_000))[:-8]
    archive.write_bytes(damaged)
    destination = tmp_path / 'extracted'

    result = extract(archive, destination)

    assert result.returncode != 0
    assert result.stderr
    assert not destination.exists()
    assert archive.read_bytes() == damaged


def test_bad_zip_checksum_removes_previously_extracted_members(tmp_path):
    archive = tmp_path / 'logs.zip'
    second_contents = b'second-file-contents'
    with zipfile.ZipFile(archive, 'w', compression=zipfile.ZIP_STORED) as output:
        output.writestr('first.log', b'first file was extracted\n')
        output.writestr('second.log', second_contents)
    damaged = bytearray(archive.read_bytes())
    damaged[damaged.index(second_contents)] ^= 1
    archive.write_bytes(damaged)
    destination = tmp_path / 'extracted'

    result = extract(archive, destination)

    assert result.returncode != 0
    assert not destination.exists()
    assert archive.read_bytes() == damaged


def test_missing_source_does_not_leave_new_destination(tmp_path):
    destination = tmp_path / 'extracted'
    result = extract(tmp_path / 'missing.log.gz', destination)
    assert result.returncode != 0
    assert not destination.exists()


def test_existing_destination_is_never_deleted(tmp_path):
    archive = tmp_path / 'conn.log.gz'
    archive.write_bytes(gzip.compress(b'new data'))
    destination = tmp_path / 'existing'
    destination.mkdir()
    sentinel = destination / 'keep.log'
    sentinel.write_bytes(b'existing data')

    result = extract(archive, destination)

    assert result.returncode != 0
    assert sentinel.read_bytes() == b'existing data'
    assert list(destination.iterdir()) == [sentinel]


def test_size_limit_still_cleans_up_output(tmp_path):
    archive = tmp_path / 'conn.log.gz'
    archive.write_bytes(gzip.compress(b'x' * 1024))
    destination = tmp_path / 'extracted'
    result = extract(archive, destination, SAFE_EXTRACT_MAX_BYTES='16')
    assert result.returncode != 0
    assert 'ArchiveBombError' in result.stderr
    assert not destination.exists()


@pytest.mark.parametrize('archive_type', ['gzip', 'tar', 'zip'])
def test_successful_extraction_preserves_output(tmp_path, archive_type):
    contents = b'valid log contents\n'
    if archive_type == 'gzip':
        archive = tmp_path / 'conn.log.gz'
        archive.write_bytes(gzip.compress(contents))
    elif archive_type == 'tar':
        archive = tmp_path / 'logs.tar'
        with tarfile.open(archive, 'w') as output:
            entry = tarfile.TarInfo('conn.log')
            entry.size = len(contents)
            output.addfile(entry, io.BytesIO(contents))
    else:
        archive = tmp_path / 'logs.zip'
        with zipfile.ZipFile(archive, 'w') as output:
            output.writestr('conn.log', contents)
    original = archive.read_bytes()
    destination = tmp_path / 'extracted'

    result = extract(archive, destination)

    assert result.returncode == 0, result.stderr
    assert (destination / 'conn.log').read_bytes() == contents
    assert archive.read_bytes() == original
