#!/usr/bin/env python3
# safe_extract.py - extract archive to dest with path traversal protection
# usage: safe-extract.py <archive> <destdir>
import sys
import os
import gzip
import bz2
import lzma
import libarchive.extract
import libarchive.read
import magic
import malcolm_utils
import re
import shutil
import subprocess

ARCHIVE_EXTRACT_FLAGS = (
    libarchive.extract.EXTRACT_SECURE_NODOTDOT
    | libarchive.extract.EXTRACT_SECURE_NOABSOLUTEPATHS
    | libarchive.extract.EXTRACT_SECURE_SYMLINKS
)

# Archive bomb limits — override via environment variables
ARCHIVE_EXTRACT_MAX_ENTRIES = int(os.environ.get('SAFE_EXTRACT_MAX_ENTRIES', 5000))
ARCHIVE_EXTRACT_MAX_DEPTH = int(os.environ.get('SAFE_EXTRACT_MAX_DEPTH', 20))
ARCHIVE_EXTRACT_MAX_TOTAL_BYTES = int(os.environ.get('SAFE_EXTRACT_MAX_BYTES', 4 * 1024**3))

# Raw single-stream compression formats: no container, no member paths.
# Decompress to a single output file via stdlib.
ARCHIVE_RAW_STREAM_MIMES = {
    'application/gzip': gzip.open,
    'application/x-gzip': gzip.open,
    'application/x-bzip2': bz2.open,
    'application/x-xz': lzma.open,
    'application/x-lzma': lzma.open,
}

TAR_COMPRESSED_EXTS = re.compile(
    r'\.(tgz|tbz2?|txz|tlz|tar\.(gz|bz2|xz|lz|lzma))$',
    flags=re.IGNORECASE,
)


class ArchiveBombError(Exception):
    """Raised when an archive exceeds configured extraction limits."""

    pass


def _strip_compression_ext(path):
    return (
        re.sub(
            r'\.(gz|bz2|xz|lz|lzma)$',
            '',
            os.path.basename(path),
            flags=re.IGNORECASE,
        )
        or 'decompressed'
    )


def _extract_raw_stream(archive, dest, archive_mime=None):
    open_fn = ARCHIVE_RAW_STREAM_MIMES[archive_mime if archive_mime else magic.from_file(archive, mime=True)]
    outname = _strip_compression_ext(archive)
    outpath = os.path.join(dest, outname)
    total_bytes = 0
    with open_fn(archive, 'rb') as src, open(outpath, 'wb') as dst:
        while chunk := src.read(65536):
            total_bytes += len(chunk)
            if total_bytes > ARCHIVE_EXTRACT_MAX_TOTAL_BYTES:
                raise ArchiveBombError(
                    f"archive exceeds size limit ({ARCHIVE_EXTRACT_MAX_TOTAL_BYTES} bytes) "
                    f"during decompression of {os.path.basename(archive)!r}"
                )
            dst.write(chunk)


def _extract_lzip(archive, dest):
    outname = _strip_compression_ext(archive)
    outpath = os.path.join(dest, outname)
    total_bytes = 0
    proc = subprocess.Popen(['lzip', '-d', '-c', archive], stdout=subprocess.PIPE)
    with open(outpath, 'wb') as dst:
        while chunk := proc.stdout.read(65536):
            total_bytes += len(chunk)
            if total_bytes > ARCHIVE_EXTRACT_MAX_TOTAL_BYTES:
                proc.kill()
                raise ArchiveBombError(
                    f"archive exceeds size limit ({ARCHIVE_EXTRACT_MAX_TOTAL_BYTES} bytes) "
                    f"during decompression of {os.path.basename(archive)!r}"
                )
            dst.write(chunk)
    proc.wait()
    if proc.returncode != 0:
        raise subprocess.CalledProcessError(proc.returncode, 'lzip')


def _extract_libarchive(archive, dest):
    """Extract an archive using libarchive with security flags.
    Iterates entries manually to skip directory entries that some
    formats (e.g. RAR) mark in a way that confuses extract_file.
    Enforces limits on entry count, nesting depth, and total
    uncompressed bytes to prevent archive bomb DoS.
    Validates directory entry paths to prevent traversal outside dest."""
    count = 0
    total_bytes = 0
    real_dest = os.path.realpath(dest)

    with malcolm_utils.pushd(dest):
        with libarchive.read.file_reader(archive) as a:
            for entry in a:
                count += 1
                total_bytes += getattr(entry, 'size', 0) or 0
                depth = entry.pathname.rstrip('/').count('/')

                if count > ARCHIVE_EXTRACT_MAX_ENTRIES:
                    raise ArchiveBombError(
                        f"archive exceeds entry limit ({ARCHIVE_EXTRACT_MAX_ENTRIES}): "
                        f"stopped at entry {count} ({entry.pathname!r})"
                    )
                if depth > ARCHIVE_EXTRACT_MAX_DEPTH:
                    raise ArchiveBombError(
                        f"archive exceeds depth limit ({ARCHIVE_EXTRACT_MAX_DEPTH}): {entry.pathname!r} is {depth} levels deep"
                    )
                if total_bytes > ARCHIVE_EXTRACT_MAX_TOTAL_BYTES:
                    raise ArchiveBombError(
                        f"archive exceeds size limit ({ARCHIVE_EXTRACT_MAX_TOTAL_BYTES} bytes): "
                        f"stopped at entry {count} ({entry.pathname!r})"
                    )

                if entry.isdir:
                    # Validate resolved path stays within dest before creating;
                    # os.makedirs with a raw entry.pathname has no traversal
                    # protection unlike file entries handled via ARCHIVE_EXTRACT_FLAGS.
                    target = os.path.realpath(os.path.join(dest, entry.pathname))
                    if target != real_dest and not target.startswith(real_dest + os.sep):
                        raise ArchiveBombError(
                            f"directory traversal detected: {entry.pathname!r} resolves outside dest"
                        )
                    os.makedirs(target, exist_ok=True)
                    continue

                libarchive.extract.extract_entries([entry], flags=ARCHIVE_EXTRACT_FLAGS)


def safe_extract(archive, dest):
    os.makedirs(dest, exist_ok=False)
    file_mime_type = magic.from_file(archive, mime=True)
    try:
        if TAR_COMPRESSED_EXTS.search(archive):
            _extract_libarchive(archive, dest)
        elif file_mime_type in ARCHIVE_RAW_STREAM_MIMES:
            _extract_raw_stream(archive, dest, file_mime_type)
        elif file_mime_type == 'application/x-lzip':
            _extract_lzip(archive, dest)
        else:
            _extract_libarchive(archive, dest)
    except ArchiveBombError:
        shutil.rmtree(dest, ignore_errors=True)
        raise


if len(sys.argv) != 3:
    print(f"Usage: {sys.argv[0]} <archive> <destdir>", file=sys.stderr)
    sys.exit(1)

safe_extract(os.path.realpath(sys.argv[1]), os.path.realpath(sys.argv[2]))
