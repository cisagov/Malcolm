"""Preview and safely restage previously processed PCAPs for re-ingestion.

The ordinary watcher deduplicates on the stored filename and size. A fresh
reingest_ prefix creates a new basename so this opt-in replay is not silently
skipped. Existing processed captures are never deleted or overwritten.
"""

import errno
import os
from pathlib import Path
import secrets
import shutil
import stat
import tempfile

PCAP_MAGIC = {
    b'\xa1\xb2\xc3\xd4',
    b'\xd4\xc3\xb2\xa1',
    b'\xa1\xb2\x3c\x4d',
    b'\x4d\x3c\xb2\xa1',
    b'\x0a\x0d\x0d\x0a',  # PCAPNG
}
MAX_REINGEST_FILES = 100
REINGEST_PREFIX = 'reingest_'
COPY_CHUNK_BYTES = 1024 * 1024


def _validate_dirs(processed_dir, upload_dir):
    """Only operate on real sibling directories under the same PCAP mount."""
    processed_dir = Path(processed_dir)
    upload_dir = Path(upload_dir)
    if any(path.is_symlink() or not path.is_dir() for path in (processed_dir, upload_dir)):
        raise ValueError('PCAP processed and upload directories must exist and must not be symlinks')
    if processed_dir.resolve() == upload_dir.resolve() or processed_dir.parent.resolve() != upload_dir.parent.resolve():
        raise ValueError('PCAP processed and upload directories must be distinct siblings in the same mount')
    return processed_dir, upload_dir


def _open_regular_capture(path):
    """Open a PCAP without following links and verify the header and size."""
    flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_CLOEXEC', 0)
    descriptor = os.open(path, flags)
    try:
        st = os.fstat(descriptor)
        if not stat.S_ISREG(st.st_mode) or st.st_size < 24:
            raise ValueError(f'Not a complete regular PCAP file: {path}')
        if os.read(descriptor, 4) not in PCAP_MAGIC:
            raise ValueError(f'Not a PCAP or PCAPNG header: {path}')
        os.lseek(descriptor, 0, os.SEEK_SET)
        entry = os.lstat(path)
        if not stat.S_ISREG(entry.st_mode) or (entry.st_dev, entry.st_ino) != (st.st_dev, st.st_ino):
            raise ValueError(f'PCAP source changed during opening: {path}')
        return descriptor, st
    except Exception:
        os.close(descriptor)
        raise


def _unchanged_source(path, st, descriptor):
    """Detect renamed, replaced, grown or modified captures during copying."""
    actual = os.fstat(descriptor)
    try:
        visible = os.lstat(path)
    except OSError:
        return False
    return (
        stat.S_ISREG(visible.st_mode)
        and (actual.st_dev, actual.st_ino, actual.st_size, actual.st_mtime_ns)
        == (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns)
        and (visible.st_dev, visible.st_ino) == (st.st_dev, st.st_ino)
    )


def find_processed_pcaps(processed_dir, upload_dir, max_files=10):
    """Return a deterministic read-only preview of eligible original files."""
    processed_dir, _ = _validate_dirs(processed_dir, upload_dir)
    if type(max_files) is not int or not 1 <= max_files <= MAX_REINGEST_FILES:
        raise ValueError(f'reingest limit must be an integer between 1 and {MAX_REINGEST_FILES}')
    eligible = []
    for item in sorted(processed_dir.iterdir(), key=lambda path: path.name):
        if item.name.startswith(REINGEST_PREFIX) or item.is_symlink():
            continue
        try:
            fd, _ = _open_regular_capture(item)
        except (OSError, ValueError):
            continue
        else:
            os.close(fd)
            eligible.append(item)
            if len(eligible) == max_files:
                break
    return eligible


def _stage_capture(original, staging_dir):
    """Copy into an unwatched staging directory; validate source stability."""
    source_fd, source_st = _open_regular_capture(original)
    with os.fdopen(source_fd, 'rb') as src:
        temp_fd, temp_name = tempfile.mkstemp(prefix='.pcap-', suffix='.part', dir=staging_dir)
        try:
            with os.fdopen(temp_fd, 'wb') as dst:
                shutil.copyfileobj(src, dst, COPY_CHUNK_BYTES)
                if not _unchanged_source(original, source_st, src.fileno()):
                    raise ValueError(f'PCAP source changed during copy: {original}')
                os.fchmod(dst.fileno(), stat.S_IMODE(source_st.st_mode) & 0o666)
                dst.flush()
                os.fsync(dst.fileno())
        except Exception:
            if os.path.lexists(temp_name):
                os.unlink(temp_name)
            raise
    return Path(temp_name)


def _publish_staged(original, staged, upload_dir):
    """Publish a completed file atomically, without clobbering an upload."""
    for _attempt in range(10):
        name = f'{REINGEST_PREFIX}{secrets.token_hex(8)}_{original.name}'
        destination = upload_dir / name
        try:
            os.link(staged, destination)
        except FileExistsError:
            continue
        except OSError as error:
            if error.errno == errno.EXDEV:
                raise OSError('PCAP upload and staging must share a filesystem for atomic publication') from error
            raise
        os.utime(destination, None)
        return destination
    raise FileExistsError(f'Could not allocate a unique re-ingest filename for {original}')


def publish_processed_pcaps(candidates, upload_dir):
    """Restage copies only; originals, indices and other data remain intact."""
    candidates = list(candidates)
    if not candidates:
        return []
    upload_dir = Path(upload_dir)
    processed_dir, upload_dir = _validate_dirs(Path(candidates[0]).parent, upload_dir)
    for candidate in candidates:
        if Path(candidate).parent != processed_dir or Path(candidate).name.startswith(REINGEST_PREFIX):
            raise ValueError('Only original files directly under the processed directory may be replayed')
    published = []
    # The parent of upload/ and processed/ is not itself watched for PCAPs.
    with tempfile.TemporaryDirectory(prefix='.malcolm-reingest-', dir=processed_dir.parent) as staging:
        for original in candidates:
            staged = _stage_capture(Path(original), staging)
            try:
                published.append(_publish_staged(Path(original), staged, upload_dir))
            finally:
                staged.unlink(missing_ok=True)
    return published
