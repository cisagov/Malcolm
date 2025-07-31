#!/usr/bin/env python3

# Copyright (c) 2025 Battelle Energy Alliance, LLC. All rights reserved.

import fcntl
import logging
import magic
import os
import subprocess
import sys
import time
from tempfile import gettempdir
from subprocess import DEVNULL
from typing import List, Tuple, Optional, Any

from malcolm_utils import LoadFileIfJson, deep_get, set_logging, get_verbosity_env_var_count

# --------------------------------------------------------------------
# Configuration and globals
# --------------------------------------------------------------------

lock_filename = os.path.join(gettempdir(), f'{os.path.basename(__file__)}.lock')

filebeat_registry_filename = os.getenv(
    'FILEBEAT_REGISTRY_FILE', "/usr/share/filebeat-logs/data/registry/filebeat/log.json"
)

zeek_dir = os.path.join(os.getenv('FILEBEAT_ZEEK_DIR', "/zeek/"), '')
zeek_live_dir = os.path.join(zeek_dir, "live/logs/")
zeek_current_dir = os.path.join(zeek_dir, "current/")
zeek_processed_dir = os.path.join(zeek_dir, "processed/")

suricata_dir = os.path.join(os.getenv('FILEBEAT_SURICATA_LOG_PATH', "/suricata/"), '')

# We're only able to do this pruning because we're forwarding the logs along to Logstash
#   so they're not needed here anymore. If we're *not* forwarding, we can't delete them
#   based on age like that.
if (os.getenv('MALCOLM_PROFILE') == 'hedgehog') and not os.getenv('LOGSTASH_HOST'):
    clean_log_seconds = 0
    clean_zip_seconds = 0
else:
    clean_log_seconds = int(os.getenv('LOG_CLEANUP_MINUTES', "30")) * 60
    clean_zip_seconds = int(os.getenv('ZIP_CLEANUP_MINUTES', "120")) * 60

now_time = time.time()

_LOG_MIME_TYPES = (
    "application/json",
    "application/x-ndjson",
    "text/plain",
    "text/x-file",
)

_ARCHIVE_MIME_TYPES = (
    "application/gzip",
    "application/x-7z-compressed",
    "application/x-bzip2",
    "application/x-cpio",
    "application/x-gzip",
    "application/x-lzip",
    "application/x-lzma",
    "application/x-ms-evtx",
    "application/x-rar-compressed",
    "application/x-tar",
    "application/x-xz",
    "application/zip",
)

# --------------------------------------------------------------------
# Helper functions
# --------------------------------------------------------------------


def silent_remove(filename: str) -> None:
    """Remove a file, link, or directory without raising exceptions."""
    try:
        if os.path.isfile(filename) or os.path.islink(filename):
            os.remove(filename)
        elif os.path.isdir(filename):
            os.rmdir(filename)
    except OSError:
        pass


def check_file(
    filename: str,
    fb_files: List[Tuple[int, int]],
    check_logs: bool = True,
    check_archives: bool = True,
) -> None:
    """Check if a file can be deleted based on age, type, and registry usage."""
    try:
        # first check to see if it's in the filebeat registry
        file_stat = os.stat(filename)
        if (file_stat.st_dev, file_stat.st_ino) in fb_files:
            # It's still in the filebeat registry.
            return

        log_time = os.path.getmtime(filename)
        last_use_time = now_time - log_time
        if last_use_time < min(clean_log_seconds, clean_zip_seconds):
            # Too new to remove regardless of type.
            return

        # now see if the file is in use by any other process in the system
        fuser_proc = subprocess.run(["fuser", "-s", filename], stdout=DEVNULL, stderr=DEVNULL)
        if fuser_proc.returncode == 0:
            # The file is in use by another process.
            return

        # get the file type (treat zero-length files as log files)
        file_type = magic.from_file(filename, mime=True)
        if check_logs and clean_log_seconds > 0 and (file_stat.st_size == 0 or file_type in _LOG_MIME_TYPES):
            clean_seconds = clean_log_seconds
        elif check_archives and clean_zip_seconds > 0 and file_type in _ARCHIVE_MIME_TYPES:
            clean_seconds = clean_zip_seconds
        else:
            # not a file we're going to be messing with
            logging.debug(f"Ignoring {filename} due to {file_type=}")
            return

        if clean_seconds > 0 and last_use_time >= clean_seconds:
            # this is a closed file that is old, so delete it
            silent_remove(filename)
            logging.info(f'Removed old file "{filename}" ({file_type}, used {last_use_time:.0f} seconds ago)')

    except FileNotFoundError:
        # file's already gone, oh well
        pass

    except Exception as e:
        logging.error(f"{type(e).__name__} for '{filename}': {e}")


def list_files_in_dir(base_dir: str) -> List[str]:
    """Recursively list all files in a directory."""
    if not os.path.isdir(base_dir):
        return []
    return [os.path.join(root, f) for root, _, files in os.walk(base_dir) for f in files]


def load_filebeat_registry(registry_path: str) -> List[Tuple[int, int]]:
    """Load the filebeat registry file and extract (device, inode) tuples."""
    if not os.path.isfile(registry_path):
        return []
    try:
        with open(registry_path) as f:
            fb_reg = LoadFileIfJson(f, attemptLines=True)
    except Exception as e:
        logging.error(f"Failed to load filebeat registry: {e}")
        return []

    fb_files = []
    for entry in fb_reg:
        device = deep_get(entry, ['v', 'FileStateOS', 'device'])
        inode = deep_get(entry, ['v', 'FileStateOS', 'inode'])
        if device is not None and inode is not None:
            fb_files.append((int(device), int(inode)))
    return fb_files


def process_files(
    files: List[str],
    fb_files: List[Tuple[int, int]],
    check_logs: bool = True,
    check_archives: bool = True,
    label: str = "",
) -> None:
    """Run check_file() on a batch of files and log processing statistics."""
    if not files:
        return
    start = time.time()
    for file in files:
        check_file(file, fb_files=fb_files, check_logs=check_logs, check_archives=check_archives)
    duration = time.time() - start
    if duration > 0:
        rate = len(files) / duration
        logging.debug(f"Checked {len(files)} {label} files at a rate of {rate:.0f} files/second.")
    else:
        logging.debug(f"Checked {len(files)} {label} files.")


def cleanup_dead_symlinks(directory: str) -> None:
    """Remove dead symlinks within a directory."""
    if not os.path.isdir(directory):
        return
    for entry in os.listdir(directory):
        path = os.path.join(directory, entry)
        if os.path.islink(path) and not os.path.exists(path):
            silent_remove(path)
            logging.info(f'Removed dead symlink "{path}"')


def cleanup_empty_dirs(base_dirs: List[str], clean_dir_seconds: int) -> None:
    """Remove empty directories older than clean_dir_seconds."""
    candidate_dirs = []
    for base_dir in base_dirs:
        if not os.path.isdir(base_dir):
            continue
        for root, dirs, _ in os.walk(base_dir, topdown=False):
            for d in dirs:
                candidate_dirs.append(os.path.join(root, d))

    candidate_dirs = list(set(candidate_dirs))
    candidate_dirs.sort(key=len, reverse=True)
    candidate_dirs_times = zip(candidate_dirs, [os.path.getmtime(dir_to_rm) for dir_to_rm in candidate_dirs])
    for dir_to_rm, dir_time in candidate_dirs_times:
        dir_age = now_time - dir_time
        if dir_age >= clean_dir_seconds:
            try:
                os.rmdir(dir_to_rm)
                logging.info(f'Removed empty directory "{dir_to_rm}" (used {dir_age} seconds ago)')
            except OSError:
                pass


def prune_files() -> None:
    """Main cleanup logic: prune Zeek and Suricata logs, remove old dirs and symlinks."""
    if (clean_log_seconds <= 0) and (clean_zip_seconds <= 0):
        return

    fb_files = load_filebeat_registry(filebeat_registry_filename)

    # look for regular Zeek files in the processed/ directory
    zeek_found = list_files_in_dir(zeek_processed_dir)
    logging.debug(f"Found {len(zeek_found)} Zeek processed files to consider.")

    # look for rotated files from live zeek instance
    zeek_rotated = list_files_in_dir(zeek_live_dir)
    logging.debug(f"Found {len(zeek_rotated)} Zeek live files to consider.")

    process_files(zeek_found, fb_files, check_logs=True, check_archives=True, label="Zeek processed")
    process_files(zeek_rotated, fb_files, check_logs=False, check_archives=True, label="Zeek live")

    # clean up any broken symlinks in the Zeek current/ directory
    cleanup_dead_symlinks(zeek_current_dir)

    # check the suricata logs (live and otherwise) as well
    suricata_files = list_files_in_dir(suricata_dir)
    logging.debug(f"Found {len(suricata_files)} Suricata files to consider.")
    process_files(suricata_files, fb_files, check_logs=True, check_archives=False, label="Suricata")

    # clean up any old and empty directories in Zeek processed/ and suricata non-live directories
    clean_dir_seconds = min(i for i in (clean_log_seconds, clean_zip_seconds) if i > 0)
    cleanup_empty_dirs([zeek_processed_dir, suricata_dir], clean_dir_seconds)

    logging.debug("Finished pruning files.")


def main() -> None:
    """Entry point: acquire lock, perform cleanup, and release lock."""
    set_logging(
        os.getenv("FILEBEAT_CLEANUP_LOGLEVEL", ""),
        get_verbosity_env_var_count("FILEBEAT_CLEANUP_VERBOSITY"),
        set_traceback_limit=True,
        logfmt='%(message)s',
    )

    with open(lock_filename, 'w') as lock_file:
        try:
            fcntl.flock(lock_file, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except IOError:
            return
        else:
            prune_files()
        finally:
            os.remove(lock_filename)


if __name__ == '__main__':
    main()
