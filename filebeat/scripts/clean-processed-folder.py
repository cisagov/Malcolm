#!/usr/bin/env python3

# Copyright (c) 2025 Battelle Energy Alliance, LLC.  All rights reserved.

import fcntl
import logging
import magic
import os
import subprocess
import sys
import time
from tempfile import gettempdir
from subprocess import DEVNULL
from malcolm_utils import LoadFileIfJson, deep_get, set_logging, get_verbosity_env_var_count

lockFilename = os.path.join(gettempdir(), '{}.lock'.format(os.path.basename(__file__)))
cleanLogSeconds = int(os.getenv('LOG_CLEANUP_MINUTES', "30")) * 60
cleanZipSeconds = int(os.getenv('ZIP_CLEANUP_MINUTES', "120")) * 60
fbRegFilename = os.getenv('FILEBEAT_REGISTRY_FILE', "/usr/share/filebeat-logs/data/registry/filebeat/log.json")

zeekDir = os.path.join(os.getenv('FILEBEAT_ZEEK_DIR', "/zeek/"), '')
zeekLiveDir = zeekDir + "live/logs/"
zeekCurrentDir = zeekDir + "current/"
zeekProcessedDir = zeekDir + "processed/"

suricataDir = os.path.join(os.getenv('FILEBEAT_SURICATA_LOG_PATH', "/suricata/"), '')

nowTime = time.time()

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


def silentRemove(filename):
    try:
        if os.path.isfile(filename) or os.path.islink(filename):
            os.remove(filename)
        elif os.path.isdir(filename):
            os.rmdir(filename)
    except OSError:
        pass


def checkFile(filename, fb_files: list[tuple[int, int]], checkLogs=True, checkArchives=True):
    try:
        # first check to see if it's in the filebeat registry
        fileStatInfo = os.stat(filename)
        if (fileStatInfo.st_dev, fileStatInfo.st_ino) in fb_files:
            # It's still in the filebeat registry.
            return

        logTime = os.path.getmtime(filename)
        lastUseTime = nowTime - logTime
        if lastUseTime < min(cleanLogSeconds, cleanZipSeconds):
            # Too new to remove regardless of type.
            return

        # now see if the file is in use by any other process in the system
        fuserProcess = subprocess.run(["fuser", "-s", filename], stdout=DEVNULL, stderr=DEVNULL)
        fuserExitCode = fuserProcess.returncode
        if fuserExitCode == 0:
            # The file is in use by another process.
            return

        # get the file type (treat zero-length files as log files)
        fileType = magic.from_file(filename, mime=True)
        if (
            (checkLogs is True)
            and (cleanLogSeconds > 0)
            and ((fileStatInfo.st_size == 0) or (fileType in _LOG_MIME_TYPES))
        ):
            cleanSeconds = cleanLogSeconds
        elif (checkArchives is True) and (cleanZipSeconds > 0) and (fileType in _ARCHIVE_MIME_TYPES):
            cleanSeconds = cleanZipSeconds
        else:
            # not a file we're going to be messing with
            logging.debug(f"Ignoring {filename} due to {fileType=}")
            return

        if (cleanSeconds > 0) and (lastUseTime >= cleanSeconds):
            # this is a closed file that is old, so delete it
            silentRemove(filename)
            logging.info(f'Removed old file "{filename}" ({fileType}, used {lastUseTime:.0f} seconds ago)')

    except FileNotFoundError:
        # file's already gone, oh well
        pass

    except Exception as e:
        logging.error(f"{type(e).__name__} for '{filename}': {e}")


def pruneFiles():
    if (cleanLogSeconds <= 0) and (cleanZipSeconds <= 0):
        # disabled, don't do anything
        return

    # look for regular Zeek files in the processed/ directory
    zeekFoundFiles = (
        [
            (os.path.join(root, filename))
            for root, dirnames, filenames in os.walk(zeekProcessedDir)
            for filename in filenames
        ]
        if os.path.isdir(zeekProcessedDir)
        else []
    )
    logging.debug(f"Found {len(zeekFoundFiles)} Zeek processed directory files to consider.")

    # look for rotated files from live zeek instance
    zeekRotatedFiles = (
        [(os.path.join(root, filename)) for root, dirnames, filenames in os.walk(zeekLiveDir) for filename in filenames]
        if os.path.isdir(zeekLiveDir)
        else []
    )
    logging.debug(f"Found {len(zeekRotatedFiles)} Zeek live directory files to consider.")

    # look up the filebeat registry file and try to read it
    fbReg = None
    if os.path.isfile(fbRegFilename):
        with open(fbRegFilename) as f:
            fbReg = LoadFileIfJson(f, attemptLines=True)

    # Extract file device and inode information from the registry for faster processing
    fb_files: list[tuple[int, int]] = []
    for entry in fbReg:
        device = deep_get(entry, ['v', 'FileStateOS', 'device'])
        inode = deep_get(entry, ['v', 'FileStateOS', 'inode'])
        if device is not None and inode is not None:
            fb_files.append((int(device), int(inode)))

    # see if the files we found are in use and old enough to be pruned
    start = time.time()
    for file in zeekFoundFiles:
        checkFile(file, fb_files=fb_files, checkLogs=True, checkArchives=True)
    duration = time.time() - start
    file_rate = len(zeekFoundFiles) / duration
    logging.debug(
        f"Checked {len(zeekFoundFiles)} Zeek processed directory files at a rate of {file_rate:.0f} files/second."
    )

    start = time.time()
    for file in zeekRotatedFiles:
        checkFile(file, fb_files=fb_files, checkLogs=False, checkArchives=True)
    duration = time.time() - start
    file_rate = len(zeekRotatedFiles) / duration
    logging.debug(
        f"Checked {len(zeekRotatedFiles)} Zeek live directory files at a rate of {file_rate:.0f} files/second."
    )

    # clean up any broken symlinks in the Zeek current/ directory
    if os.path.isdir(zeekCurrentDir):
        for current in os.listdir(zeekCurrentDir):
            currentFileSpec = os.path.join(zeekCurrentDir, current)
            if os.path.islink(currentFileSpec) and not os.path.exists(currentFileSpec):
                silentRemove(currentFileSpec)
                logging.info(f'Removed dead symlink "{currentFileSpec}"')

    # check the suricata logs (live and otherwise) as well
    suricata_found_files: list[str] = []
    for dir_path, _, filenames in os.walk(suricataDir):
        for filename in filenames:
            path = f"{dir_path}/{filename}"
            suricata_found_files.append(path)
    logging.debug(f"Found {len(suricata_found_files)} Suricata files to consider.")

    start = time.time()
    for file in suricata_found_files:
        checkFile(file, fb_files=fb_files, checkLogs=True, checkArchives=False)
    duration = time.time() - start
    file_rate = len(suricata_found_files) / duration
    logging.debug(f"Checked {len(suricata_found_files)} Suricata files at a rate of {file_rate:.0f} files/second.")

    # clean up any old and empty directories in Zeek processed/ and suricata non-live directories
    cleanDirSeconds = min(i for i in (cleanLogSeconds, cleanZipSeconds) if i > 0)
    candidateDirs = []
    for processedDir in [zeekProcessedDir, suricataDir]:
        if os.path.isdir(processedDir):
            for root, dirs, files in os.walk(processedDir, topdown=False):
                if root and dirs:
                    candidateDirs += [os.path.join(root, tmpDir) for tmpDir in dirs]
    candidateDirs = list(set(candidateDirs))
    candidateDirs.sort(reverse=True)
    candidateDirs.sort(key=len, reverse=True)
    candidateDirsAndTimes = zip(candidateDirs, [os.path.getmtime(dirToRm) for dirToRm in candidateDirs])
    for dirToRm, dirTime in candidateDirsAndTimes:
        dirAge = nowTime - dirTime
        if dirAge >= cleanDirSeconds:
            try:
                os.rmdir(dirToRm)
                logging.info(f'Removed empty directory "{dirToRm}" (used {dirAge} seconds ago)')
            except OSError:
                pass


def main():
    set_logging(
        os.getenv("FILEBEAT_CLEANUP_LOGLEVEL", ""),
        get_verbosity_env_var_count("FILEBEAT_CLEANUP_VERBOSITY"),
        set_traceback_limit=True,
        logfmt='%(message)s',
    )

    with open(lockFilename, 'w') as lock_file:
        try:
            fcntl.flock(lock_file, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except IOError:
            return
        else:
            pruneFiles()
            logging.debug("Finished pruning files.")
        finally:
            os.remove(lockFilename)


if __name__ == '__main__':
    main()
