#!/usr/bin/env python3

# Copyright (c) 2025 Battelle Energy Alliance, LLC.  All rights reserved.


import os
from os.path import splitext
from tempfile import gettempdir
import errno
import time
import fcntl
import magic
import json
import re
from subprocess import Popen, PIPE, DEVNULL
from malcolm_utils import LoadFileIfJson, deep_get

lockFilename = os.path.join(gettempdir(), '{}.lock'.format(os.path.basename(__file__)))
cleanLogSeconds = int(os.getenv('LOG_CLEANUP_MINUTES', "30")) * 60
cleanZipSeconds = int(os.getenv('ZIP_CLEANUP_MINUTES', "120")) * 60
fbRegFilename = os.getenv('FILEBEAT_REGISTRY_FILE', "/usr/share/filebeat-logs/data/registry/filebeat/log.json")

zeekDir = os.path.join(os.getenv('FILEBEAT_ZEEK_DIR', "/zeek/"), '')
zeekLiveDir = zeekDir + "live/logs/"
zeekCurrentDir = zeekDir + "current/"
zeekProcessedDir = zeekDir + "processed/"

suricataDir = os.path.join(os.getenv('FILEBEAT_SURICATA_LOG_PATH', "/suricata/"), '')
suricataLiveDir = suricataDir + "live/"

nowTime = time.time()
logMimeTypeRegex = re.compile(r"(text/plain|application/(x-nd)?json)")
archiveMimeTypeRegex = re.compile(
    r"(application/gzip|application/x-gzip|application/x-7z-compressed|application/x-bzip2|application/x-cpio|application/x-lzip|application/x-lzma|application/x-rar-compressed|application/x-tar|application/x-xz|application/zip|application/x-ms-evtx)"
)


def silentRemove(filename):
    try:
        if os.path.isfile(filename) or os.path.islink(filename):
            os.remove(filename)
        elif os.path.isdir(filename):
            os.rmdir(filename)
    except OSError:
        pass


def checkFile(filename, filebeatReg=None, checkLogs=True, checkArchives=True):
    try:
        # first check to see if it's in the filebeat registry
        if filebeatReg is not None:
            fileStatInfo = os.stat(filename)
            if fileStatInfo:
                fileFound = any(
                    (
                        (deep_get(entry, ['v', 'FileStateOS', 'device']) == fileStatInfo.st_dev)
                        and (deep_get(entry, ['v', 'FileStateOS', 'inode']) == fileStatInfo.st_ino)
                    )
                    for entry in filebeatReg
                )
                if fileFound:
                    # found a file in the filebeat registry, so leave it alone!
                    # we only want to delete files that filebeat has forgotten
                    # print(f"{filename} is found in registry!")
                    return
                # else:
                #     print(f"{filename} is NOT found in registry!")

        # now see if the file is in use by any other process in the system
        fuserProcess = Popen(["fuser", "-s", filename], stdout=PIPE, stderr=DEVNULL)
        fuserProcess.communicate()
        fuserExitCode = fuserProcess.wait()
        if fuserExitCode != 0:
            # the file is not in use, let's check it's mtime/ctime
            logTime = max(os.path.getctime(filename), os.path.getmtime(filename))
            lastUseTime = nowTime - logTime

            # get the file type
            fileType = magic.from_file(filename, mime=True)
            if (checkLogs is True) and (cleanLogSeconds > 0) and logMimeTypeRegex.match(fileType) is not None:
                cleanSeconds = cleanLogSeconds
            elif (checkArchives is True) and (cleanZipSeconds > 0) and archiveMimeTypeRegex.match(fileType) is not None:
                cleanSeconds = cleanZipSeconds
            else:
                # not a file we're going to be messing with
                cleanSeconds = 0

            if (cleanSeconds > 0) and (lastUseTime >= cleanSeconds):
                # this is a closed file that is old, so delete it
                print(f'removing old file "{filename}" ({fileType}, used {lastUseTime} seconds ago)')
                silentRemove(filename)

    except FileNotFoundError:
        # file's already gone, oh well
        pass

    except Exception as e:
        print(f"{type(e).__name__} for '{filename}': {e}")


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

    # look for rotated files from live zeek instance
    zeekRotatedFiles = (
        [(os.path.join(root, filename)) for root, dirnames, filenames in os.walk(zeekLiveDir) for filename in filenames]
        if os.path.isdir(zeekLiveDir)
        else []
    )

    # look up the filebeat registry file and try to read it
    fbReg = None
    if os.path.isfile(fbRegFilename):
        with open(fbRegFilename) as f:
            fbReg = LoadFileIfJson(f, attemptLines=True)

    # see if the files we found are in use and old enough to be pruned
    for file in zeekFoundFiles:
        checkFile(file, filebeatReg=fbReg, checkLogs=True, checkArchives=True)
    for file in zeekRotatedFiles:
        checkFile(file, filebeatReg=None, checkLogs=False, checkArchives=True)

    # clean up any broken symlinks in the Zeek current/ directory
    if os.path.isdir(zeekCurrentDir):
        for current in os.listdir(zeekCurrentDir):
            currentFileSpec = os.path.join(zeekCurrentDir, current)
            if os.path.islink(currentFileSpec) and not os.path.exists(currentFileSpec):
                print(f'removing dead symlink "{currentFileSpec}"')
                silentRemove(currentFileSpec)

    # check the suricata logs (live and otherwise) as well
    for surDir in [suricataDir, suricataLiveDir]:
        if os.path.isdir(surDir):
            for eve in os.listdir(surDir):
                eveFile = os.path.join(surDir, eve)
                if os.path.isfile(eveFile):
                    checkFile(eveFile, filebeatReg=fbReg, checkLogs=True, checkArchives=False)

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
                print(f'removed empty directory "{dirToRm}" (used {dirAge} seconds ago)')
            except OSError:
                pass


def main():
    with open(lockFilename, 'w') as lock_file:
        try:
            fcntl.flock(lock_file, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except IOError:
            return
        else:
            pruneFiles()
        finally:
            os.remove(lockFilename)


if __name__ == '__main__':
    main()
