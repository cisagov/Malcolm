#!/usr/bin/env python3

# Copyright (c) 2022 Battelle Energy Alliance, LLC.  All rights reserved.


import os
from os.path import splitext
from tempfile import gettempdir
import errno
import time
import fcntl
import fnmatch
import magic
import json
import pprint
import re
from subprocess import Popen, PIPE

lockFilename = os.path.join(gettempdir(), '{}.lock'.format(os.path.basename(__file__)))
broDir = os.path.join(os.getenv('FILEBEAT_ZEEK_DIR', "/data/zeek/"), '')
cleanLogSeconds = int(os.getenv('LOG_CLEANUP_MINUTES', "30")) * 60
cleanZipSeconds = int(os.getenv('ZIP_CLEANUP_MINUTES', "120")) * 60
fbRegFilename = os.getenv('FILEBEAT_REGISTRY_FILE', "/usr/share/filebeat/data/registry/filebeat/data.json")
currentDir = broDir + "current/"
processedDir = broDir + "processed/"

import os, errno


def silentRemove(filename):
    try:
        if os.path.isfile(filename) or os.path.islink(filename):
            os.remove(filename)
        elif os.path.isdir(filename):
            os.rmdir(filename)
    except OSError:
        pass


def pruneFiles():

    if (cleanLogSeconds <= 0) and (cleanZipSeconds <= 0):
        # disabled, don't do anything
        return

    nowTime = time.time()

    logMimeType = "text/plain"
    archiveMimeTypeRegex = re.compile(
        r"(application/gzip|application/x-gzip|application/x-7z-compressed|application/x-bzip2|application/x-cpio|application/x-lzip|application/x-lzma|application/x-rar-compressed|application/x-tar|application/x-xz|application/zip)"
    )

    # look for regular files in the processed/ directory
    foundFiles = [
        (os.path.join(root, filename)) for root, dirnames, filenames in os.walk(processedDir) for filename in filenames
    ]

    # look up the filebeat registry file and try to read it
    fbReg = None
    if os.path.isfile(fbRegFilename):
        with open(fbRegFilename) as f:
            fbReg = json.load(f)

    # see if the files we found are in use and old enough to be pruned
    for file in foundFiles:

        # first check to see if it's in the filebeat registry
        if fbReg is not None:
            fileStatInfo = os.stat(file)
            if fileStatInfo:
                fileFound = any(
                    (
                        (entry['FileStateOS'])
                        and (entry['FileStateOS']['device'] == fileStatInfo.st_dev)
                        and (entry['FileStateOS']['inode'] == fileStatInfo.st_ino)
                    )
                    for entry in fbReg
                )
                if fileFound:
                    # found a file in the filebeat registry, so leave it alone!
                    # we only want to delete files that filebeat has forgotten
                    # print "{} is found in registry!".format(file)
                    continue
                # else:
                # print "{} is NOT found in registry!".format(file)

        # now see if the file is in use by any other process in the system
        fuserProcess = Popen(["fuser", "-s", file], stdout=PIPE)
        fuserProcess.communicate()
        fuserExitCode = fuserProcess.wait()
        if fuserExitCode != 0:

            # the file is not in use, let's check it's mtime/ctime
            logTime = max(os.path.getctime(file), os.path.getmtime(file))
            lastUseTime = nowTime - logTime

            # get the file type
            fileType = magic.from_file(file, mime=True)
            if (cleanLogSeconds > 0) and (fileType == logMimeType):
                cleanSeconds = cleanLogSeconds
            elif (cleanZipSeconds > 0) and archiveMimeTypeRegex.match(fileType) is not None:
                cleanSeconds = cleanZipSeconds
            else:
                # not a file we're going to be messing with
                cleanSeconds = 0

            if (cleanSeconds > 0) and (lastUseTime >= cleanSeconds):
                # this is a closed file that is old, so delete it
                print('removing old file "{}" ({}, used {} seconds ago)'.format(file, fileType, lastUseTime))
                silentRemove(file)

    # clean up any broken symlinks in the current/ directory
    for current in os.listdir(currentDir):
        currentFileSpec = os.path.join(currentDir, current)
        if os.path.islink(currentFileSpec) and not os.path.exists(currentFileSpec):
            print('removing dead symlink "{}"'.format(currentFileSpec))
            silentRemove(currentFileSpec)

    # clean up any old and empty directories in processed/ directory
    cleanDirSeconds = min(i for i in (cleanLogSeconds, cleanZipSeconds) if i > 0)
    candidateDirs = []
    for root, dirs, files in os.walk(processedDir, topdown=False):
        if root and dirs:
            candidateDirs += [os.path.join(root, tmpDir) for tmpDir in dirs]
    candidateDirs = list(set(candidateDirs))
    candidateDirs.sort(reverse=True)
    candidateDirs.sort(key=len, reverse=True)
    candidateDirsAndTimes = zip(candidateDirs, [os.path.getmtime(dirToRm) for dirToRm in candidateDirs])
    for (dirToRm, dirTime) in candidateDirsAndTimes:
        dirAge = nowTime - dirTime
        if dirAge >= cleanDirSeconds:
            try:
                os.rmdir(dirToRm)
                print('removed empty directory "{}" (used {} seconds ago)'.format(dirToRm, dirAge))
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
