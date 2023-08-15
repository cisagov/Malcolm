#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2023 Battelle Energy Alliance, LLC.  All rights reserved.

###################################################################################################
# Monitor a directory for PCAP files for processing (by publishing their filenames to a ZMQ socket)
#
# Run the script with --help for options
###################################################################################################

import argparse
import glob
import logging
import magic
import os
import pathlib
import shutil
import signal
import sys
import time

import malcolm_utils
from malcolm_utils import eprint, str2bool, remove_suffix
import watch_common

###################################################################################################
scriptName = os.path.basename(__file__)
scriptPath = os.path.dirname(os.path.realpath(__file__))
origPath = os.getcwd()
shuttingDown = [False]

SUPPORTED_MIME_TYPES = [
    'application/gzip',
    'application/x-gzip',
    'application/x-7z-compressed',
    'application/x-bzip2',
    'application/x-cpio',
    'application/x-lzip',
    'application/x-lzma',
    'application/x-rar-compressed',
    'application/x-tar',
    'application/x-xz',
    'application/zip',
]


###################################################################################################
# handle sigint/sigterm and set a global shutdown variable
def shutdown_handler(signum, frame):
    global shuttingDown
    shuttingDown[0] = True


###################################################################################################
def file_processor(pathname, **kwargs):
    mime_types = kwargs["mime_types"]
    uid = kwargs["uid"]
    gid = kwargs["gid"]
    destination = kwargs["destination"]
    logger = kwargs["logger"] if "logger" in kwargs and kwargs["logger"] else logging

    logger.info(f"{scriptName}:\t👓\t{pathname}")

    if os.path.isfile(pathname) and os.path.isdir(destination):
        time.sleep(0.1)
        try:
            os.chown(pathname, uid, gid)

            # get the file magic mime type
            fileMime = magic.from_file(pathname, mime=True)

            if fileMime in mime_types:
                # looks like this is a compressed file, we're assuming it's a zeek log archive to be processed by filebeat
                logger.info(f"{scriptName}:\t🖅\t{pathname} [{fileMime}] to {destination}")
                shutil.move(pathname, os.path.join(destination, os.path.basename(pathname)))

            else:
                # unhandled file type uploaded, delete it
                logger.warning(f"{scriptName}:\t🗑\t{pathname} [{fileMime}]")
                os.unlink(pathname)

        except Exception as genericError:
            logger.error(f"{scriptName}:\texception: {genericError}")


###################################################################################################
# main
def main():
    global shuttingDown

    parser = argparse.ArgumentParser(
        description=scriptName,
        add_help=False,
        usage='{} <arguments>'.format(scriptName),
    )
    parser.add_argument('--verbose', '-v', action='count', default=1, help='Increase verbosity (e.g., -v, -vv, etc.)')
    parser.add_argument(
        '-r',
        '--recursive-directory',
        dest='recursiveDir',
        help="If specified, monitor all directories with this name underneath --directory",
        metavar='<name>',
        type=str,
        required=False,
    )
    parser.add_argument(
        '--recursive',
        dest='recursiveAll',
        help="Monitor all directories underneath --directory",
        metavar='true|false',
        type=str2bool,
        nargs='?',
        const=True,
        default=False,
        required=False,
    )
    parser.add_argument(
        '-p',
        '--polling',
        dest='polling',
        help="Use polling (instead of inotify)",
        metavar='true|false',
        type=str2bool,
        nargs='?',
        const=True,
        default=os.getenv('FILEBEAT_WATCHER_POLLING', False),
        required=False,
    )
    parser.add_argument(
        '-c',
        '--closed-sec',
        dest='assumeClosedSec',
        help="When polling, assume a file is closed after this many seconds of inactivity",
        metavar='<seconds>',
        type=int,
        default=int(
            os.getenv('FILEBEAT_WATCHER_POLLING_ASSUME_CLOSED_SEC', str(watch_common.ASSUME_CLOSED_SEC_DEFAULT))
        ),
        required=False,
    )
    parser.add_argument(
        '-i',
        '--in',
        dest='srcDir',
        help='Source directory to monitor',
        metavar='<directory>',
        type=str,
        default=os.path.join(remove_suffix(os.getenv('FILEBEAT_ZEEK_DIR', '/zeek'), '/'), 'upload'),
        required=False,
    )
    parser.add_argument(
        '-o',
        '--out',
        dest='dstDir',
        help='Destination directory',
        metavar='<directory>',
        type=str,
        default=remove_suffix(os.getenv('FILEBEAT_ZEEK_DIR', '/zeek'), '/'),
        required=False,
    )
    parser.add_argument(
        '-u',
        '--uid',
        dest='chownUid',
        help='UID to chown files',
        metavar='<integer>',
        type=int,
        default=int(os.getenv('PUID', os.getenv('DEFAULT_UID', '1000'))),
        required=False,
    )
    parser.add_argument(
        '-g',
        '--gid',
        dest='chownGid',
        help='UID to chown files',
        metavar='<integer>',
        type=int,
        default=int(os.getenv('PGID', os.getenv('DEFAULT_GID', '1000'))),
        required=False,
    )
    parser.add_argument(
        '--start-sleep',
        dest='startSleepSec',
        help="Sleep for this many seconds before starting",
        metavar='<seconds>',
        type=int,
        default=0,
        required=False,
    )

    try:
        parser.error = parser.exit
        args = parser.parse_args()
    except SystemExit:
        parser.print_help()
        exit(2)

    args.verbose = logging.ERROR - (10 * args.verbose) if args.verbose > 0 else 0
    logging.basicConfig(
        level=args.verbose, format='%(asctime)s %(levelname)s: %(message)s', datefmt='%Y-%m-%d %H:%M:%S'
    )
    logging.info(os.path.join(scriptPath, scriptName))
    logging.info("Arguments: {}".format(sys.argv[1:]))
    logging.info("Arguments: {}".format(args))
    if args.verbose > logging.DEBUG:
        sys.tracebacklimit = 0

    # handle sigint and sigterm for graceful shutdown
    signal.signal(signal.SIGINT, shutdown_handler)
    signal.signal(signal.SIGTERM, shutdown_handler)

    # sleep for a bit if requested
    sleepCount = 0
    while (not shuttingDown[0]) and (sleepCount < args.startSleepSec):
        time.sleep(1)
        sleepCount += 1

    args.dstDir = remove_suffix(args.dstDir, '/')
    args.srcDir = remove_suffix(args.srcDir, '/')

    # if directory to monitor doesn't exist, create it now
    if not os.path.isdir(args.srcDir):
        logging.info(f'{scriptName}:\tcreating "{args.srcDir}" to monitor')
        pathlib.Path(args.srcDir).mkdir(parents=False, exist_ok=True)

    # if recursion was requested, get list of directories to monitor
    watchDirs = []
    while len(watchDirs) == 0:
        if args.recursiveDir is None:
            watchDirs = [args.srcDir]
        else:
            watchDirs = glob.glob(f'{args.srcDir}/**/{args.recursiveDir}', recursive=True)

    watch_common.WatchAndProcessDirectory(
        watchDirs,
        args.polling,
        args.recursiveAll,
        file_processor,
        {
            "logger": logging,
            "destination": args.dstDir,
            "uid": args.chownUid,
            "gid": args.chownGid,
            "mime_types": SUPPORTED_MIME_TYPES,
        },
        args.assumeClosedSec,
        shuttingDown,
        logging,
    )


if __name__ == '__main__':
    main()
