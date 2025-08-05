#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2025 Battelle Energy Alliance, LLC.  All rights reserved.

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
import re
import shutil
import signal
import sys
import time

import malcolm_utils
from malcolm_utils import str2bool, remove_suffix, set_logging, get_verbosity_env_var_count
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
    # windows event logs (idaholab/Malcolm#465) will be handled here as well, as they
    # may be uploaded either as-is or compressed
    'application/x-ms-evtx',
]

# PITA... The version of the "file" utility in the filebeat container
#   gives "application/octet-stream" instead of "application/x-ms-evtx"
#   for Windows .evtx files.
#   A similar check exists in filebeat-process-zeek-folder.sh
SUPPORTED_FILE_TYPE_REGEXES = [
    r'Windows.*Event Log',
]


###################################################################################################
# handle sigint/sigterm and set a global shutdown variable
def shutdown_handler(signum, frame):
    global shuttingDown
    shuttingDown[0] = True


###################################################################################################
def file_processor(pathname, **kwargs):
    mime_types = kwargs["mime_types"]
    file_type_regexes = kwargs["file_types"]
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
            fileType = magic.from_file(pathname)

            if (fileMime in mime_types) or any([re.search(reg, fileType, re.IGNORECASE) for reg in file_type_regexes]):
                # looks like this is a compressed file (or evtx file), we're assuming it's:
                #  * a zeek log archive to be processed by filebeat
                #  * a windows event log archive to be processed into JSON and then also sent through filebeat
                logger.info(f"{scriptName}:\t🖅\t{pathname} [{fileMime}] to {destination}")
                shutil.move(pathname, os.path.join(destination, os.path.basename(pathname)))

            else:
                # unhandled file type uploaded, delete it
                logger.warning(f"{scriptName}:\t🗑\t{pathname} [{fileMime} unsupported file type, deleted]")
                os.unlink(pathname)

        except Exception as genericError:
            logger.critical(f"{scriptName}:\texception: {genericError}")


###################################################################################################
# main
def main():
    global shuttingDown

    parser = argparse.ArgumentParser(
        description=scriptName,
        add_help=True,
        usage='{} <arguments>'.format(scriptName),
    )
    parser.add_argument(
        '--verbose',
        '-v',
        action='count',
        default=get_verbosity_env_var_count("PCAP_PIPELINE_VERBOSITY"),
        help='Increase verbosity (e.g., -v, -vv, etc.)',
    )
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
        args = parser.parse_args()
    except SystemExit as e:
        if e.code == 2:
            parser.print_help()
        sys.exit(e.code)

    args.verbose = set_logging(os.getenv("PCAP_PIPELINE_LOGLEVEL", ""), args.verbose, set_traceback_limit=True)
    logging.debug(os.path.join(scriptPath, scriptName))
    logging.debug(f"Arguments: {sys.argv[1:]}")
    logging.debug(f"Arguments: {args}")

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
            "file_types": SUPPORTED_FILE_TYPE_REGEXES,
        },
        args.assumeClosedSec,
        shuttingDown,
        logging,
    )


if __name__ == '__main__':
    main()
