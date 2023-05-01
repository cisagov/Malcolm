#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2023 Battelle Energy Alliance, LLC.  All rights reserved.

###################################################################################################
# Monitor a directory for files extracted by zeek for processing
#
# Run the script with --help for options
###################################################################################################

import argparse
import glob
import json
import logging
import magic
import os
import pathlib
import signal
import sys
import time
import zmq

from multiprocessing.pool import ThreadPool
from watchdog.observers import Observer
from watchdog.observers.polling import PollingObserver
from watchdog.utils import WatchdogShutdown

from zeek_carve_utils import (
    CAPA_VIV_MIME,
    CAPA_VIV_SUFFIX,
    FILE_SCAN_RESULT_FILE,
    FILE_SCAN_RESULT_FILE_SIZE,
    FILE_SCAN_RESULT_FILE_TYPE,
    VENTILATOR_PORT,
)

import malcolm_utils
from malcolm_utils import touch, eprint, str2bool
import watch_common

###################################################################################################
MINIMUM_CHECKED_FILE_SIZE_DEFAULT = 64
MAXIMUM_CHECKED_FILE_SIZE_DEFAULT = 134217728

###################################################################################################
pdbFlagged = False
args = None
scriptName = os.path.basename(__file__)
scriptPath = os.path.dirname(os.path.realpath(__file__))
origPath = os.getcwd()
shuttingDown = [False]


###################################################################################################
# watch files written to and moved to this directory
class EventWatcher:
    def __init__(self, logger=None):
        super().__init__()

        self.logger = logger if logger else logging

        # initialize ZeroMQ context and socket(s) to send messages to
        self.context = zmq.Context()

        # Socket to send messages on
        self.logger.info(f"{scriptName}:\tbinding ventilator port {VENTILATOR_PORT}")
        self.ventilator_socket = self.context.socket(zmq.PUB)
        self.ventilator_socket.bind(f"tcp://*:{VENTILATOR_PORT}")

        # todo: do I want to set this? probably not since this guy's whole job is to send
        # and if he can't then what's the point? just block
        # self.ventilator_socket.SNDTIMEO = 5000

        self.logger.info(f"{scriptName}:\tEventWatcher initialized")

    ###################################################################################################
    # set up event processor to append processed events from to the event queue
    def processFile(self, pathname):
        global args

        self.logger.info(f"{scriptName}:\t👓\t{pathname}")

        if os.path.isfile(pathname):
            fileSize = os.path.getsize(pathname)
            if args.minBytes <= fileSize <= args.maxBytes:
                fileType = magic.from_file(pathname, mime=True)
                if (pathlib.Path(pathname).suffix != CAPA_VIV_SUFFIX) and (fileType != CAPA_VIV_MIME):
                    # the entity is a right-sized file, is not a capa .viv cache file, and it exists, so send it to get scanned

                    fileInfo = json.dumps(
                        {
                            FILE_SCAN_RESULT_FILE: pathname,
                            FILE_SCAN_RESULT_FILE_SIZE: fileSize,
                            FILE_SCAN_RESULT_FILE_TYPE: fileType,
                        }
                    )
                    self.logger.info(f"{scriptName}:\t📩\t{fileInfo}")
                    try:
                        self.ventilator_socket.send_string(fileInfo)
                        self.logger.info(f"{scriptName}:\t📫\t{pathname}")
                    except zmq.Again:
                        self.logger.debug(f"{scriptName}:\t🕑\t{pathname}")

                else:
                    # temporary capa .viv file, just ignore it as it will get cleaned up by the scanner when it's done
                    self.logger.info(f"{scriptName}:\t🚧\t{pathname}")

            else:
                # too small/big to care about, delete it
                os.remove(pathname)
                self.logger.info(f"{scriptName}:\t🚫\t{pathname}")


def file_processor(pathname, **kwargs):
    if "watcher" in kwargs and kwargs["watcher"]:
        kwargs["watcher"].processFile(pathname)


###################################################################################################
# handle sigint/sigterm and set a global shutdown variable
def shutdown_handler(signum, frame):
    global shuttingDown
    shuttingDown[0] = True


###################################################################################################
# handle sigusr1 for a pdb breakpoint
def pdb_handler(sig, frame):
    global pdbFlagged
    pdbFlagged = True


###################################################################################################
# main
def main():
    global args
    global pdbFlagged
    global shuttingDown

    parser = argparse.ArgumentParser(description=scriptName, add_help=False, usage='{} <arguments>'.format(scriptName))
    parser.add_argument('--verbose', '-v', action='count', default=1, help='Increase verbosity (e.g., -v, -vv, etc.)')
    parser.add_argument(
        '--ignore-existing',
        dest='ignoreExisting',
        help="Ignore preexisting files in the monitor directory",
        metavar='true|false',
        type=str2bool,
        nargs='?',
        const=True,
        default=False,
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
        '-p',
        '--polling',
        dest='polling',
        help="Use polling (instead of inotify)",
        metavar='true|false',
        type=str2bool,
        nargs='?',
        const=True,
        default=os.getenv('EXTRACTED_FILE_WATCHER_POLLING', False),
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
            os.getenv('EXTRACTED_FILE_WATCHER_POLLING_ASSUME_CLOSED_SEC', str(watch_common.ASSUME_CLOSED_SEC_DEFAULT))
        ),
        required=False,
    )
    parser.add_argument(
        '--min-bytes',
        dest='minBytes',
        help="Minimum size for checked files",
        metavar='<bytes>',
        type=int,
        default=MINIMUM_CHECKED_FILE_SIZE_DEFAULT,
        required=False,
    )
    parser.add_argument(
        '--max-bytes',
        dest='maxBytes',
        help="Maximum size for checked files",
        metavar='<bytes>',
        type=int,
        default=MAXIMUM_CHECKED_FILE_SIZE_DEFAULT,
        required=False,
    )
    requiredNamed = parser.add_argument_group('required arguments')
    requiredNamed.add_argument(
        '-d', '--directory', dest='baseDir', help='Directory to monitor', metavar='<directory>', type=str, required=True
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
    signal.signal(signal.SIGUSR1, pdb_handler)

    # sleep for a bit if requested
    sleepCount = 0
    while (not shuttingDown[0]) and (sleepCount < args.startSleepSec):
        time.sleep(1)
        sleepCount += 1

    # if directory to monitor doesn't exist, create it now
    if os.path.isdir(args.baseDir):
        preexistingDir = True
    else:
        preexistingDir = False
        logging.info(f'{scriptName}:\tcreating "{args.baseDir}" to monitor')
        pathlib.Path(args.baseDir).mkdir(parents=False, exist_ok=True)

    # if recursion was requested, get list of directories to monitor
    watchDirs = []
    while len(watchDirs) == 0:
        if args.recursiveDir is None:
            watchDirs = [args.baseDir]
        else:
            watchDirs = glob.glob(f'{args.baseDir}/**/{args.recursiveDir}', recursive=True)

    # begin threaded watch of path(s)
    time.sleep(1)

    observer = PollingObserver() if args.polling else Observer()
    handler = watch_common.FileOperationEventHandler(
        logger=None,
        polling=args.polling,
    )
    for watchDir in watchDirs:
        logging.info(f"{scriptName}:\tScheduling {watchDir}")
        observer.schedule(handler, watchDir, recursive=False)

    observer.start()

    logging.info(f"{scriptName}:\tmonitoring {watchDirs}")

    try:
        time.sleep(2)

        # if there are any previously included files (and not ignoreExisting), "touch" them so that they will be notified on
        if preexistingDir and (not args.ignoreExisting) and (not shuttingDown[0]):
            filesTouched = 0
            for watchDir in watchDirs:
                for preexistingFile in [
                    os.path.join(watchDir, x) for x in pathlib.Path(watchDir).iterdir() if x.is_file()
                ]:
                    touch(preexistingFile)
                    filesTouched += 1
            if filesTouched > 0:
                logging.info(f"{scriptName}:\tfound {filesTouched} preexisting files to check")

        # start the thread to actually handle the files as they're queued by the FileOperationEventHandler handler
        workerThreadCount = malcolm_utils.AtomicInt(value=0)
        ThreadPool(
            1,
            watch_common.ProcessFileEventWorker(
                [
                    handler,
                    observer,
                    file_processor,
                    {'watcher': EventWatcher(logger=logging)},
                    args.assumeClosedSec,
                    workerThreadCount,
                    shuttingDown,
                    logging,
                ],
            ),
        )

        # loop forever, or until we're told to shut down, whichever comes first
        while (not shuttingDown[0]) and observer.is_alive():
            if pdbFlagged:
                pdbFlagged = False
                breakpoint()
            observer.join(1)

        # graceful shutdown
        logging.info(f"{scriptName}:\tshutting down...")

        if shuttingDown[0]:
            raise WatchdogShutdown()

    except WatchdogShutdown:
        observer.unschedule_all()

    finally:
        observer.stop()
        observer.join()

    time.sleep(1)
    while workerThreadCount.value() > 0:
        time.sleep(1)

    logging.info(f"{scriptName}:\tfinished monitoring {watchDirs}")


if __name__ == '__main__':
    main()
