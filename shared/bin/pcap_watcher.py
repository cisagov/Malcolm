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
import json
import logging
import magic
import os
import pathlib
import re
import signal
import sys
import time
import zmq

from pcap_utils import (
    FILE_INFO_DICT_NAME,
    FILE_INFO_DICT_NODE,
    FILE_INFO_DICT_SIZE,
    FILE_INFO_DICT_TAGS,
    FILE_INFO_FILE_MIME,
    FILE_INFO_FILE_TYPE,
    PCAP_MIME_TYPES,
    PCAP_TOPIC_PORT,
    tags_from_filename,
)
import malcolm_utils
from malcolm_utils import eprint, str2bool, ParseCurlFile, remove_prefix, touch
import watch_common

from collections import defaultdict
from multiprocessing.pool import ThreadPool

from opensearchpy import OpenSearch, Search
from opensearchpy.exceptions import ConnectionError, ConnectionTimeout
from urllib3.exceptions import NewConnectionError

from watchdog.observers import Observer
from watchdog.observers.polling import PollingObserver
from watchdog.utils import WatchdogShutdown

###################################################################################################
MINIMUM_CHECKED_FILE_SIZE_DEFAULT = 24
MAXIMUM_CHECKED_FILE_SIZE_DEFAULT = 32 * 1024 * 1024 * 1024

###################################################################################################
# for querying the Arkime's "arkime_files" OpenSearch index to avoid re-processing (duplicating sessions for)
# files that have already been processed
ARKIME_FILES_INDEX = "arkime_files"
ARKIME_FILE_SIZE_FIELD = "filesize"

###################################################################################################
pdbFlagged = False
args = None
opensearchHttpAuth = None
scriptName = os.path.basename(__file__)
scriptPath = os.path.dirname(os.path.realpath(__file__))
origPath = os.getcwd()
shuttingDown = [False]
DEFAULT_NODE_NAME = os.getenv('PCAP_NODE_NAME', 'malcolm')


###################################################################################################
# watch files written to and moved to this directory
class EventWatcher:
    def __init__(self, logger=None):
        global args
        global opensearchHttpAuth
        global shuttingDown

        super().__init__()

        self.logger = logger if logger else logging
        self.useOpenSearch = False
        self.openSearchClient = None

        # if we're going to be querying OpenSearch for past PCAP file status, connect now
        if args.opensearchUrl is not None:
            connected = False
            healthy = False

            # create the connection to OpenSearch
            while (not connected) and (not shuttingDown[0]):
                try:
                    try:
                        self.logger.info(f"{scriptName}:\tconnecting to OpenSearch {args.opensearchUrl}...")

                        self.openSearchClient = OpenSearch(
                            hosts=[args.opensearchUrl],
                            http_auth=opensearchHttpAuth,
                            verify_certs=args.opensearchSslVerify,
                            ssl_assert_hostname=False,
                            ssl_show_warn=False,
                            request_timeout=1,
                        )

                        self.logger.debug(f"{scriptName}:\t{self.openSearchClient.cluster.health()}")

                        self.openSearchClient.cluster.health(
                            wait_for_status='red',
                            request_timeout=1,
                        )

                        self.logger.debug(f"{scriptName}:\t{self.openSearchClient.cluster.health()}")

                        connected = self.openSearchClient is not None
                        if not connected:
                            time.sleep(1)

                    except (
                        ConnectionError,
                        ConnectionTimeout,
                        ConnectionRefusedError,
                        NewConnectionError,
                    ) as connError:
                        self.logger.error(f"{scriptName}:\tOpenSearch connection error: {connError}")

                except Exception as genericError:
                    self.logger.error(
                        f"{scriptName}:\tUnexpected exception while connecting to OpenSearch: {genericError}"
                    )

                if (not connected) and args.opensearchWaitForHealth:
                    time.sleep(1)
                else:
                    if args.opensearchWaitForHealth:
                        time.sleep(1)
                    break

            # if requested, wait for at least "yellow" health in the cluster for the "files" index
            while connected and args.opensearchWaitForHealth and (not healthy) and (not shuttingDown[0]):
                try:
                    self.logger.info(f"{scriptName}:\twaiting for OpenSearch to be healthy")
                    self.openSearchClient.cluster.health(
                        index=ARKIME_FILES_INDEX,
                        wait_for_status='yellow',
                    )
                    self.logger.debug(f"{scriptName}:\t{self.openSearchClient.cluster.health()}")
                    healthy = True

                except (
                    ConnectionError,
                    ConnectionTimeout,
                    ConnectionRefusedError,
                    NewConnectionError,
                ) as connError:
                    self.logger.debug(f"{scriptName}:\tOpenSearch health check: {connError}")

                if not healthy:
                    time.sleep(1)

            self.useOpenSearch = connected and healthy

        # initialize ZeroMQ context and socket(s) to publish messages to
        self.context = zmq.Context()

        # Socket to send messages on
        self.logger.info(f"{scriptName}:\tbinding publisher port {PCAP_TOPIC_PORT}")
        self.topic_socket = self.context.socket(zmq.PUB)
        self.topic_socket.bind(f"tcp://*:{PCAP_TOPIC_PORT}")

        # todo: do I want to set this? probably not since this guy's whole job is to send
        # and if he can't then what's the point? just block
        # self.topic_socket.SNDTIMEO = 5000

        self.logger.info(f"{scriptName}:\tEventWatcher initialized")

    ###################################################################################################
    # set up event processor to append processed events from to the event queue
    def processFile(self, pathname):
        global args

        self.logger.info(f"{scriptName}:\t👓\t{pathname}")

        # the entity must be a regular PCAP file and actually exist
        if os.path.isfile(pathname):
            # get the file magic description and mime type
            fileMime = magic.from_file(pathname, mime=True)
            fileType = magic.from_file(pathname)

            # get the file size, in bytes to compare against sane values
            fileSize = os.path.getsize(pathname)
            if (args.minBytes <= fileSize <= args.maxBytes) and (
                (fileMime in PCAP_MIME_TYPES) or re.search(r'pcap-?ng', fileType, re.IGNORECASE)
            ):
                relativePath = remove_prefix(pathname, os.path.join(args.baseDir, ''))

                # check with Arkime's files index in OpenSearch and make sure it's not a duplicate
                fileIsDuplicate = False
                if self.useOpenSearch:
                    s = (
                        Search(using=self.openSearchClient, index=ARKIME_FILES_INDEX)
                        .filter("term", node=args.nodeName)
                        .query("wildcard", name=f"*{os.path.sep}{relativePath}")
                    )
                    response = s.execute()
                    for hit in response:
                        fileInfo = hit.to_dict()
                        if (ARKIME_FILE_SIZE_FIELD in fileInfo) and (fileInfo[ARKIME_FILE_SIZE_FIELD] == fileSize):
                            fileIsDuplicate = True
                            break

                if fileIsDuplicate:
                    # this is duplicate file (it's been processed before) so ignore it
                    self.logger.info(f"{scriptName}:\t📋\t{pathname}")

                else:
                    # the entity is a right-sized non-duplicate file, and it exists, so send it to get processed
                    self.logger.info(f"{scriptName}:\t📩\t{pathname}")
                    try:
                        fileInfo = {
                            FILE_INFO_DICT_NAME: pathname if args.includeAbsolutePath else relativePath,
                            FILE_INFO_DICT_SIZE: fileSize,
                            FILE_INFO_FILE_MIME: fileMime,
                            FILE_INFO_FILE_TYPE: fileType,
                            FILE_INFO_DICT_NODE: args.nodeName,
                            FILE_INFO_DICT_TAGS: tags_from_filename(relativePath),
                        }
                        self.topic_socket.send_string(json.dumps(fileInfo))
                        self.logger.info(f"{scriptName}:\t📫\t{fileInfo}")
                    except zmq.Again:
                        self.logger.debug(f"{scriptName}:\t🕑\t{pathname}")

            else:
                # too small/big to care about, or the wrong type, ignore it
                self.logger.info(f"{scriptName}:\t✋\t{pathname}")


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
    global opensearchHttpAuth
    global pdbFlagged
    global shuttingDown

    parser = argparse.ArgumentParser(description=scriptName, add_help=False, usage='{} <arguments>'.format(scriptName))
    parser.add_argument('--verbose', '-v', action='count', default=1, help='Increase verbosity (e.g., -v, -vv, etc.)')
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
    parser.add_argument(
        '--opensearch',
        required=False,
        dest='opensearchUrl',
        metavar='<STR>',
        type=str,
        default=os.getenv('OPENSEARCH_URL', None),
        help='OpenSearch connection string for querying Arkime files index to ignore duplicates',
    )
    parser.add_argument(
        '--opensearch-curlrc',
        dest='opensearchCurlRcFile',
        metavar='<filename>',
        type=str,
        default=os.getenv('OPENSEARCH_CREDS_CONFIG_FILE', '/var/local/curlrc/.opensearch.primary.curlrc'),
        help='cURL.rc formatted file containing OpenSearch connection parameters',
    )
    parser.add_argument(
        '--opensearch-ssl-verify',
        dest='opensearchSslVerify',
        type=str2bool,
        nargs='?',
        const=True,
        default=str2bool(os.getenv('OPENSEARCH_SSL_CERTIFICATE_VERIFICATION', default='False')),
        help="Verify SSL certificates for OpenSearch",
    )
    parser.add_argument(
        '--opensearch-local',
        dest='opensearchIsLocal',
        type=str2bool,
        nargs='?',
        const=True,
        default=str2bool(os.getenv('OPENSEARCH_LOCAL', default='True')),
        help="Malcolm is using its local OpenSearch instance",
    )
    parser.add_argument(
        '--opensearch-wait',
        dest='opensearchWaitForHealth',
        help="Wait for OpenSearch to be healthy before starting",
        metavar='true|false',
        type=str2bool,
        nargs='?',
        const=True,
        default=False,
        required=False,
    )
    parser.add_argument(
        '--node',
        required=False,
        dest='nodeName',
        metavar='<STR>',
        type=str,
        default=DEFAULT_NODE_NAME,
        help='PCAP source node name',
    )

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
        '--absolute-path',
        dest='includeAbsolutePath',
        help="Publish absolute path for message (vs. path relative to monitored directory)",
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
        default=os.getenv('PCAP_PIPELINE_POLLING', False),
        required=False,
    )
    parser.add_argument(
        '-c',
        '--closed-sec',
        dest='assumeClosedSec',
        help="When polling, assume a file is closed after this many seconds of inactivity",
        metavar='<seconds>',
        type=int,
        default=int(os.getenv('PCAP_PIPELINE_POLLING_ASSUME_CLOSED_SEC', str(watch_common.ASSUME_CLOSED_SEC_DEFAULT))),
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

    args.opensearchIsLocal = args.opensearchIsLocal or (args.opensearchUrl == 'http://opensearch:9200')
    opensearchCreds = (
        ParseCurlFile(args.opensearchCurlRcFile) if (not args.opensearchIsLocal) else defaultdict(lambda: None)
    )
    if not args.opensearchUrl:
        if args.opensearchIsLocal:
            args.opensearchUrl = 'http://opensearch:9200'
        elif 'url' in opensearchCreds:
            args.opensearchUrl = opensearchCreds['url']
    opensearchHttpAuth = (
        f"{opensearchCreds['user']}:{opensearchCreds['password']}" if opensearchCreds['user'] is not None else None
    )

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
        logging.debug(f"{scriptName}:\tScheduling {watchDir}")
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
