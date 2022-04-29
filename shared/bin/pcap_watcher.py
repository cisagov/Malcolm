#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2022 Battelle Energy Alliance, LLC.  All rights reserved.

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
import pyinotify
import signal
import sys
import time
import zmq

from pcap_utils import *

import opensearchpy
import opensearch_dsl

###################################################################################################
MINIMUM_CHECKED_FILE_SIZE_DEFAULT = 24
MAXIMUM_CHECKED_FILE_SIZE_DEFAULT = 32 * 1024 * 1024 * 1024

###################################################################################################
# for querying the Arkime's "arkime_files" OpenSearch index to avoid re-processing (duplicating sessions for)
# files that have already been processed
ARKIME_FILES_INDEX = "arkime_files"
ARKIME_FILE_TYPE = "file"
ARKIME_FILE_SIZE_FIELD = "filesize"

###################################################################################################
debug = False
verboseDebug = False
pdbFlagged = False
args = None
scriptName = os.path.basename(__file__)
scriptPath = os.path.dirname(os.path.realpath(__file__))
origPath = os.getcwd()
shuttingDown = False
DEFAULT_NODE_NAME = os.getenv('PCAP_NODE_NAME', 'malcolm')

###################################################################################################
# watch files written to and moved to this directory
class EventWatcher(pyinotify.ProcessEvent):

    # notify on files written in-place then closed (IN_CLOSE_WRITE), and moved into this directory (IN_MOVED_TO)
    _methods = ["IN_CLOSE_WRITE", "IN_MOVED_TO"]

    def __init__(self):
        global args
        global debug
        global verboseDebug

        super().__init__()

        self.useOpenSearch = False

        # if we're going to be querying OpenSearch for past PCAP file status, connect now
        if args.opensearchHost is not None:

            connected = False
            healthy = False

            # create the connection to OpenSearch
            while (not connected) and (not shuttingDown):
                try:
                    if debug:
                        eprint(f"{scriptName}:\tconnecting to OpenSearch {args.opensearchHost}...")
                    opensearch_dsl.connections.create_connection(hosts=[args.opensearchHost])
                    if verboseDebug:
                        eprint(f"{scriptName}:\t{opensearch_dsl.connections.get_connection().cluster.health()}")
                    connected = opensearch_dsl.connections.get_connection() is not None

                except opensearchpy.exceptions.ConnectionError as connError:
                    if debug:
                        eprint(f"{scriptName}:\tOpenSearch connection error: {connError}")

                if (not connected) and args.opensearchWaitForHealth:
                    time.sleep(1)
                else:
                    break

            # if requested, wait for at least "yellow" health in the cluster for the "files" index
            while connected and args.opensearchWaitForHealth and (not healthy) and (not shuttingDown):
                try:
                    if debug:
                        eprint(f"{scriptName}:\twaiting for OpenSearch to be healthy")
                    opensearch_dsl.connections.get_connection().cluster.health(
                        index=ARKIME_FILES_INDEX, wait_for_status='yellow'
                    )
                    if verboseDebug:
                        eprint(f"{scriptName}:\t{opensearch_dsl.connections.get_connection().cluster.health()}")
                    healthy = True

                except opensearchpy.exceptions.ConnectionTimeout as connError:
                    if verboseDebug:
                        eprint(f"{scriptName}:\tOpenSearch health check: {connError}")

                if not healthy:
                    time.sleep(1)

            self.useOpenSearch = connected and healthy

        # initialize ZeroMQ context and socket(s) to publish messages to
        self.context = zmq.Context()

        # Socket to send messages on
        if debug:
            eprint(f"{scriptName}:\tbinding publisher port {PCAP_TOPIC_PORT}")
        self.topic_socket = self.context.socket(zmq.PUB)
        self.topic_socket.bind(f"tcp://*:{PCAP_TOPIC_PORT}")

        # todo: do I want to set this? probably not since this guy's whole job is to send
        # and if he can't then what's the point? just block
        # self.topic_socket.SNDTIMEO = 5000

        if debug:
            eprint(f"{scriptName}:\tEventWatcher initialized")


###################################################################################################
# set up event processor to append processed events from to the event queue
def event_process_generator(cls, method):

    # actual method called when we are notified of a file
    def _method_name(self, event):

        global args
        global debug
        global verboseDebug

        if debug:
            eprint(f"{scriptName}:\t👓\t{event.pathname}")

        # the entity must be a regular PCAP file and actually exist
        if (not event.dir) and os.path.isfile(event.pathname):

            # get the file magic description and mime type
            fileMime = magic.from_file(event.pathname, mime=True)
            fileType = magic.from_file(event.pathname)

            # get the file size, in bytes to compare against sane values
            fileSize = os.path.getsize(event.pathname)
            if (args.minBytes <= fileSize <= args.maxBytes) and (
                (fileMime in PCAP_MIME_TYPES) or ('pcap-ng' in fileType)
            ):

                relativePath = remove_prefix(event.pathname, os.path.join(args.baseDir, ''))

                # check with Arkime's files index in OpenSearch and make sure it's not a duplicate
                fileIsDuplicate = False
                if self.useOpenSearch:
                    s = (
                        opensearch_dsl.Search(index=ARKIME_FILES_INDEX)
                        .filter("term", _type=ARKIME_FILE_TYPE)
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
                    if debug:
                        eprint(f"{scriptName}:\t📋\t{event.pathname}")

                else:
                    # the entity is a right-sized non-duplicate file, and it exists, so send it to get processed
                    if debug:
                        eprint(f"{scriptName}:\t📩\t{event.pathname}")
                    try:
                        fileInfo = {
                            FILE_INFO_DICT_NAME: event.pathname if args.includeAbsolutePath else relativePath,
                            FILE_INFO_DICT_SIZE: fileSize,
                            FILE_INFO_FILE_MIME: fileMime,
                            FILE_INFO_FILE_TYPE: fileType,
                            FILE_INFO_DICT_NODE: args.nodeName,
                            FILE_INFO_DICT_TAGS: tags_from_filename(relativePath),
                        }
                        self.topic_socket.send_string(json.dumps(fileInfo))
                        if debug:
                            eprint(f"{scriptName}:\t📫\t{fileInfo}")
                    except zmq.Again as timeout:
                        if verboseDebug:
                            eprint(f"{scriptName}:\t🕑\t{event.pathname}")

            else:
                # too small/big to care about, or the wrong type, ignore it
                if debug:
                    eprint(f"{scriptName}:\t✋\t{event.pathname}")

    # assign process method to class
    _method_name.__name__ = "process_{}".format(method)
    setattr(cls, _method_name.__name__, _method_name)


###################################################################################################
# handle sigint/sigterm and set a global shutdown variable
def shutdown_handler(signum, frame):
    global shuttingDown
    shuttingDown = True


###################################################################################################
# handle sigusr1 for a pdb breakpoint
def pdb_handler(sig, frame):
    global pdbFlagged
    pdbFlagged = True


###################################################################################################
# handle sigusr2 for toggling debug
def debug_toggle_handler(signum, frame):
    global debug
    global debugToggled
    debug = not debug
    debugToggled = True


###################################################################################################
# main
def main():
    global args
    global debug
    global verboseDebug
    global debugToggled
    global pdbFlagged
    global shuttingDown

    parser = argparse.ArgumentParser(description=scriptName, add_help=False, usage='{} <arguments>'.format(scriptName))
    parser.add_argument(
        '-v',
        '--verbose',
        dest='debug',
        help="Verbose output",
        metavar='true|false',
        type=str2bool,
        nargs='?',
        const=True,
        default=False,
        required=False,
    )
    parser.add_argument(
        '--extra-verbose',
        dest='verboseDebug',
        help="Super verbose output",
        metavar='true|false',
        type=str2bool,
        nargs='?',
        const=True,
        default=False,
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
    parser.add_argument(
        '--opensearch',
        required=False,
        dest='opensearchHost',
        metavar='<STR>',
        type=str,
        default=None,
        help='OpenSearch connection string for querying Arkime files index to ignore duplicates',
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

    verboseDebug = args.verboseDebug
    debug = args.debug or verboseDebug
    if debug:
        eprint(os.path.join(scriptPath, scriptName))
        eprint("{} arguments: {}".format(scriptName, sys.argv[1:]))
        eprint("{} arguments: {}".format(scriptName, args))
    else:
        sys.tracebacklimit = 0

    logging.basicConfig(level=logging.ERROR)

    # handle sigint and sigterm for graceful shutdown
    signal.signal(signal.SIGINT, shutdown_handler)
    signal.signal(signal.SIGTERM, shutdown_handler)
    signal.signal(signal.SIGUSR1, pdb_handler)
    signal.signal(signal.SIGUSR2, debug_toggle_handler)

    # sleep for a bit if requested
    sleepCount = 0
    while (not shuttingDown) and (sleepCount < args.startSleepSec):
        time.sleep(1)
        sleepCount += 1

    # add events to watch to EventWatcher class
    for method in EventWatcher._methods:
        event_process_generator(EventWatcher, method)

    # if directory to monitor doesn't exist, create it now
    if os.path.isdir(args.baseDir):
        preexistingDir = True
    else:
        preexistingDir = False
        if debug:
            eprint(f'{scriptname}: creating "{args.baseDir}" to monitor')
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

    event_notifier_started = False
    watch_manager = pyinotify.WatchManager()
    event_notifier = pyinotify.ThreadedNotifier(watch_manager, EventWatcher())
    for watchDir in watchDirs:
        watch_manager.add_watch(os.path.abspath(watchDir), pyinotify.ALL_EVENTS)
    if debug:
        eprint(f"{scriptName}: monitoring {watchDirs}")
    time.sleep(2)
    if not shuttingDown:
        event_notifier.start()
        event_notifier_started = True

    # if there are any previously included files (and not ignoreExisting), "touch" them so that they will be notified on
    if preexistingDir and (not args.ignoreExisting) and (not shuttingDown):
        filesTouched = 0
        for watchDir in watchDirs:
            for preexistingFile in [os.path.join(watchDir, x) for x in pathlib.Path(watchDir).iterdir() if x.is_file()]:
                touch(preexistingFile)
                filesTouched += 1
        if debug and (filesTouched > 0):
            eprint(f"{scriptName}: found {filesTouched} preexisting files to check")

    # loop forever, or until we're told to shut down, whichever comes first
    while not shuttingDown:
        if pdbFlagged:
            pdbFlagged = False
            breakpoint()
        time.sleep(0.2)

    # graceful shutdown
    if debug:
        eprint(f"{scriptName}: shutting down...")
    if event_notifier_started:
        event_notifier.stop()
    time.sleep(1)

    if debug:
        eprint(f"{scriptName}: finished monitoring {watchDirs}")


if __name__ == '__main__':
    main()
