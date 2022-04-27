#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2022 Battelle Energy Alliance, LLC.  All rights reserved.

###################################################################################################
# Process queued files reported by pcap_watcher.py, using either arkime's capture or zeek to process
# them for session creation and logging into the OpenSearch database
#
# Run the script with --help for options
###################################################################################################

import argparse
import json
import os
import shutil
import signal
import sys
import tarfile
import tempfile
import time
import zmq

from pcap_utils import *
from multiprocessing.pool import ThreadPool
from collections import deque
from itertools import chain, repeat

###################################################################################################
MAX_WORKER_PROCESSES_DEFAULT = 1

PCAP_PROCESSING_MODE_ARKIME = "arkime"
PCAP_PROCESSING_MODE_ZEEK = "zeek"

ARKIME_CAPTURE_PATH = "/opt/arkime/bin/capture"

ZEEK_PATH = "/opt/zeek/bin/zeek"
ZEEK_EXTRACTOR_MODE_INTERESTING = 'interesting'
ZEEK_EXTRACTOR_MODE_MAPPED = 'mapped'
ZEEK_EXTRACTOR_MODE_NONE = 'none'
ZEEK_EXTRACTOR_SCRIPT = "extractor.zeek"
ZEEK_EXTRACTOR_SCRIPT_INTERESTING = "extractor_override.interesting.zeek"
ZEEK_LOCAL_SCRIPT = 'local'
ZEEK_STATE_DIR = '.state'
ZEEK_AUTOZEEK_TAG = 'AUTOZEEK'
ZEEK_AUTOCARVE_TAG_PREFIX = 'AUTOCARVE'
ZEEK_USERTAG_TAG = 'USERTAG'
ZEEK_EXTRACTOR_MODE_ENV_VAR = 'ZEEK_EXTRACTOR_MODE'
ZEEK_LOG_COMPRESSION_LEVEL = 6

###################################################################################################
debug = False
verboseDebug = False
debugToggled = False
pdbFlagged = False
args = None
scriptName = os.path.basename(__file__)
scriptPath = os.path.dirname(os.path.realpath(__file__))
origPath = os.getcwd()
shuttingDown = False
scanWorkersCount = AtomicInt(value=0)
arkimeProvider = os.getenv('ARKIME_ECS_PROVIDER', 'arkime')
arkimeDataset = os.getenv('ARKIME_ECS_DATASET', 'session')

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
def arkimeCaptureFileWorker(arkimeWorkerArgs):
    global debug
    global verboseDebug
    global shuttingDown
    global scanWorkersCount
    global arkimeProvider
    global arkimeDataset

    scanWorkerId = scanWorkersCount.increment()  # unique ID for this thread

    newFileQueue, pcapBaseDir, arkimeBin, autotag, notLocked = (
        arkimeWorkerArgs[0],
        arkimeWorkerArgs[1],
        arkimeWorkerArgs[2],
        arkimeWorkerArgs[3],
        arkimeWorkerArgs[4],
    )

    if debug:
        eprint(f"{scriptName}[{scanWorkerId}]:\tstarted")

    # loop forever, or until we're told to shut down
    while not shuttingDown:
        try:
            # pull an item from the queue of files that need to be processed
            fileInfo = newFileQueue.popleft()
        except IndexError:
            time.sleep(1)
        else:
            if isinstance(fileInfo, dict) and (FILE_INFO_DICT_NAME in fileInfo):

                if pcapBaseDir and os.path.isdir(pcapBaseDir):
                    fileInfo[FILE_INFO_DICT_NAME] = os.path.join(pcapBaseDir, fileInfo[FILE_INFO_DICT_NAME])

                if os.path.isfile(fileInfo[FILE_INFO_DICT_NAME]):
                    # finalize tags list
                    fileInfo[FILE_INFO_DICT_TAGS] = (
                        [
                            x
                            for x in fileInfo[FILE_INFO_DICT_TAGS]
                            if (x != ZEEK_AUTOZEEK_TAG)
                            and (x != ZEEK_USERTAG_TAG)
                            and (not x.startswith(ZEEK_AUTOCARVE_TAG_PREFIX))
                        ]
                        if ((FILE_INFO_DICT_TAGS in fileInfo) and autotag)
                        else list()
                    )
                    if debug:
                        eprint(f"{scriptName}[{scanWorkerId}]:\t🔎\t{fileInfo}")

                    # put together arkime execution command
                    cmd = [
                        arkimeBin,
                        '--quiet',
                        '-o',
                        f'ecsEventProvider={arkimeProvider}',
                        '-o',
                        f'ecsEventDataset={arkimeDataset}',
                        '-r',
                        fileInfo[FILE_INFO_DICT_NAME],
                    ]
                    if notLocked:
                        cmd.append('--nolockpcap')
                    cmd.extend(list(chain.from_iterable(zip(repeat('-t'), fileInfo[FILE_INFO_DICT_TAGS]))))

                    # execute capture for pcap file
                    retcode, output = run_process(cmd, debug=verboseDebug)
                    if retcode == 0:
                        if debug:
                            eprint(
                                f"{scriptName}[{scanWorkerId}]:\t✅\t{os.path.basename(fileInfo[FILE_INFO_DICT_NAME])}"
                            )
                    else:
                        if debug:
                            eprint(
                                f"{scriptName}[{scanWorkerId}]:\t❗\t{arkimeBin} {os.path.basename(fileInfo[FILE_INFO_DICT_NAME])} returned {retcode} {output if verboseDebug else ''}"
                            )

    if debug:
        eprint(f"{scriptName}[{scanWorkerId}]:\tfinished")


###################################################################################################
def zeekFileWorker(zeekWorkerArgs):
    global debug
    global verboseDebug
    global shuttingDown
    global scanWorkersCount

    scanWorkerId = scanWorkersCount.increment()  # unique ID for this thread

    newFileQueue, pcapBaseDir, zeekBin, autozeek, autotag, uploadDir, defaultExtractFileMode = (
        zeekWorkerArgs[0],
        zeekWorkerArgs[1],
        zeekWorkerArgs[2],
        zeekWorkerArgs[3],
        zeekWorkerArgs[4],
        zeekWorkerArgs[5],
        zeekWorkerArgs[6],
    )

    if debug:
        eprint(f"{scriptName}[{scanWorkerId}]:\tstarted")

    # loop forever, or until we're told to shut down
    while not shuttingDown:
        try:
            # pull an item from the queue of files that need to be processed
            fileInfo = newFileQueue.popleft()
        except IndexError:
            time.sleep(1)
        else:
            if isinstance(fileInfo, dict) and (FILE_INFO_DICT_NAME in fileInfo) and os.path.isdir(uploadDir):

                if pcapBaseDir and os.path.isdir(pcapBaseDir):
                    fileInfo[FILE_INFO_DICT_NAME] = os.path.join(pcapBaseDir, fileInfo[FILE_INFO_DICT_NAME])

                if os.path.isfile(fileInfo[FILE_INFO_DICT_NAME]):
                    # zeek this PCAP if it's tagged "AUTOZEEK" or if the global autozeek flag is turned on
                    if autozeek or (
                        (FILE_INFO_DICT_TAGS in fileInfo) and ZEEK_AUTOZEEK_TAG in fileInfo[FILE_INFO_DICT_TAGS]
                    ):

                        extractFileMode = defaultExtractFileMode

                        # if file carving was specified via tag, make note of it
                        if FILE_INFO_DICT_TAGS in fileInfo:
                            for autocarveTag in filter(
                                lambda x: x.startswith(ZEEK_AUTOCARVE_TAG_PREFIX), fileInfo[FILE_INFO_DICT_TAGS]
                            ):
                                fileInfo[FILE_INFO_DICT_TAGS].remove(autocarveTag)
                                extractFileMode = autocarveTag[len(ZEEK_AUTOCARVE_TAG_PREFIX) :]

                        extractFileMode = extractFileMode.lower() if extractFileMode else ZEEK_EXTRACTOR_MODE_NONE

                        # finalize tags list (removing AUTOZEEK and AUTOCARVE*)
                        fileInfo[FILE_INFO_DICT_TAGS] = (
                            [
                                x
                                for x in fileInfo[FILE_INFO_DICT_TAGS]
                                if (x != ZEEK_AUTOZEEK_TAG)
                                and (x != ZEEK_USERTAG_TAG)
                                and (not x.startswith(ZEEK_AUTOCARVE_TAG_PREFIX))
                            ]
                            if ((FILE_INFO_DICT_TAGS in fileInfo) and autotag)
                            else list()
                        )
                        if debug:
                            eprint(f"{scriptName}[{scanWorkerId}]:\t🔎\t{fileInfo}")

                        # create a temporary work directory where zeek will be executed to generate the log files
                        with tempfile.TemporaryDirectory() as tmpLogDir:
                            if os.path.isdir(tmpLogDir):

                                processTimeUsec = int(round(time.time() * 1000000))

                                # use Zeek to process the pcap
                                zeekCmd = [zeekBin, "-r", fileInfo[FILE_INFO_DICT_NAME], ZEEK_LOCAL_SCRIPT]

                                # set file extraction parameters if required
                                if extractFileMode != ZEEK_EXTRACTOR_MODE_NONE:
                                    zeekCmd.append(ZEEK_EXTRACTOR_SCRIPT)
                                    if extractFileMode == ZEEK_EXTRACTOR_MODE_INTERESTING:
                                        zeekCmd.append(ZEEK_EXTRACTOR_SCRIPT_INTERESTING)
                                        extractFileMode = ZEEK_EXTRACTOR_MODE_MAPPED

                                # execute zeek with the cwd of tmpLogDir so that's where the logs go, and with the updated file carving environment variable
                                zeekEnv = os.environ.copy()
                                zeekEnv[ZEEK_EXTRACTOR_MODE_ENV_VAR] = extractFileMode
                                retcode, output = run_process(zeekCmd, cwd=tmpLogDir, env=zeekEnv, debug=verboseDebug)
                                if retcode == 0:
                                    if debug:
                                        eprint(
                                            f"{scriptName}[{scanWorkerId}]:\t✅\t{os.path.basename(fileInfo[FILE_INFO_DICT_NAME])}"
                                        )
                                else:
                                    if debug:
                                        eprint(
                                            f"{scriptName}[{scanWorkerId}]:\t❗\t{zeekBin} {os.path.basename(fileInfo[FILE_INFO_DICT_NAME])} returned {retcode} {output if verboseDebug else ''}"
                                        )

                                # clean up the .state directory we don't care to keep
                                tmpStateDir = os.path.join(tmpLogDir, ZEEK_STATE_DIR)
                                if os.path.isdir(tmpStateDir):
                                    shutil.rmtree(tmpStateDir)

                                # make sure log files were generated
                                logFiles = [logFile for logFile in os.listdir(tmpLogDir) if logFile.endswith('.log')]
                                if len(logFiles) > 0:

                                    # tar up the results
                                    tgzFileName = os.path.join(
                                        tmpLogDir,
                                        "{}-{}-{}.tar.gz".format(
                                            os.path.basename(fileInfo[FILE_INFO_DICT_NAME]),
                                            '_'.join(fileInfo[FILE_INFO_DICT_TAGS]),
                                            processTimeUsec,
                                        ),
                                    )
                                    with tarfile.open(
                                        tgzFileName, mode="w:gz", compresslevel=ZEEK_LOG_COMPRESSION_LEVEL
                                    ) as tar:
                                        tar.add(tmpLogDir, arcname=os.path.basename('.'))

                                    # relocate the tarball to the upload directory (do it this way instead of with a shutil.move because of
                                    # the way Docker volume mounts work, ie. avoid "OSError: [Errno 18] Invalid cross-device link").
                                    # we don't have to explicitly delete it since this whole directory is about to leave context and be removed
                                    shutil.copy(tgzFileName, uploadDir)
                                    if verboseDebug:
                                        eprint(f"{scriptName}[{scanWorkerId}]:\t⏩\t{tgzFileName} → {uploadDir}")

                                else:
                                    # zeek returned no log files (or an error)
                                    if debug:
                                        eprint(
                                            f"{scriptName}[{scanWorkerId}]:\t❓\t{zeekBin} {os.path.basename(fileInfo[FILE_INFO_DICT_NAME])} generated no log files"
                                        )

                            else:
                                if debug:
                                    eprint(
                                        f"{scriptName}[{scanWorkerId}]:\t❗\terror creating temporary directory {tmpLogDir}"
                                    )

    if debug:
        eprint(f"{scriptName}[{scanWorkerId}]:\tfinished")


###################################################################################################
# main
def main():

    processingMode = None
    if (PCAP_PROCESSING_MODE_ARKIME in scriptName) and ('zeek' in scriptName):
        eprint(
            f"{scriptName} could not determine PCAP processing mode. Create a symlink to {scriptName} with either '{PCAP_PROCESSING_MODE_ARKIME}' or '{PCAP_PROCESSING_MODE_ZEEK}' in the name and run that instead."
        )
        exit(2)
    elif PCAP_PROCESSING_MODE_ARKIME in scriptName:
        processingMode = PCAP_PROCESSING_MODE_ARKIME
    elif PCAP_PROCESSING_MODE_ZEEK in scriptName:
        processingMode = PCAP_PROCESSING_MODE_ZEEK
    else:
        eprint(
            f"{scriptName} could not determine PCAP processing mode. Create a symlink to {scriptName} with either '{PCAP_PROCESSING_MODE_ARKIME}' or '{PCAP_PROCESSING_MODE_ZEEK}' in the name and run that instead."
        )
        exit(2)

    global args
    global debug
    global debugToggled
    global pdbFlagged
    global shuttingDown
    global verboseDebug

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
        '--start-sleep',
        dest='startSleepSec',
        help="Sleep for this many seconds before starting",
        metavar='<seconds>',
        type=int,
        default=0,
        required=False,
    )
    parser.add_argument(
        '-t',
        '--threads',
        dest='threads',
        help="Worker threads",
        metavar='<seconds>',
        type=int,
        default=MAX_WORKER_PROCESSES_DEFAULT,
        required=False,
    )
    parser.add_argument(
        '--publisher',
        required=True,
        dest='publisherHost',
        help="host publishing PCAP events",
        metavar='<STR>',
        type=str,
        default="127.0.0.1",
    )
    parser.add_argument(
        '--autotag',
        dest='autotag',
        help="Autotag logs based on PCAP file names",
        metavar='true|false',
        type=str2bool,
        nargs='?',
        const=True,
        default=False,
        required=False,
    )
    requiredNamed = parser.add_argument_group('required arguments')
    requiredNamed.add_argument(
        '--pcap-directory',
        dest='pcapBaseDir',
        help='Base directory for PCAP files',
        metavar='<directory>',
        type=str,
        required=True,
    )
    if processingMode == PCAP_PROCESSING_MODE_ARKIME:
        parser.add_argument(
            '--arkime',
            required=False,
            dest='executable',
            help="Arkime capture executable path",
            metavar='<STR>',
            type=str,
            default=ARKIME_CAPTURE_PATH,
        )
        parser.add_argument(
            '--managed',
            dest='notLocked',
            help="Allow Arkime to manage PCAP files",
            metavar='true|false',
            type=str2bool,
            nargs='?',
            const=True,
            default=False,
            required=False,
        )
    elif processingMode == PCAP_PROCESSING_MODE_ZEEK:
        parser.add_argument(
            '--zeek',
            required=False,
            dest='executable',
            help="zeek executable path",
            metavar='<STR>',
            type=str,
            default=ZEEK_PATH,
        )
        parser.add_argument(
            '--autozeek',
            dest='autozeek',
            help="Autoanalyze all PCAP file with Zeek",
            metavar='true|false',
            type=str2bool,
            nargs='?',
            const=True,
            default=False,
            required=False,
        )
        parser.add_argument(
            '--extract',
            dest='zeekExtractFileMode',
            help='Zeek file carving mode',
            metavar=f'{ZEEK_EXTRACTOR_MODE_INTERESTING}|{ZEEK_EXTRACTOR_MODE_MAPPED}|{ZEEK_EXTRACTOR_MODE_NONE}',
            type=str,
            default=ZEEK_EXTRACTOR_MODE_NONE,
        )
        requiredNamed.add_argument(
            '--zeek-directory',
            dest='zeekUploadDir',
            help='Destination directory for Zeek log files',
            metavar='<directory>',
            type=str,
            required=True,
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

    # initialize ZeroMQ context and socket(s) to receive filenames and send scan results
    context = zmq.Context()

    # Socket to subscribe to messages on
    new_files_socket = context.socket(zmq.SUB)
    new_files_socket.connect(f"tcp://{args.publisherHost}:{PCAP_TOPIC_PORT}")
    new_files_socket.setsockopt(zmq.SUBSCRIBE, b"")  # All topics
    new_files_socket.setsockopt(zmq.LINGER, 0)  # All topics
    new_files_socket.RCVTIMEO = 1500
    if debug:
        eprint(f"{scriptName}:\tsubscribed to topic at {PCAP_TOPIC_PORT}")

    # we'll pull from the topic in the main thread and queue them for processing by the worker threads
    newFileQueue = deque()

    # start worker threads which will pull filenames/tags to be processed by capture
    if processingMode == PCAP_PROCESSING_MODE_ARKIME:
        scannerThreads = ThreadPool(
            args.threads,
            arkimeCaptureFileWorker,
            ([newFileQueue, args.pcapBaseDir, args.executable, args.autotag, args.notLocked],),
        )
    elif processingMode == PCAP_PROCESSING_MODE_ZEEK:
        scannerThreads = ThreadPool(
            args.threads,
            zeekFileWorker,
            (
                [
                    newFileQueue,
                    args.pcapBaseDir,
                    args.executable,
                    args.autozeek,
                    args.autotag,
                    args.zeekUploadDir,
                    args.zeekExtractFileMode,
                ],
            ),
        )

    while not shuttingDown:
        # for debugging
        if pdbFlagged:
            pdbFlagged = False
            breakpoint()

        # accept a file info dict from new_files_socket as json
        try:
            fileInfo = json.loads(new_files_socket.recv_string())
        except zmq.Again as timeout:
            # no file received due to timeout, we'll go around and try again
            if verboseDebug:
                eprint(f"{scriptName}:\t🕑\t(recv)")
            fileInfo = None

        if isinstance(fileInfo, dict) and (FILE_INFO_DICT_NAME in fileInfo):
            # queue for the workers to process with capture
            newFileQueue.append(fileInfo)
            if debug:
                eprint(f"{scriptName}:\t📨\t{fileInfo}")

    # graceful shutdown
    if debug:
        eprint(f"{scriptName}: shutting down...")
    time.sleep(5)


if __name__ == '__main__':
    main()
