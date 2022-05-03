#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2022 Battelle Energy Alliance, LLC.  All rights reserved.

###################################################################################################
# Process queued files reported by zeek_carve_watcher.py, scanning them with the specified
# virus scan engine and sending the results along to zeek_carve_logger.py
#
# Run the script with --help for options
###################################################################################################

import argparse
import os
import pathlib
import json
import signal
import sys
import threading
import time
import zmq

from zeek_carve_utils import *
from multiprocessing.pool import ThreadPool

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
# look for a file to scan (probably in its original directory, but possibly already moved to quarantine)
def locate_file(fileInfo):
    global verboseDebug

    if isinstance(fileInfo, dict) and (FILE_SCAN_RESULT_FILE in fileInfo):
        fileName = fileInfo[FILE_SCAN_RESULT_FILE]
    elif isinstance(fileInfo, str):
        fileName = fileInfo
    else:
        fileName = None

    if fileName is not None:

        if os.path.isfile(fileName):
            return fileName

        else:
            for testPath in [PRESERVE_QUARANTINED_DIR_NAME, PRESERVE_PRESERVED_DIR_NAME]:
                testFileName = os.path.join(
                    os.path.join(os.path.dirname(os.path.realpath(fileName)), testPath), os.path.basename(fileName)
                )
                if os.path.isfile(testFileName):
                    if verboseDebug:
                        eprint(f"{scriptName}:\t⏩\t{testFileName}")
                    return testFileName

    return None


###################################################################################################
def scanFileWorker(checkConnInfo, carvedFileSub):
    global debug
    global verboseDebug
    global shuttingDown
    global scanWorkersCount

    scanWorkerId = scanWorkersCount.increment()  # unique ID for this thread
    scannerRegistered = False

    if debug:
        eprint(f"{scriptName}[{scanWorkerId}]:\tstarted")

    try:
        if isinstance(checkConnInfo, FileScanProvider):

            # initialize ZeroMQ context and socket(s) to send scan results
            context = zmq.Context()

            # Socket to send messages to
            scanned_files_socket = context.socket(zmq.PUSH)
            scanned_files_socket.connect(f"tcp://localhost:{SINK_PORT}")
            # todo: do I want to set this? probably not, since what else would we do if we can't send? just block
            # scanned_files_socket.SNDTIMEO = 5000
            if debug:
                eprint(f"{scriptName}[{scanWorkerId}]:\tconnected to sink at {SINK_PORT}")

            fileInfo = None
            fileName = None
            retrySubmitFile = False  # todo: maximum file retry count?

            # loop forever, or until we're told to shut down
            while not shuttingDown:

                # "register" this scanner with the logger
                while (not scannerRegistered) and (not shuttingDown):
                    try:
                        scanned_files_socket.send_string(
                            json.dumps({FILE_SCAN_RESULT_SCANNER: checkConnInfo.scanner_name()})
                        )
                        scannerRegistered = True
                        if debug:
                            eprint(f"{scriptName}[{scanWorkerId}]:\t🇷\t{checkConnInfo.scanner_name()}")

                    except zmq.Again as timeout:
                        # todo: what to do here?
                        if verboseDebug:
                            eprint(f"{scriptName}[{scanWorkerId}]:\t🕑\t{checkConnInfo.scanner_name()} 🇷")

                if shuttingDown:
                    break

                if retrySubmitFile and (fileInfo is not None) and (locate_file(fileInfo) is not None):
                    # we were unable to submit the file for processing, so try again
                    time.sleep(1)
                    if debug:
                        eprint(f"{scriptName}[{scanWorkerId}]:\t🔃\t{json.dumps(fileInfo)}")

                else:
                    retrySubmitFile = False
                    # read watched file information from the subscription
                    fileInfo = carvedFileSub.Pull(scanWorkerId=scanWorkerId)

                fileName = locate_file(fileInfo)
                if (fileName is not None) and os.path.isfile(fileName):

                    # file exists, submit for scanning
                    if debug:
                        eprint(f"{scriptName}[{scanWorkerId}]:\t🔎\t{json.dumps(fileInfo)}")
                    requestComplete = False
                    scanResult = None
                    fileSize = (
                        int(fileInfo[FILE_SCAN_RESULT_FILE_SIZE])
                        if isinstance(fileInfo[FILE_SCAN_RESULT_FILE_SIZE], int)
                        or (
                            isinstance(fileInfo[FILE_SCAN_RESULT_FILE_SIZE], str)
                            and fileInfo[FILE_SCAN_RESULT_FILE_SIZE].isdecimal()
                        )
                        else None
                    )
                    scan = AnalyzerScan(
                        provider=checkConnInfo,
                        name=fileName,
                        size=fileSize,
                        fileType=fileInfo[FILE_SCAN_RESULT_FILE_TYPE],
                        submissionResponse=checkConnInfo.submit(
                            fileName=fileName,
                            fileSize=fileSize,
                            fileType=fileInfo[FILE_SCAN_RESULT_FILE_TYPE],
                            block=False,
                        ),
                    )
                    if scan.submissionResponse is not None:
                        if debug:
                            eprint(f"{scriptName}[{scanWorkerId}]:\t🔍\t{fileName}")

                        # file was successfully submitted and is now being scanned
                        retrySubmitFile = False
                        requestComplete = False

                        # todo: maximum time we wait for a single file to be scanned?
                        while (not requestComplete) and (not shuttingDown):

                            # wait a moment then check to see if the scan is complete
                            time.sleep(scan.provider.check_interval())
                            response = scan.provider.check_result(scan.submissionResponse)

                            if isinstance(response, AnalyzerResult):

                                # whether the scan has completed
                                requestComplete = response.finished

                                if response.success:
                                    # successful scan, report the scan results
                                    scanResult = response

                                elif isinstance(response.result, dict) and ("error" in response.result):
                                    # scan errored out, report the error
                                    scanResult = response.result["error"]
                                    eprint(f"{scriptName}[{scanWorkerId}]:\t❗\t{fileName} {scanResult}")

                                else:
                                    # result is unrecognizable
                                    scanResult = "Invalid scan result format"
                                    eprint(f"{scriptName}[{scanWorkerId}]:\t❗\t{fileName} {scanResult}")

                            else:
                                # impossibru! abandon ship for this file?
                                # todo? what else? touch it?
                                requestComplete = True
                                scanResult = "Error checking results"
                                eprint(f"{scriptName}[{scanWorkerId}]:\t❗{fileName} {scanResult}")

                    else:
                        # we were denied (rate limiting, probably), so we'll need wait for a slot to clear up
                        retrySubmitFile = True

                    if requestComplete and (scanResult is not None):
                        try:
                            # Send results to sink
                            scanned_files_socket.send_string(json.dumps(scan.provider.format(fileName, scanResult)))
                            if debug:
                                eprint(f"{scriptName}[{scanWorkerId}]:\t✅\t{fileName}")

                        except zmq.Again as timeout:
                            # todo: what to do here?
                            if verboseDebug:
                                eprint(f"{scriptName}[{scanWorkerId}]:\t🕑\t{fileName}")

        else:
            eprint(f"{scriptName}[{scanWorkerId}]:\tinvalid scanner provider specified")

    finally:
        # "unregister" this scanner with the logger
        if scannerRegistered:
            try:
                scanned_files_socket.send_string(
                    json.dumps({FILE_SCAN_RESULT_SCANNER: f"-{checkConnInfo.scanner_name()}"})
                )
                scannerRegistered = False
                if debug:
                    eprint(f"{scriptName}[{scanWorkerId}]:\t🙃\t{checkConnInfo.scanner_name()}")
            except zmq.Again as timeout:
                # todo: what to do here?
                if verboseDebug:
                    eprint(f"{scriptName}[{scanWorkerId}]:\t🕑\t{checkConnInfo.scanner_name()} 🙃")

    if debug:
        eprint(f"{scriptName}[{scanWorkerId}]:\tfinished")


###################################################################################################
# main
def main():
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
        '--req-limit',
        dest='reqLimit',
        help="Requests limit",
        metavar='<requests>',
        type=int,
        default=None,
        required=False,
    )
    parser.add_argument(
        '--vtot-api', dest='vtotApi', help="VirusTotal API key", metavar='<API key>', type=str, required=False
    )
    parser.add_argument(
        '--clamav',
        dest='enableClamAv',
        metavar='true|false',
        help="Enable ClamAV",
        type=str2bool,
        nargs='?',
        const=True,
        default=False,
        required=False,
    )
    parser.add_argument(
        '--clamav-socket',
        dest='clamAvSocket',
        help="ClamAV socket filename",
        metavar='<filespec>',
        type=str,
        required=False,
        default=None,
    )
    parser.add_argument(
        '--yara',
        dest='enableYara',
        metavar='true|false',
        help="Enable Yara",
        type=str2bool,
        nargs='?',
        const=True,
        default=False,
        required=False,
    )
    parser.add_argument(
        '--yara-custom-only',
        dest='yaraCustomOnly',
        metavar='true|false',
        help="Ignore default Yara rules",
        type=str2bool,
        nargs='?',
        const=True,
        default=False,
        required=False,
    )
    parser.add_argument(
        '--capa',
        dest='enableCapa',
        metavar='true|false',
        help="Enable Capa",
        type=str2bool,
        nargs='?',
        const=True,
        default=False,
        required=False,
    )
    parser.add_argument(
        '--capa-rules', dest='capaRulesDir', help="Capa Rules Directory", metavar='<pathspec>', type=str, required=False
    )
    parser.add_argument(
        '--capa-verbose',
        dest='capaVerbose',
        metavar='true|false',
        help="Log all capa rules, not just MITRE ATT&CK technique classifications",
        type=str2bool,
        nargs='?',
        const=True,
        default=False,
        required=False,
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

    # intialize objects for virus scanning engines
    if isinstance(args.vtotApi, str) and (len(args.vtotApi) > 1) and (args.reqLimit > 0):
        checkConnInfo = VirusTotalSearch(args.vtotApi, reqLimit=args.reqLimit)
    elif args.enableYara:
        yaraDirs = []
        if not args.yaraCustomOnly:
            yaraDirs.append(YARA_RULES_DIR)
        yaraDirs.append(YARA_CUSTOM_RULES_DIR)
        checkConnInfo = YaraScan(debug=debug, verboseDebug=verboseDebug, rulesDirs=yaraDirs, reqLimit=args.reqLimit)
    elif args.enableCapa:
        checkConnInfo = CapaScan(
            debug=debug,
            verboseDebug=verboseDebug,
            rulesDir=args.capaRulesDir,
            verboseHits=args.capaVerbose,
            reqLimit=args.reqLimit,
        )
    else:
        if not args.enableClamAv:
            eprint('No scanner specified, defaulting to ClamAV')
        checkConnInfo = ClamAVScan(
            debug=debug, verboseDebug=verboseDebug, socketFileName=args.clamAvSocket, reqLimit=args.reqLimit
        )

    carvedFileSub = CarvedFileSubscriberThreaded(
        debug=debug, verboseDebug=verboseDebug, host='localhost', port=VENTILATOR_PORT, scriptName=scriptName
    )

    # start scanner threads which will pull filenames to be scanned and send the results to the logger
    scannerThreads = ThreadPool(checkConnInfo.max_requests(), scanFileWorker, ([checkConnInfo, carvedFileSub]))
    while not shuttingDown:
        if pdbFlagged:
            pdbFlagged = False
            breakpoint()
        time.sleep(0.2)

    # graceful shutdown
    if debug:
        eprint(f"{scriptName}: shutting down...")
    time.sleep(5)


if __name__ == '__main__':
    main()
