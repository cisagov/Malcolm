#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2023 Battelle Energy Alliance, LLC.  All rights reserved.

###################################################################################################
# Monitor a directory for files extracted by zeek for processing
#
# Run the script with --help for options
###################################################################################################

import argparse
import json
import os
import logging
import pathlib
import re
import shutil
import signal
import sys
import time
import zmq

from collections import defaultdict
from contextlib import nullcontext
from datetime import datetime

from zeek_carve_utils import (
    BroSignatureLine,
    extracted_filespec_to_fields,
    FILE_SCAN_RESULT_DESCRIPTION,
    FILE_SCAN_RESULT_ENGINES,
    FILE_SCAN_RESULT_FILE,
    FILE_SCAN_RESULT_HITS,
    FILE_SCAN_RESULT_MESSAGE,
    FILE_SCAN_RESULT_SCANNER,
    PRESERVE_ALL,
    PRESERVE_NONE,
    PRESERVE_PRESERVED_DIR_NAME,
    PRESERVE_QUARANTINED,
    PRESERVE_QUARANTINED_DIR_NAME,
    SINK_PORT,
    ZEEK_SIGNATURE_NOTICE,
)

import malcolm_utils
from malcolm_utils import str2bool, AtomicInt, same_file_or_dir

###################################################################################################
pdbFlagged = False
args = None
scriptName = os.path.basename(__file__)
scriptPath = os.path.dirname(os.path.realpath(__file__))
origPath = os.getcwd()
shuttingDown = False


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
# main
def main():
    global args
    global pdbFlagged
    global shuttingDown

    parser = argparse.ArgumentParser(description=scriptName, add_help=False, usage='{} <arguments>'.format(scriptName))
    parser.add_argument('--verbose', '-v', action='count', default=1, help='Increase verbosity (e.g., -v, -vv, etc.)')
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
        '--preserve',
        dest='preserveMode',
        help=f"File preservation mode (default: {PRESERVE_QUARANTINED})",
        metavar=f'[{PRESERVE_QUARANTINED}|{PRESERVE_ALL}|{PRESERVE_NONE}]',
        type=str,
        default=PRESERVE_QUARANTINED,
        required=False,
    )
    parser.add_argument(
        '--zeek-log',
        dest='broSigLogSpec',
        help="Filespec to write Zeek signature log",
        metavar='<filespec>',
        type=str,
        required=False,
    )
    requiredNamed = parser.add_argument_group('required arguments')
    requiredNamed.add_argument(
        '-d',
        '--directory',
        dest='baseDir',
        help='Directory being monitored',
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

    args.verbose = logging.ERROR - (10 * args.verbose) if args.verbose > 0 else 0
    logging.basicConfig(
        level=args.verbose, format='%(asctime)s %(levelname)s: %(message)s', datefmt='%Y-%m-%d %H:%M:%S'
    )
    logging.info(os.path.join(scriptPath, scriptName))
    logging.info("Arguments: {}".format(sys.argv[1:]))
    logging.info("Arguments: {}".format(args))
    if args.verbose > logging.DEBUG:
        sys.tracebacklimit = 0

    # determine what to do with scanned files (preserve only "hits", preserve all, preserve none)
    args.preserveMode = args.preserveMode.lower()
    if len(args.preserveMode) == 0:
        args.preserveMode = PRESERVE_QUARANTINED
    elif args.preserveMode not in [PRESERVE_QUARANTINED, PRESERVE_ALL, PRESERVE_NONE]:
        logging.error(f'Invalid file preservation mode "{args.preserveMode}"')
        sys.exit(1)

    # handle sigint and sigterm for graceful shutdown
    signal.signal(signal.SIGINT, shutdown_handler)
    signal.signal(signal.SIGTERM, shutdown_handler)
    signal.signal(signal.SIGUSR1, pdb_handler)

    # sleep for a bit if requested
    sleepCount = 0
    while (not shuttingDown) and (sleepCount < args.startSleepSec):
        time.sleep(1)
        sleepCount += 1

    # where will the fake zeek log file be written to?
    broSigLogSpec = args.broSigLogSpec
    if broSigLogSpec is not None:
        if os.path.isdir(broSigLogSpec):
            # _carved tag will be recognized by 12_zeek_mutate.conf in logstash
            broSigLogSpec = os.path.join(broSigLogSpec, "signatures(_carved).log")
        else:
            # make sure path to write to zeek signatures log file exists before we start writing
            pathlib.Path(os.path.dirname(os.path.realpath(broSigLogSpec))).mkdir(parents=True, exist_ok=True)

    # create quarantine/preserved directories for preserved files (see preserveMode)
    quarantineDir = os.path.join(args.baseDir, PRESERVE_QUARANTINED_DIR_NAME)
    preserveDir = os.path.join(args.baseDir, PRESERVE_PRESERVED_DIR_NAME)
    if (args.preserveMode != PRESERVE_NONE) and (not os.path.isdir(quarantineDir)):
        logging.info(f'Creating "{quarantineDir}" for quarantined files')
        pathlib.Path(quarantineDir).mkdir(parents=False, exist_ok=True)
    if (args.preserveMode == PRESERVE_ALL) and (not os.path.isdir(preserveDir)):
        logging.info(f'Creating "{preserveDir}" for other preserved files')
        pathlib.Path(preserveDir).mkdir(parents=False, exist_ok=True)

    # initialize ZeroMQ context and socket(s) to send messages to
    context = zmq.Context()

    # Socket to receive scan results on
    scanned_files_socket = context.socket(zmq.PULL)
    scanned_files_socket.bind(f"tcp://*:{SINK_PORT}")
    scanned_files_socket.SNDTIMEO = 5000
    scanned_files_socket.RCVTIMEO = 5000

    logging.info(f"{scriptName}: bound sink port {SINK_PORT}")

    scanners = set()
    fileScanCounts = defaultdict(AtomicInt)
    fileScanHits = defaultdict(AtomicInt)

    # open and write out header for our super legit zeek signature.log file
    with open(broSigLogSpec, 'w+', 1) if (broSigLogSpec is not None) else nullcontext() as broSigFile:
        if broSigFile is not None:
            print('#separator \\x09', file=broSigFile, end='\n')
            print('#set_separator\t,', file=broSigFile, end='\n')
            print('#empty_field\t(empty)', file=broSigFile, end='\n')
            print('#unset_field\t-', file=broSigFile, end='\n')
            print('#path\tsignature', file=broSigFile, end='\n')
            print(f'#open\t{datetime.now().strftime("%Y-%m-%d-%H-%M-%S")}', file=broSigFile, end='\n')
            print(
                re.sub(
                    r"\b((orig|resp)_[hp])\b",
                    r"id.\1",
                    f"#fields\t{BroSignatureLine.signature_format_line()}".replace('{', '').replace('}', ''),
                ),
                file=broSigFile,
                end='\n',
            )
            print(f'#types\t{BroSignatureLine.signature_types_line()}', file=broSigFile, end='\n')

        while not shuttingDown:
            if pdbFlagged:
                pdbFlagged = False
                breakpoint()

            triggered = False
            try:
                scanResult = json.loads(scanned_files_socket.recv_string())
                logging.info(f"{scriptName}:\t📨\t{scanResult}")
            except zmq.Again:
                # no file received due to timeout, we'll go around and try again
                scanResult = None

            if isinstance(scanResult, dict):
                # register/deregister scanners
                if FILE_SCAN_RESULT_SCANNER in scanResult:
                    scanner = scanResult[FILE_SCAN_RESULT_SCANNER].lower()
                    if scanner.startswith('-'):
                        logging.info(f"{scriptName}:\t🙃\t{scanner[1:]}")
                        try:
                            scanners.remove(scanner[1:])
                        except KeyError:
                            pass
                    else:
                        if scanner not in scanners:
                            logging.info(f"{scriptName}:\t🇷\t{scanner}")
                        scanners.add(scanner)

                # process scan results
                if all(
                    k in scanResult
                    for k in (
                        FILE_SCAN_RESULT_SCANNER,
                        FILE_SCAN_RESULT_FILE,
                        FILE_SCAN_RESULT_ENGINES,
                        FILE_SCAN_RESULT_HITS,
                        FILE_SCAN_RESULT_MESSAGE,
                        FILE_SCAN_RESULT_DESCRIPTION,
                    )
                ):
                    triggered = scanResult[FILE_SCAN_RESULT_HITS] > 0
                    fileName = scanResult[FILE_SCAN_RESULT_FILE]
                    fileNameBase = os.path.basename(fileName)

                    # we won't delete or move/quarantine a file until fileScanCount < len(scanners)
                    fileScanCount = fileScanCounts[fileNameBase].increment()

                    if triggered:
                        # this file had a "hit" in one of the virus engines, log it!
                        fileScanHitCount = fileScanHits[fileNameBase].increment()

                        # format the line as it should appear in the signatures log file
                        fileSpecFields = extracted_filespec_to_fields(fileName)
                        broLine = BroSignatureLine(
                            ts=f"{fileSpecFields.time}",
                            uid=fileSpecFields.uid if fileSpecFields.uid is not None else '-',
                            note=ZEEK_SIGNATURE_NOTICE,
                            signature_id=scanResult[FILE_SCAN_RESULT_MESSAGE],
                            event_message=scanResult[FILE_SCAN_RESULT_DESCRIPTION],
                            sub_message=fileSpecFields.fid
                            if fileSpecFields.fid is not None
                            else os.path.basename(fileName),
                            signature_count=scanResult[FILE_SCAN_RESULT_HITS],
                            host_count=scanResult[FILE_SCAN_RESULT_ENGINES],
                        )
                        broLineStr = str(broLine)

                        # write broLineStr event line out to the signatures log file or to stdout
                        if broSigFile is not None:
                            print(broLineStr, file=broSigFile, end='\n', flush=True)
                        else:
                            print(broLineStr, file=broSigFile, flush=True)

                    else:
                        fileScanHitCount = fileScanHits[fileNameBase].value()

                    # finally, what to do with the file itself
                    if os.path.isfile(fileName):
                        # once all of the scanners have had their turn...
                        if fileScanCount >= len(scanners):
                            fileScanCounts.pop(fileNameBase, None)
                            fileScanHits.pop(fileNameBase, None)

                            if (fileScanHitCount > 0) and (args.preserveMode != PRESERVE_NONE):
                                # move triggering file to quarantine
                                if not same_file_or_dir(
                                    fileName, os.path.join(quarantineDir, fileNameBase)
                                ):  # unless it's somehow already there
                                    try:
                                        shutil.move(fileName, quarantineDir)
                                        logging.info(f"{scriptName}:\t⏩\t{fileName} ({fileScanCount}/{len(scanners)})")
                                    except Exception as e:
                                        logging.warning(f"{scriptName}:\t❗\t🚫\t{fileName} move exception: {e}")
                                        # hm move failed, delete it i guess?
                                        os.remove(fileName)

                            else:
                                if not same_file_or_dir(
                                    quarantineDir, os.path.dirname(fileName)
                                ):  # don't move or delete if it's somehow already quarantined
                                    if args.preserveMode == PRESERVE_ALL:
                                        # move non-triggering file to preserved directory
                                        try:
                                            shutil.move(fileName, preserveDir)
                                            logging.debug(
                                                f"{scriptName}:\t⏩\t{fileName} ({fileScanCount}/{len(scanners)})"
                                            )
                                        except Exception as e:
                                            logging.warning(f"{scriptName}:\t❗\t🚫\t{fileName} move exception: {e}")
                                            # hm move failed, delete it i guess?
                                            os.remove(fileName)

                                    else:
                                        # delete the file
                                        os.remove(fileName)
                                        logging.debug(f"{scriptName}:\t🚫\t{fileName} ({fileScanCount}/{len(scanners)})")

    # graceful shutdown
    logging.info(f"{scriptName}: shutting down...")


if __name__ == '__main__':
    main()
