#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2025 Battelle Energy Alliance, LLC.  All rights reserved.

###################################################################################################
# Process queued files reported by pcap_watcher.py, using either arkime's capture or zeek to process
# them for session creation and logging into the OpenSearch database
#
# Run the script with --help for options
###################################################################################################

import argparse
import json
import logging
import os
import re
import shutil
import signal
import sys
import tarfile
import tempfile
import time
import zmq

from pcap_utils import (
    FILE_INFO_DICT_LIVE,
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
from malcolm_utils import eprint, str2bool, AtomicInt, run_process, same_file_or_dir
from multiprocessing.pool import ThreadPool
from collections import deque
from itertools import chain, repeat

try:
    from suricata_socket import SuricataSocketClient
except ModuleNotFoundError:
    # this will blow up later on instantiation, of course
    SuricataSocketClient = object

###################################################################################################
MAX_WORKER_PROCESSES_DEFAULT = 1

PCAP_PROCESSING_MODE_ARKIME = "arkime"
PCAP_PROCESSING_MODE_ZEEK = "zeek"
PCAP_PROCESSING_MODE_SURICATA = "suricata"

ARKIME_CAPTURE_PATH = "/opt/arkime/bin/capture-offline"
ARKIME_AUTOARKIME_TAG = 'AUTOARKIME'

SURICATA_SOCKET_PATH = "/var/run/suricata/suricata-command.socket"
SURICATA_LOG_DIR = os.getenv('SURICATA_LOG_DIR', '/var/log/suricata')
SURICATA_LOG_PATH = os.path.join(SURICATA_LOG_DIR, 'suricata.log')
SURICATA_CONFIG_FILE = os.getenv('SURICATA_CONFIG_FILE', '/etc/suricata/suricata.yaml')
SURICATA_AUTOSURICATA_TAG = 'AUTOSURICATA'
SURICATA_FAILURES_FORCE_RECONNECT = 5

ZEEK_PATH = "/opt/zeek/bin/zeek-offline"
ZEEK_EXTRACTOR_MODE_INTERESTING = 'interesting'
ZEEK_EXTRACTOR_MODE_MAPPED = 'mapped'
ZEEK_EXTRACTOR_MODE_NONE = 'none'
ZEEK_EXTRACTOR_MODE_NOTCOMMTXT = 'notcommtxt'
ZEEK_EXTRACTOR_SCRIPT = "extractor.zeek"
ZEEK_EXTRACTOR_SCRIPT_INTERESTING = "extractor_override.interesting.zeek"
ZEEK_LOCAL_SCRIPT = 'local'
ZEEK_STATE_DIR = '.state'
ZEEK_AUTOZEEK_TAG = 'AUTOZEEK'
ZEEK_EXTRACTOR_MODE_ENV_VAR = 'ZEEK_EXTRACTOR_MODE'
ZEEK_LOG_COMPRESSION_LEVEL = 6
NETBOX_SITE_ID_TAG_PREFIX = 'NBSITEID'
USERTAG_TAG = 'USERTAG'

TAGS_NOSHOW = (
    USERTAG_TAG,
    ARKIME_AUTOARKIME_TAG,
    SURICATA_AUTOSURICATA_TAG,
    ZEEK_AUTOZEEK_TAG,
)


###################################################################################################
pdbFlagged = False
args = None
scriptName = os.path.basename(__file__)
scriptPath = os.path.dirname(os.path.realpath(__file__))
origPath = os.getcwd()
shuttingDown = False
workersCount = AtomicInt(value=0)
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
def arkimeCaptureFileWorker(arkimeWorkerArgs):
    global shuttingDown
    global workersCount
    global arkimeProvider
    global arkimeDataset

    workerId = workersCount.increment()  # unique ID for this thread

    (
        newFileQueue,
        pcapBaseDir,
        arkimeBin,
        nodeName,
        nodeHost,
        autoArkime,
        forceArkime,
        extraTags,
        autoTag,
        notLocked,
        logger,
        debug,
    ) = (
        arkimeWorkerArgs[0],
        arkimeWorkerArgs[1],
        arkimeWorkerArgs[2],
        arkimeWorkerArgs[3],
        arkimeWorkerArgs[4],
        arkimeWorkerArgs[5],
        arkimeWorkerArgs[6],
        arkimeWorkerArgs[7],
        arkimeWorkerArgs[8],
        arkimeWorkerArgs[9],
        arkimeWorkerArgs[10],
        arkimeWorkerArgs[11],
    )

    if not logger:
        logger = logging

    logger.info(f"{scriptName}[{workerId}]:\tstarted")

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
                    # Arkime this PCAP if it's tagged "AUTOARKIME" or if the global autoArkime flag is turned on.
                    if (
                        autoArkime
                        or (
                            (FILE_INFO_DICT_TAGS in fileInfo) and ARKIME_AUTOARKIME_TAG in fileInfo[FILE_INFO_DICT_TAGS]
                        )
                    ) and (
                        forceArkime
                        or (
                            not any(
                                os.path.basename(fileInfo[FILE_INFO_DICT_NAME]).startswith(prefix)
                                for prefix in ('mnetsniff', 'mtcpdump')
                            )
                        )
                    ):
                        # finalize tags list
                        fileInfo[FILE_INFO_DICT_TAGS] = (
                            [
                                x
                                for x in fileInfo[FILE_INFO_DICT_TAGS]
                                if (x not in TAGS_NOSHOW) and (not x.startswith(NETBOX_SITE_ID_TAG_PREFIX))
                            ]
                            if ((FILE_INFO_DICT_TAGS in fileInfo) and autoTag)
                            else list()
                        )
                        if extraTags and isinstance(extraTags, list):
                            fileInfo[FILE_INFO_DICT_TAGS].extend(extraTags)
                        fileInfo[FILE_INFO_DICT_TAGS] = list(dict.fromkeys(fileInfo[FILE_INFO_DICT_TAGS]))
                        logger.info(f"{scriptName}[{workerId}]:\t🔎\t{fileInfo}")

                        # if this is an uploaded PCAP (not captured "live"")
                        #   append -upload to the node name used (which originates from PCAP_NODE_NAME)
                        tmpNodeName = fileInfo[FILE_INFO_DICT_NODE] if (FILE_INFO_DICT_NODE in fileInfo) else nodeName
                        if tmpNodeName and (
                            (not (FILE_INFO_DICT_LIVE in fileInfo)) or (not fileInfo[FILE_INFO_DICT_LIVE])
                        ):
                            tmpNodeName = tmpNodeName + '-upload'

                        # put together arkime execution command
                        cmd = [
                            arkimeBin,
                            '--quiet',
                            '--insecure',
                            '-o',
                            f'ecsEventProvider={arkimeProvider}',
                            '-o',
                            f'ecsEventDataset={arkimeDataset}',
                            '-r',
                            fileInfo[FILE_INFO_DICT_NAME],
                        ]
                        if tmpNodeName:
                            cmd.append('--node')
                            cmd.append(tmpNodeName)
                        if nodeHost:
                            cmd.append('--host')
                            cmd.append(nodeHost)
                        if notLocked:
                            cmd.append('--nolockpcap')
                        cmd.extend(list(chain.from_iterable(zip(repeat('-t'), fileInfo[FILE_INFO_DICT_TAGS]))))

                        # execute capture for pcap file
                        retcode, output = run_process(cmd, logger=logger)
                        if retcode == 0:
                            logger.info(
                                f"{scriptName}[{workerId}]:\t✅\t{os.path.basename(fileInfo[FILE_INFO_DICT_NAME])}"
                            )
                        else:
                            logger.warning(
                                f"{scriptName}[{workerId}]:\t❗\t{arkimeBin} {os.path.basename(fileInfo[FILE_INFO_DICT_NAME])} returned {retcode} {output}"
                            )

    logger.info(f"{scriptName}[{workerId}]:\tfinished")


###################################################################################################
def zeekFileWorker(zeekWorkerArgs):
    global shuttingDown
    global workersCount

    workerId = workersCount.increment()  # unique ID for this thread

    (
        newFileQueue,
        pcapBaseDir,
        zeekBin,
        autoZeek,
        forceZeek,
        extraTags,
        autoTag,
        uploadDir,
        defaultExtractFileMode,
        logger,
        debug,
    ) = (
        zeekWorkerArgs[0],
        zeekWorkerArgs[1],
        zeekWorkerArgs[2],
        zeekWorkerArgs[3],
        zeekWorkerArgs[4],
        zeekWorkerArgs[5],
        zeekWorkerArgs[6],
        zeekWorkerArgs[7],
        zeekWorkerArgs[8],
        zeekWorkerArgs[9],
        zeekWorkerArgs[10],
    )

    if not logger:
        logger = logging

    logger.info(f"{scriptName}[{workerId}]:\tstarted")

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
                    # Zeek this PCAP if it's tagged "AUTOZEEK" or if the global autoZeek flag is turned on.
                    # However, skip "live" PCAPs Malcolm is capturing and rotating through for Arkime capture,
                    # as Zeek now does its own network capture in Malcolm standalone mode.
                    if (
                        autoZeek
                        or ((FILE_INFO_DICT_TAGS in fileInfo) and ZEEK_AUTOZEEK_TAG in fileInfo[FILE_INFO_DICT_TAGS])
                    ) and (
                        forceZeek
                        or (
                            not any(
                                os.path.basename(fileInfo[FILE_INFO_DICT_NAME]).startswith(prefix)
                                for prefix in ('mnetsniff', 'mtcpdump')
                            )
                        )
                    ):
                        extractFileMode = defaultExtractFileMode
                        extractFileMode = extractFileMode.lower() if extractFileMode else ZEEK_EXTRACTOR_MODE_NONE

                        # finalize tags list
                        fileInfo[FILE_INFO_DICT_TAGS] = (
                            [x for x in fileInfo[FILE_INFO_DICT_TAGS] if (x not in TAGS_NOSHOW)]
                            if ((FILE_INFO_DICT_TAGS in fileInfo) and autoTag)
                            else list()
                        )
                        if extraTags and isinstance(extraTags, list):
                            fileInfo[FILE_INFO_DICT_TAGS].extend(extraTags)
                        fileInfo[FILE_INFO_DICT_TAGS] = list(dict.fromkeys(fileInfo[FILE_INFO_DICT_TAGS]))
                        logger.info(f"{scriptName}[{workerId}]:\t🔎\t{fileInfo}")

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
                                retcode, output = run_process(zeekCmd, cwd=tmpLogDir, env=zeekEnv, logger=logger)
                                if retcode == 0:
                                    logger.info(
                                        f"{scriptName}[{workerId}]:\t✅\t{os.path.basename(fileInfo[FILE_INFO_DICT_NAME])}"
                                    )
                                else:
                                    logger.info(
                                        f"{scriptName}[{workerId}]:\t❗\t{zeekBin} {os.path.basename(fileInfo[FILE_INFO_DICT_NAME])} returned {retcode} {output}"
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
                                    logger.debug(f"{scriptName}[{workerId}]:\t⏩\t{tgzFileName} → {uploadDir}")

                                else:
                                    # zeek returned no log files (or an error)
                                    logger.warning(
                                        f"{scriptName}[{workerId}]:\t❓\t{zeekBin} {os.path.basename(fileInfo[FILE_INFO_DICT_NAME])} generated no log files"
                                    )

                            else:
                                logger.warning(
                                    f"{scriptName}[{workerId}]:\t❗\terror creating temporary directory {tmpLogDir}"
                                )

    logger.info(f"{scriptName}[{workerId}]:\tfinished")


###################################################################################################
def suricataFileWorker(suricataWorkerArgs):
    global shuttingDown
    global workersCount

    workerId = workersCount.increment()  # unique ID for this thread

    (
        newFileQueue,
        pcapBaseDir,
        autoSuricata,
        forceSuricata,
        socketPath,
        extraTags,
        autoTag,
        uploadDir,
        suricataConfig,
        logger,
        debug,
    ) = (
        suricataWorkerArgs[0],
        suricataWorkerArgs[1],
        suricataWorkerArgs[2],
        suricataWorkerArgs[3],
        suricataWorkerArgs[4],
        suricataWorkerArgs[5],
        suricataWorkerArgs[6],
        suricataWorkerArgs[7],
        suricataWorkerArgs[8],
        suricataWorkerArgs[9],
        suricataWorkerArgs[10],
    )

    if not logger:
        logger = logging

    logger.info(f"{scriptName}[{workerId}]:\tstarted")

    suricata = None
    processFailures = 0

    # loop forever, or until we're told to shut down
    while not shuttingDown:
        if suricata:
            try:
                # pull an item from the queue of files that need to be processed
                fileInfo = newFileQueue.popleft()
            except IndexError:
                time.sleep(1)
                continue

            if isinstance(fileInfo, dict) and (FILE_INFO_DICT_NAME in fileInfo):
                # Suricata this PCAP if it's tagged "AUTOSURICATA" or if the global autoSuricata flag is turned on.
                # However, skip "live" PCAPs Malcolm is capturing and rotating through for Arkime capture,
                # as Suricata now does its own network capture in Malcolm standalone mode.
                if (
                    autoSuricata
                    or (
                        (FILE_INFO_DICT_TAGS in fileInfo) and SURICATA_AUTOSURICATA_TAG in fileInfo[FILE_INFO_DICT_TAGS]
                    )
                ) and (
                    forceSuricata
                    or (
                        not any(
                            os.path.basename(fileInfo[FILE_INFO_DICT_NAME]).startswith(prefix)
                            for prefix in ('mnetsniff', 'mtcpdump')
                        )
                    )
                ):
                    if pcapBaseDir and os.path.isdir(pcapBaseDir):
                        fileInfo[FILE_INFO_DICT_NAME] = os.path.join(pcapBaseDir, fileInfo[FILE_INFO_DICT_NAME])

                    if os.path.isfile(fileInfo[FILE_INFO_DICT_NAME]):
                        # finalize tags list
                        fileInfo[FILE_INFO_DICT_TAGS] = (
                            [x for x in fileInfo[FILE_INFO_DICT_TAGS] if (x not in TAGS_NOSHOW)]
                            if ((FILE_INFO_DICT_TAGS in fileInfo) and autoTag)
                            else list()
                        )
                        if extraTags and isinstance(extraTags, list):
                            fileInfo[FILE_INFO_DICT_TAGS].extend(extraTags)
                        fileInfo[FILE_INFO_DICT_TAGS] = list(dict.fromkeys(fileInfo[FILE_INFO_DICT_TAGS]))
                        logger.info(f"{scriptName}[{workerId}]:\t🔎\t{fileInfo}")

                        # Create unique output directory for this PCAP's suricata output
                        processTimeUsec = int(round(time.time() * 1000000))
                        output_dir = os.path.join(
                            uploadDir,
                            f"suricata-{processTimeUsec}-{workerId}-({','.join(fileInfo[FILE_INFO_DICT_TAGS])})",
                        )

                        try:
                            logger.info(
                                f"{scriptName}[{workerId}]:\t📥\tSubmitting {os.path.basename(fileInfo[FILE_INFO_DICT_NAME])} to Suricata"
                            )
                            if suricata.process_pcap(
                                pcap_file=fileInfo[FILE_INFO_DICT_NAME],
                                output_dir=output_dir,
                            ):
                                # suricata over socket mode doesn't let us know when a PCAP file is done processing,
                                #   so all we do here is submit it and then we'll let filebeat tail the results
                                #   as long as it needs to
                                logger.info(
                                    f"{scriptName}[{workerId}]:\t✅\t{os.path.basename(fileInfo[FILE_INFO_DICT_NAME])}"
                                )
                                processFailures = 0

                            else:
                                logger.error(
                                    f"{scriptName}[{workerId}]:\t❌\tFailed to process {os.path.basename(fileInfo[FILE_INFO_DICT_NAME])}"
                                )
                                processFailures = processFailures + 1
                        except Exception as e:
                            logger.error(
                                f"{scriptName}[{workerId}]:\t💥\tError processing {os.path.basename(fileInfo[FILE_INFO_DICT_NAME])}: {e}"
                            )
                            processFailures = processFailures + 1

                        if processFailures > SURICATA_FAILURES_FORCE_RECONNECT:
                            # force a reconnect the next time we come around the loop
                            suricata = None
                            processFailures = 0

        else:
            # create a single socket client for this worker
            try:
                suricata = SuricataSocketClient(
                    socket_path=socketPath,
                    logger=logger,
                    debug=debug,
                    output_dir=uploadDir,
                )
            except Exception as e:
                logger.error(f"Failed to create Suricata socket client, will retry: {e}")
                suricata = None
            if not suricata:
                time.sleep(5)

    logger.info(f"{scriptName}[{workerId}]:\tfinished")


###################################################################################################
# main
def main():
    processingMode = None
    if 'pcap_processor' in scriptName:
        eprint(
            f"{scriptName} could not determine PCAP processing mode. Create a symlink to {scriptName} with the processor (e.g., arkime, suricata, zeek) in the name and run that instead."
        )
        exit(2)
    elif PCAP_PROCESSING_MODE_ARKIME in scriptName:
        processingMode = PCAP_PROCESSING_MODE_ARKIME
    elif PCAP_PROCESSING_MODE_ZEEK in scriptName:
        processingMode = PCAP_PROCESSING_MODE_ZEEK
    elif PCAP_PROCESSING_MODE_SURICATA in scriptName:
        processingMode = PCAP_PROCESSING_MODE_SURICATA
    else:
        eprint(
            f"{scriptName} could not determine PCAP processing mode. Create a symlink to {scriptName} with the processor (e.g., arkime, suricata, zeek) in the name and run that instead."
        )
        exit(2)

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
        '--extra-tags',
        dest='extraTags',
        help="A comma-separated list of default tags for data generated by Malcolm (default is an empty string)",
        metavar='<STR>',
        type=str,
        default=None,
        required=False,
    )
    parser.add_argument(
        '--autotag',
        dest='autoTag',
        help="Autotag logs based on PCAP file names",
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
        help="PCAP source node name (may be overriden by publisher)",
        metavar='<STR>',
        type=str,
        default=os.getenv('PCAP_NODE_NAME', 'malcolm'),
    )
    parser.add_argument(
        '--host',
        required=False,
        dest='nodeHost',
        help="PCAP source node host (for Arkime viewer reachback)",
        metavar='<STR>',
        type=str,
        default='',
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
            '--autoarkime',
            dest='autoArkime',
            help="Autoanalyze all PCAP file with Arkime",
            metavar='true|false',
            type=str2bool,
            nargs='?',
            const=True,
            default=False,
            required=False,
        )
        parser.add_argument(
            '--forcearkime',
            dest='forceArkime',
            help="Force Arkime analysis even on rotated PCAPs",
            metavar='true|false',
            type=str2bool,
            nargs='?',
            const=True,
            default=False,
            required=False,
        )
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
            dest='autoZeek',
            help="Autoanalyze all PCAP file with Zeek",
            metavar='true|false',
            type=str2bool,
            nargs='?',
            const=True,
            default=False,
            required=False,
        )
        parser.add_argument(
            '--forcezeek',
            dest='forceZeek',
            help="Force Zeek analysis even on rotated PCAPs",
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
            metavar=f'{ZEEK_EXTRACTOR_MODE_INTERESTING}|{ZEEK_EXTRACTOR_MODE_MAPPED}|{ZEEK_EXTRACTOR_MODE_NONE}|{ZEEK_EXTRACTOR_MODE_NOTCOMMTXT}',
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
    elif processingMode == PCAP_PROCESSING_MODE_SURICATA:
        parser.add_argument(
            '--suricata',
            required=False,
            dest='suricataSocketPath',
            help="suricata socket path",
            metavar='<STR>',
            type=str,
            default=SURICATA_SOCKET_PATH,
        )
        parser.add_argument(
            '--autosuricata',
            dest='autoSuricata',
            help="Autoanalyze all PCAP file with Suricata",
            metavar='true|false',
            type=str2bool,
            nargs='?',
            const=True,
            default=False,
            required=False,
        )
        parser.add_argument(
            '--forcesuricata',
            dest='forceSuricata',
            help="Force Suricata analysis even on rotated PCAPs",
            metavar='true|false',
            type=str2bool,
            nargs='?',
            const=True,
            default=False,
            required=False,
        )
        requiredNamed.add_argument(
            '--suricata-config',
            dest='suricataConfigFile',
            help='Suricata configuration YAML file',
            metavar='<STR>',
            type=str,
            default=SURICATA_CONFIG_FILE,
        )
        requiredNamed.add_argument(
            '--suricata-directory',
            dest='suricataUploadDir',
            help='Destination directory for Suricata EVE JSON log files',
            metavar='<directory>',
            type=str,
            default=SURICATA_LOG_DIR,
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

    if args.extraTags is not None:
        args.extraTags = [
            tag for tag in [re.sub(r'[^A-Za-z0-9 ._-]', '', x.strip()) for x in args.extraTags.split(',')] if tag
        ]

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
    logging.info(f"{scriptName}:\tsubscribed to topic at {PCAP_TOPIC_PORT}")

    # we'll pull from the topic in the main thread and queue them for processing by the worker threads
    newFileQueue = deque()

    # start worker threads which will pull filenames/tags to be processed by capture
    if processingMode == PCAP_PROCESSING_MODE_ARKIME:
        ThreadPool(
            args.threads,
            arkimeCaptureFileWorker,
            (
                [
                    newFileQueue,
                    args.pcapBaseDir,
                    args.executable,
                    args.nodeName,
                    args.nodeHost,
                    args.autoArkime,
                    args.forceArkime,
                    args.extraTags,
                    args.autoTag,
                    args.notLocked,
                    logging,
                    args.verbose <= logging.DEBUG,
                ],
            ),
        )
    elif processingMode == PCAP_PROCESSING_MODE_ZEEK:
        ThreadPool(
            args.threads,
            zeekFileWorker,
            (
                [
                    newFileQueue,
                    args.pcapBaseDir,
                    args.executable,
                    args.autoZeek,
                    args.forceZeek,
                    args.extraTags,
                    args.autoTag,
                    args.zeekUploadDir,
                    args.zeekExtractFileMode,
                    logging,
                    args.verbose <= logging.DEBUG,
                ],
            ),
        )
    elif processingMode == PCAP_PROCESSING_MODE_SURICATA:
        ThreadPool(
            # threading is done inside of Suricata in socket mode, so just use 1 thread to submit PCAP
            1,
            suricataFileWorker,
            (
                [
                    newFileQueue,
                    args.pcapBaseDir,
                    args.autoSuricata,
                    args.forceSuricata,
                    args.suricataSocketPath,
                    args.extraTags,
                    args.autoTag,
                    args.suricataUploadDir,
                    args.suricataConfigFile,
                    logging,
                    args.verbose <= logging.DEBUG,
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
        except zmq.Again:
            # no file received due to timeout, we'll go around and try again
            fileInfo = None

        if isinstance(fileInfo, dict) and (FILE_INFO_DICT_NAME in fileInfo):
            # queue for the workers to process with capture
            newFileQueue.append(fileInfo)
            logging.info(f"{scriptName}:\t📨\t{fileInfo}")

    # graceful shutdown
    logging.info(f"{scriptName}: shutting down...")
    time.sleep(5)


if __name__ == '__main__':
    main()
