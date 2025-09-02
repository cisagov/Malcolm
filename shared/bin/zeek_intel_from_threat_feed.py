#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2025 Battelle Energy Alliance, LLC.  All rights reserved.

from collections import deque
from dateparser import parse as ParseDate
from datetime import datetime
from multiprocessing.pool import ThreadPool
from pytz import utc as UTCTimeZone
from time import sleep
import argparse
import logging
import os
import re
import sys
import yaml
import zeek_threat_feed_utils

import malcolm_utils
from contextlib import nullcontext

###################################################################################################
script_name = os.path.basename(__file__)
script_path = os.path.dirname(os.path.realpath(__file__))


###################################################################################################
# main
def main():
    parser = argparse.ArgumentParser(
        description='\n'.join(
            [
                'Outputs a Zeek intelligence framework file from various formats used to represent threat information:',
                ' - "Indicator" objects in STIX™ v2.0/v2.1 JSON files',
                ' - MISP attributes or core format JSON files',
                ' - Indicators from Mantiant Threat Intelligence',
                '',
                'See:',
                ' - Malcolm documentation: https://idaholab.github.io/Malcolm/docs/zeek-intel.html#ZeekIntel',
                ' - Zeek intelligence framework: https://docs.zeek.org/en/master/frameworks/intel.html',
                ' - Zeek intel types: https://docs.zeek.org/en/stable/scripts/base/frameworks/intel/main.zeek.html#type-Intel::Type',
                ' - Introduction to STIX: https://oasis-open.github.io/cti-documentation/stix/intro.html',
                ' - Introduction to TAXII: https://oasis-open.github.io/cti-documentation/taxii/intro.html',
                ' - STIX cyber-observable objects: https://docs.oasis-open.org/cti/stix/v2.1/cs01/stix-v2.1-cs01.html#_mlbmudhl16lr',
                ' - MISP core format: https://github.com/MISP/misp-rfc/blob/master/misp-core-format/raw.md.txt',
                ' - MISP communities: https://www.misp-project.org/communities/',
                ' - MISP default feeds: https://www.misp-project.org/feeds/',
                ' - Managing MISP feeds: https://misp.gitbooks.io/misp-book/content/managing-feeds/',
                ' - Expand MISP usage: https://github.com/idaholab/Malcolm/issues/336',
                ' - Mandiant Threat Intelligence Indicators API: https://docs.mandiant.com/home/mati-threat-intelligence-api-v4#tag/Indicators'
                '',
                'Note: The Zeek intelligence framework only supports simple indicators matched against a single value.',
                'The STIX™ standard can express more complex indicators that cannot be expressed with Zeek intelligence items.',
            ]
        ),
        formatter_class=argparse.RawTextHelpFormatter,
        add_help=True,
        usage='{} <arguments>'.format(script_name),
    )
    parser.add_argument(
        '--verbose',
        '-v',
        action='count',
        default=malcolm_utils.get_verbosity_env_var_count("VERBOSITY"),
        help='Increase verbosity (e.g., -v, -vv, etc.)',
    )
    parser.add_argument(
        '--notice',
        dest='notice',
        type=malcolm_utils.str2bool,
        nargs='?',
        const=True,
        default=True,
        help='Add fields for policy/frameworks/intel/do_notice.zeek',
    )
    parser.add_argument(
        '--cif',
        dest='cif',
        type=malcolm_utils.str2bool,
        nargs='?',
        const=True,
        default=True,
        help='Add fields for policy/integration/collective-intel/main.zeek',
    )
    parser.add_argument(
        '--extended',
        dest='extended',
        type=malcolm_utils.str2bool,
        nargs='?',
        const=True,
        default=True,
        help='Add fields for corelight/ExtendIntel',
    )
    parser.add_argument(
        '--ssl-verify',
        dest='sslVerify',
        type=malcolm_utils.str2bool,
        nargs='?',
        const=True,
        default=False,
        help='Require TLS connections to verify certificates',
    )
    parser.add_argument(
        '-i',
        '--input',
        dest='input',
        nargs='*',
        type=str,
        default=None,
        help="JSON file(s), TAXII 2.x URL(s) or MISP URL(s), e.g.\n\ttaxii|2.0|http://example.com/discovery|Collection Name|user|password\n\tmisp|https://example.com/data/feed-osint/manifest.json|auth_key",
    )
    parser.add_argument(
        '--input-file',
        dest='inputFile',
        nargs='*',
        type=str,
        default=None,
        help="Read --input arguments from a local or external file (one per line, or YAML definitions)",
    )
    parser.add_argument(
        '-o',
        '--output',
        dest='output',
        type=str,
        default=None,
        help="Output file (stdout if unspecified)",
    )
    parser.add_argument(
        '--since',
        dest='since',
        type=str,
        default=None,
        help="Retrieve indicators since this timestamp",
    )
    parser.add_argument(
        '-t',
        '--threads',
        dest='threads',
        type=int,
        default=zeek_threat_feed_utils.ZEEK_INTEL_WORKER_THREADS_DEFAULT,
        help="Worker threads",
    )
    try:
        args = parser.parse_args()
    except SystemExit as e:
        if e.code == 2:
            parser.print_help()
        sys.exit(e.code)

    args.verbose = malcolm_utils.set_logging(os.getenv("LOGLEVEL", ""), args.verbose, set_traceback_limit=True)
    logging.debug(os.path.join(script_path, script_name))
    logging.debug(f"Arguments: {sys.argv[1:]}")
    logging.debug(f"Arguments: {args}")

    if args.input is None:
        args.input = []
    yamlInputs = []
    since = (
        ParseDate(args.since).astimezone(UTCTimeZone) if (args.since is not None) and (len(args.since) > 0) else None
    )
    defaultNow = datetime.now().astimezone(UTCTimeZone)
    successCount = malcolm_utils.AtomicInt(value=0)

    with open(args.output, 'w') if args.output is not None else nullcontext() as outfile:
        zeekPrinter = zeek_threat_feed_utils.FeedParserZeekPrinter(
            args.extended, args.notice, args.cif, since=since, file=outfile, logger=logging
        )

        # if --input-file is specified, process first and append to  --input
        if (args.inputFile is not None) and (len(args.inputFile) > 0):
            for infileArg in args.inputFile:
                try:
                    if os.path.isfile(infileArg):
                        # read inputs from local file (delimited lines or YAML file)
                        infileParts = os.path.splitext(infileArg)
                        if re.search(r"\.ya?ml$", infileParts[1], re.IGNORECASE):
                            with open(infileArg, 'r') as f:
                                inputParams = yaml.safe_load(f)
                            if inputParams:
                                if isinstance(inputParams, dict):
                                    yamlInputs.append(inputParams)
                                elif isinstance(inputParams, list):
                                    yamlInputs.extend(inputParams)
                                else:
                                    logging.error(
                                        f"Connection parameters of type '{type(inputParams).__name__}' are not supported"
                                    )
                        else:
                            with open(infileArg) as f:
                                args.input.extend(f.read().splitlines())

                    elif '://' in infileArg:
                        # download from URL and read input from remote file
                        with malcolm_utils.temporary_filename(suffix='.txt') as tmpFileName:
                            dlFileName = zeek_threat_feed_utils.download_to_file(
                                infileArg,
                                ssl_verify=args.sslVerify,
                                local_filename=tmpFileName,
                                logger=logging,
                            )
                            if dlFileName is not None and os.path.isfile(dlFileName):
                                with open(dlFileName) as f:
                                    args.input.extend(f.read().splitlines())

                    else:
                        logging.warning(f"File '{infileArg}' not found")

                except Exception as e:
                    logging.critical(f"{type(e).__name__} for '{infileArg}': {e}")

        # deduplicate input sources
        seenInput = {}
        args.input = [seenInput.setdefault(x, x) for x in args.input if x not in seenInput]

        # we'll queue and then process all of the input arguments in workers
        inputQueue = deque()
        if args.input:
            inputQueue.extend(args.input)
        if yamlInputs:
            inputQueue.extend(yamlInputs)
        logging.debug(f"Inputs: {list(inputQueue)}")

        workerThreadCount = malcolm_utils.AtomicInt(value=0)
        ThreadPool(
            args.threads,
            zeek_threat_feed_utils.ProcessThreatInputWorker,
            (
                [
                    inputQueue,
                    zeekPrinter,
                    since,
                    args.sslVerify,
                    defaultNow,
                    workerThreadCount,
                    successCount,
                    logging,
                ],
            ),
        )

        # wait until all inputs are processed and threads are finished
        sleep(1)
        while len(inputQueue) > 0:
            sleep(1)
        while workerThreadCount.value() > 0:
            sleep(1)

    return successCount.value()


###################################################################################################
if __name__ == '__main__':
    if main() > 0:
        sys.exit(0)
    else:
        sys.exit(1)
