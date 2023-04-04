#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2023 Battelle Energy Alliance, LLC.  All rights reserved.

from collections import deque
from dateparser import parse as ParseDate
from datetime import datetime
from multiprocessing.pool import ThreadPool
from pytz import utc as UTCTimeZone
from time import sleep
import argparse
import logging
import os
import sys
import zeek_threat_feed_utils

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
                ' - MISP core format JSON files',
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
                '',
                'Note: The Zeek intelligence framework only supports simple indicators matched against a single value.',
                'The STIX™ standard can express more complex indicators that cannot be expressed with Zeek intelligence items.',
            ]
        ),
        formatter_class=argparse.RawTextHelpFormatter,
        add_help=False,
        usage='{} <arguments>'.format(script_name),
    )
    parser.add_argument('--verbose', '-v', action='count', default=1, help='Increase verbosity (e.g., -v, -vv, etc.)')
    parser.add_argument(
        '--notice', dest='notice', action='store_true', help='Add fields for policy/frameworks/intel/do_notice.zeek'
    )
    parser.add_argument(
        '--no-notice',
        dest='notice',
        action='store_false',
        help='Do not add fields for policy/frameworks/intel/do_notice.zeek',
    )
    parser.set_defaults(notice=True)
    parser.add_argument(
        '--cif',
        dest='cif',
        action='store_true',
        help='Add fields for policy/integration/collective-intel/main.zeek',
    )
    parser.add_argument(
        '--no-cif',
        dest='cif',
        action='store_false',
        help='Do not add fields for policy/integration/collective-intel/main.zeek',
    )
    parser.set_defaults(cif=True)
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
        help="Read --input arguments from a local or external file (one per line)",
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
        parser.error = parser.exit
        args = parser.parse_args()
    except SystemExit:
        parser.print_help()
        exit(2)

    args.verbose = logging.CRITICAL - (10 * args.verbose) if args.verbose > 0 else 0
    logging.basicConfig(
        level=args.verbose, format='%(asctime)s %(levelname)s: %(message)s', datefmt='%Y-%m-%d %H:%M:%S'
    )

    logging.info(os.path.join(script_path, script_name))
    logging.info("Arguments: {}".format(sys.argv[1:]))
    logging.info("Arguments: {}".format(args))
    if args.verbose > logging.DEBUG:
        sys.tracebacklimit = 0

    if args.input is None:
        args.input = []
    since = (
        ParseDate(args.since).astimezone(UTCTimeZone) if (args.since is not None) and (len(args.since) > 0) else None
    )
    defaultNow = datetime.now().astimezone(UTCTimeZone)

    with open(args.output, 'w') if args.output is not None else nullcontext() as outfile:
        zeekPrinter = zeek_threat_feed_utils.FeedParserZeekPrinter(
            args.notice, args.cif, since=since, file=outfile, logger=logging
        )

        # if --input-file is specified, process first and append to  --input
        if (args.inputFile is not None) and (len(args.inputFile) > 0):
            for infileArg in args.inputFile:
                try:
                    if os.path.isfile(infileArg):
                        # read inputs from local file
                        with open(infileArg) as f:
                            args.input.extend(f.read().splitlines())

                    elif '://' in infileArg:
                        # download from URL and read input from remote file
                        with zeek_threat_feed_utils.temporary_filename(suffix='.txt') as tmpFileName:
                            dlFileName = zeek_threat_feed_utils.download_to_file(
                                infileArg,
                                local_filename=tmpFileName,
                                logger=logging,
                            )
                            if dlFileName is not None and os.path.isfile(dlFileName):
                                with open(dlFileName) as f:
                                    args.input.extend(f.read().splitlines())

                    else:
                        logging.warning(f"File '{infileArg}' not found")
                except Exception as e:
                    logging.warning(f"{type(e).__name__} for '{infileArg}': {e}")

        # deduplicate input sources
        seenInput = {}
        args.input = [seenInput.setdefault(x, x) for x in args.input if x not in seenInput]
        logging.debug(f"Input: {args.input}")

        # we'll queue and then process all of the input arguments in workers
        inputQueue = deque()
        inputQueue.extend(args.input)
        workerThreadCount = zeek_threat_feed_utils.AtomicInt(value=0)
        workerThreads = ThreadPool(
            args.threads,
            zeek_threat_feed_utils.ProcessThreatInputWorker,
            (
                [
                    inputQueue,
                    zeekPrinter,
                    since,
                    workerThreadCount,
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


###################################################################################################
if __name__ == '__main__':
    main()
