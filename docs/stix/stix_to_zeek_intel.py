#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import datetime
import json
import logging
import os
import sys

from stix2 import exceptions as StixExceptions
from stix2 import parse as StixParse
from stix2.utils import STIXdatetime
from stix2.v20 import Indicator as Indicator_v20
from stix2.v21 import Indicator as Indicator_v21
import stix_zeek_utils

###################################################################################################
script_name = os.path.basename(__file__)
script_path = os.path.dirname(os.path.realpath(__file__))
orig_path = os.getcwd()

###################################################################################################
# main
def main():
    global args
    global debug

    parser = argparse.ArgumentParser(
        description=script_name, add_help=False, usage='{} <arguments>'.format(script_name)
    )
    parser.add_argument('--verbose', '-v', action='count', default=1)
    parser.add_argument('--notice', dest='notice', action='store_true')
    parser.add_argument('--no-notice', dest='notice', action='store_false')
    parser.set_defaults(notice=True)
    parser.add_argument('--cif', dest='cif', action='store_true')
    parser.add_argument('--no-cif', dest='cif', action='store_false')
    parser.set_defaults(cif=True)
    parser.add_argument(
        '-i',
        '--input',
        dest='input',
        nargs='*',
        type=str,
        default=None,
        required=True,
        metavar='<STR>',
        help="STIX file(s)",
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

    logging.debug(os.path.join(script_path, script_name))
    logging.debug("Arguments: {}".format(sys.argv[1:]))
    logging.debug("Arguments: {}".format(args))
    if args.verbose > logging.DEBUG:
        sys.tracebacklimit = 0

    fields = [
        stix_zeek_utils.ZEEK_INTEL_INDICATOR,
        stix_zeek_utils.ZEEK_INTEL_INDICATOR_TYPE,
        stix_zeek_utils.ZEEK_INTEL_META_SOURCE,
        stix_zeek_utils.ZEEK_INTEL_META_DESC,
        stix_zeek_utils.ZEEK_INTEL_META_URL,
    ]
    if args.notice:
        fields.extend(
            [
                stix_zeek_utils.ZEEK_INTEL_META_DO_NOTICE,
            ]
        )
    if args.cif:
        fields.extend(
            [
                stix_zeek_utils.ZEEK_INTEL_CIF_TAGS,
                stix_zeek_utils.ZEEK_INTEL_CIF_CONFIDENCE,
                stix_zeek_utils.ZEEK_INTEL_CIF_SOURCE,
                stix_zeek_utils.ZEEK_INTEL_CIF_DESCRIPTION,
                stix_zeek_utils.ZEEK_INTEL_CIF_FIRSTSEEN,
                stix_zeek_utils.ZEEK_INTEL_CIF_LASTSEEN,
            ]
        )

    print('\t'.join(['#fields'] + fields))
    for infile in args.input:
        with open(infile) as f:
            try:
                for obj in StixParse(f).objects:
                    if (type(obj) is Indicator_v20) or (type(obj) is Indicator_v21):
                        if vals := stix_zeek_utils.map_indicator_to_zeek(indicator=obj, logger=logging):
                            for val in vals:
                                print('\t'.join([val[key] for key in fields]))
            except StixExceptions.InvalidValueError as ve:
                logging.error(f"ValueError parsing {infile}: {ve}")


###################################################################################################
if __name__ == '__main__':
    main()
