#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import os
import json
import sys
import logging

from stix2.v20 import Indicator as Indicator_v20
from stix2.v21 import Indicator as Indicator_v21
from stix2 import parse as StixParse
from stix2 import exceptions as StixExceptions
import mmguero
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
    parser.add_argument(
        '-o', '--output', dest='output', nargs=1, type=str, metavar='<STR>', default=None, help='Output file'
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

    for infile in args.input:
        with open(infile) as f:
            try:
                for obj in StixParse(f).objects:
                    if (type(obj) is Indicator_v20) or (type(obj) is Indicator_v21):
                        val = stix_zeek_utils.map_indicator_to_zeek(indicator=obj, logger=logging)
                        if val is not None:
                            print(val)
            except StixExceptions.InvalidValueError as ve:
                logging.error(f"ValueError parsing {infile}: {ve}")


###################################################################################################
if __name__ == '__main__':
    main()
