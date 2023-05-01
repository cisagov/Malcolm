#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import csv
import os
import re
import sys

try:
    import ruamel.yaml as yaml
except ImportError:
    import yaml

from netaddr import EUI
from operator import itemgetter

import malcolm_utils
from malcolm_utils import eprint, str2bool

###################################################################################################
args = None
debug = False
script_name = os.path.basename(__file__)
script_path = os.path.dirname(os.path.realpath(__file__))
orig_path = os.getcwd()

padded_mac_low = '00:00:00:00:00:00'
padded_mac_high = 'FF:FF:FF:FF:FF:FF'


###################################################################################################
# main
def main():
    global args
    global debug

    parser = argparse.ArgumentParser(
        description=script_name, add_help=False, usage='{} <arguments>'.format(script_name)
    )
    parser.add_argument(
        '-v',
        '--verbose',
        dest='debug',
        type=str2bool,
        nargs='?',
        const=True,
        default=False,
        metavar='true|false',
        help="Verbose/debug output",
    )
    parser.add_argument(
        '-i', '--input', dest='input', type=str, default=None, required=False, metavar='<string>', help="Input"
    )
    try:
        parser.error = parser.exit
        args = parser.parse_args()
    except SystemExit:
        parser.print_help()
        exit(2)

    debug = args.debug
    if debug:
        eprint(os.path.join(script_path, script_name))
        eprint("Arguments: {}".format(sys.argv[1:]))
        eprint("Arguments: {}".format(args))
    else:
        sys.tracebacklimit = 0

    if os.path.isfile(args.input):
        ouis = []
        with open(args.input, "r") as infile:
            reader = csv.DictReader(infile, delimiter=',')
            ouis.extend(
                [line for line in reader if 'oui' in line and 'companyName' in line and 'assignmentBlockSize' in line]
            )

    companies = []

    for oui in ouis:
        # MA-L leftmost 24 bits
        # MA-M leftmost 28 bits
        # MA-S leftmost 36 bits
        # IAB  leftmost 36 bits?
        macPad = oui['oui'][0 : len(padded_mac_low)]
        macPadLow = macPad + padded_mac_low[-(len(padded_mac_low) - len(macPad)) :]
        macPadHigh = macPad + padded_mac_high[-(len(padded_mac_high) - len(macPad)) :]
        macLow = EUI(macPadLow.replace(':', '-'))
        macHigh = EUI(macPadHigh.replace(':', '-'))
        companies.append(
            {
                'name': oui['companyName'],
                'low': str(macLow),
                # 'low': int(re.sub("[.:-]", "", str(macLow)), 16),
                'high': str(macHigh),
                # 'high': int(re.sub("[.:-]", "", str(macHigh)), 16),
            }
        )

    companies.sort(key=lambda x: (x['low'], x['high']))
    print(yaml.dump(companies, allow_unicode=True))
    eprint(len(companies))


###################################################################################################
if __name__ == '__main__':
    main()
