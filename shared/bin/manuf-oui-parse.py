#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import manuf
import os
import re
import requests
import sys
import tempfile

import malcolm_utils
from malcolm_utils import eprint, str2bool

try:
    import ruamel.yaml as yaml
except ImportError:
    import yaml

DEFAULT_MANUF_URL = "https://gitlab.com/wireshark/wireshark/raw/release-4.0/manuf"
padded_mac_low = '00:00:00:00:00:00'
padded_mac_high = 'FF:FF:FF:FF:FF:FF'
mac_pattern = re.compile(r"[-:\.]")

###################################################################################################
debug = False
scriptName = os.path.basename(__file__)
scriptPath = os.path.dirname(os.path.realpath(__file__))
origPath = os.getcwd()


def strip_mac(mac):
    return mac_pattern.sub("", mac)


def bits_left(mac_str):
    return 48 - 4 * len(strip_mac(mac_str))


###################################################################################################
# main
def main():
    global debug

    parser = argparse.ArgumentParser(description=scriptName, add_help=False, usage='{} <arguments>'.format(scriptName))
    parser.add_argument(
        '-v',
        '--verbose',
        dest='debug',
        type=str2bool,
        nargs='?',
        const=True,
        default=False,
        help="Verbose output",
    )
    parser.add_argument(
        '-i',
        '--input',
        required=False,
        dest='input',
        metavar='<STR>',
        type=str,
        default=DEFAULT_MANUF_URL,
        help='Input file or URL',
    )
    parser.add_argument(
        '-o', '--output', required=True, dest='output', metavar='<STR>', type=str, default='', help='Output file'
    )
    try:
        parser.error = parser.exit
        args = parser.parse_args()
    except SystemExit:
        parser.print_help()
        exit(2)

    debug = args.debug
    if debug:
        eprint(os.path.join(scriptPath, scriptName))
        eprint("Arguments: {}".format(sys.argv[1:]))
        eprint("Arguments: {}".format(args))
    else:
        sys.tracebacklimit = 0

    if args.input.lower().startswith('http') and not os.path.isfile(args.input):
        tmpf = tempfile.NamedTemporaryFile(delete=True, suffix=".txt")
        r = requests.get(args.input)
        with open(tmpf.name, 'wb') as f:
            f.write(r.content)
        args.input = tmpf.name

    companies = []

    for k, v in manuf.MacParser(manuf_name=args.input)._masks.items():
        macLow = ':'.join('{:02x}'.format(x) for x in (k[1] << k[0]).to_bytes(6, byteorder='big'))
        macHigh = ':'.join(
            '{:02x}'.format(x)
            for x in ((k[1] << k[0]) | (int("ffffffffffff", 16) >> (48 - k[0]))).to_bytes(6, byteorder='big')
        )
        companies.append(
            {
                'name': v.manuf_long,
                'low': macLow,
                'high': str(macHigh),
            }
        )

    companies.sort(key=lambda x: (x['low'], x['high']))
    with open(args.output, 'w+') as outfile:
        yaml.dump(companies, outfile, allow_unicode=True)


if __name__ == '__main__':
    main()
