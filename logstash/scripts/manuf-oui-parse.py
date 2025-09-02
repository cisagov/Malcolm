#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import manuf
import os
import re
import requests
import sys
import tempfile
import logging

import malcolm_utils
from malcolm_utils import str2bool, set_logging, get_verbosity_env_var_count

try:
    import ruamel.yaml as yaml
except ImportError:
    import yaml

DEFAULT_MANUF_URL = "https://www.wireshark.org/download/automated/data/manuf"
padded_mac_low = '00:00:00:00:00:00'
padded_mac_high = 'FF:FF:FF:FF:FF:FF'
mac_pattern = re.compile(r"[-:\.]")

###################################################################################################
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
    parser = argparse.ArgumentParser(description=scriptName, add_help=True, usage='{} <arguments>'.format(scriptName))
    parser.add_argument(
        '--verbose',
        '-v',
        action='count',
        default=get_verbosity_env_var_count("VERBOSITY"),
        help='Increase verbosity (e.g., -v, -vv, etc.)',
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
        args = parser.parse_args()
    except SystemExit as e:
        if e.code == 2:
            parser.print_help()
        sys.exit(e.code)

    args.verbose = set_logging(os.getenv("LOGLEVEL", ""), args.verbose, set_traceback_limit=True)
    logging.debug(os.path.join(scriptPath, scriptName))
    logging.debug(f"Arguments: {sys.argv[1:]}")
    logging.debug(f"Arguments: {args}")

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
