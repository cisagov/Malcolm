#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import print_function

from bs4 import BeautifulSoup
import argparse
import os
import sys

###################################################################################################
debug = False
PY3 = sys.version_info.major >= 3
scriptName = os.path.basename(__file__)
scriptPath = os.path.dirname(os.path.realpath(__file__))
origPath = os.getcwd()

###################################################################################################
try:
    FileNotFoundError
except NameError:
    FileNotFoundError = IOError


###################################################################################################
# print to stderr
def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)


###################################################################################################
# convenient boolean argument parsing
def str2bool(v):
    if v.lower() in ('yes', 'true', 't', 'y', '1'):
        return True
    elif v.lower() in ('no', 'false', 'f', 'n', '0'):
        return False
    else:
        raise argparse.ArgumentTypeError('Boolean value expected.')


###################################################################################################
# main
def main():
    global debug

    parser = argparse.ArgumentParser(description=scriptName, add_help=False, usage='{} <arguments>'.format(scriptName))
    parser.add_argument(
        '-v', '--verbose', dest='debug', type=str2bool, nargs='?', const=True, default=False, help="Verbose output"
    )
    parser.add_argument('-i', '--input', required=True, metavar='<STR>', type=str, help='Input file')
    parser.add_argument('-o', '--output', required=True, metavar='<STR>', type=str, help='Output file')
    parser.add_argument(
        '-c',
        '--div-class',
        required=True,
        dest='divClass',
        metavar='<STR>',
        type=str,
        default='',
        help='div class to remove',
    )
    parser.add_argument(
        '-p',
        '--parser',
        required=False,
        dest='parser',
        metavar='<STR>',
        type=str,
        default='html.parser',
        help='BeautifulSoup parser',
    )
    parser.add_argument(
        '-e',
        '--encoding',
        required=False,
        dest='encoding',
        metavar='<STR>',
        type=str,
        default='utf-8',
        help='Encoding for output file',
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

    soup = BeautifulSoup(open(args.input), args.parser)
    for div in soup.find_all("div", {'class': args.divClass}):
        div.decompose()

    with open(args.output, 'wb') as f:
        f.write(soup.prettify(args.encoding))


if __name__ == '__main__':
    main()
