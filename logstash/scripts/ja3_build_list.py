#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import datetime
import hashlib
import json
import os
import platform
import pprint
import re
import requests
import string
import sys

try:
    import ruamel.yaml as yaml
except ImportError:
    import yaml
from collections import defaultdict

###################################################################################################
debug = False
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

    ja3Map = defaultdict(list)
    fingerprint = None

    try:
        url = (
            'https://raw.githubusercontent.com/LeeBrotherston/tls-fingerprinting/master/fingerprints/fingerprints.json'
        )
        keys = ['record_tls_version', 'ciphersuite', 'extensions', 'e_curves', 'ec_point_fmt']
        for fingerprint in [x for x in requests.get(url).text.splitlines() if (len(x) > 0) and (not x.startswith('#'))]:
            try:
                values = list()
                tmpMap = defaultdict(str)
                tmpMap.update(json.loads(fingerprint))
                for key in keys:
                    values.append('-'.join([str(int(x, 0)) for x in tmpMap[key].split()]))
                ja3Map[hashlib.md5(','.join(values).encode()).hexdigest()].extend(
                    tmpMap['desc'].strip('"').strip("'").split(' / ')
                )
            except Exception as e:
                eprint('"{}" raised for "{}"'.format(str(e), fingerprint))
    except Exception as e:
        eprint('"{}" raised for "{}"'.format(str(e), fingerprint))

    urls = ['https://raw.githubusercontent.com/trisulnsm/ja3prints/master/ja3fingerprint.json']
    for url in urls:
        try:
            for fingerprint in [
                x for x in requests.get(url).text.splitlines() if (len(x) > 0) and (not x.startswith('#'))
            ]:
                try:
                    values = list()
                    tmpMap = defaultdict(str)
                    tmpMap.update(json.loads(fingerprint))
                    ja3Map[tmpMap['ja3_hash'].strip()].append(tmpMap['desc'].strip('"').strip("'"))
                except Exception as e:
                    eprint('"{}" raised for "{}"'.format(str(e), fingerprint))
        except Exception as e:
            eprint('"{}" raised for "{}"'.format(str(e), fingerprint))

    # this one has desc and ja3_hash backwards from the previous one
    urls = ['https://raw.githubusercontent.com/trisulnsm/ja3prints/master/newprints.json']
    for url in urls:
        try:
            for fingerprint in [
                x for x in requests.get(url).text.splitlines() if (len(x) > 0) and (not x.startswith('#'))
            ]:
                try:
                    values = list()
                    tmpMap = defaultdict(str)
                    tmpMap.update(json.loads(fingerprint))
                    ja3Map[tmpMap['desc'].strip()].append(tmpMap['ja3_hash'].strip('"').strip("'"))
                except Exception as e:
                    eprint('"{}" raised for "{}"'.format(str(e), fingerprint))
        except Exception as e:
            eprint('"{}" raised for "{}"'.format(str(e), fingerprint))

    # this one is csv (and overlaps the previous one a lot)
    try:
        url = 'https://raw.githubusercontent.com/salesforce/ja3/master/lists/osx-nix-ja3.csv'
        for fingerprint in [x for x in requests.get(url).text.splitlines() if (len(x) > 0) and (not x.startswith('#'))]:
            vals = ' '.join(fingerprint.split()).split(',', 1)
            if (len(vals) == 2) and (len(vals[0]) == 32):
                ja3Map[vals[0].strip()].append(vals[1].strip('"').strip("'"))
    except Exception as e:
        eprint('"{}" raised for "{}"'.format(str(e), fingerprint))

    # todo: https://sslbl.abuse.ch/ja3-fingerprints/

    finalMap = dict()
    for k, v in ja3Map.items():
        if (len(k) == 32) and all(c in string.hexdigits for c in k):
            finalMap[k] = list(set([element.strip('"').strip("'").strip() for element in v]))

    with open(args.output, 'w+') as outfile:
        yaml.dump(finalMap, outfile)


if __name__ == '__main__':
    main()
