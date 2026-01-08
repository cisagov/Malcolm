#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import csv
import logging
import os
import re
import requests
import sys
import malcolm_utils
from collections import OrderedDict

###################################################################################################
script_name = os.path.basename(__file__)
script_path = os.path.dirname(os.path.realpath(__file__))

urlShortcuts = OrderedDict()
urlShortcuts['drahgkar'] = 'https://github.com/Drahgkar/ports-and-protocols/raw/refs/heads/main/ports_and_protocols.csv'
urlShortcuts['iana'] = 'https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.csv'
urlShortcutsKeys = OrderedDict()
urlShortcutsKeys['drahgkar'] = [
    'Port',
    'Protocol',
    'Service',
    'Note',
    'Reference',
]
urlShortcutsKeys['iana'] = [
    'Service Name',
    'Port Number',
    'Transport Protocol',
    'Description',
    'Assignee',
    'Contact',
    'Registration Date',
    'Modification Date',
    'Reference',
    'Service Code',
    'Unauthorized Use Reported',
    'Assignment Notes',
]


def download(url, local_filename, debug=False):
    r = requests.get(url, stream=True, allow_redirects=True)
    with open(local_filename, 'wb') as f:
        for chunk in r.iter_content(chunk_size=1024):
            if chunk:
                f.write(chunk)
    fExists = os.path.isfile(local_filename)
    fSize = os.path.getsize(local_filename)
    logging.debug(
        f"Download of {url} to {local_filename} {'succeeded' if fExists else 'failed'} ({malcolm_utils.sizeof_fmt(fSize)})"
    )
    return fExists and (fSize > 0)


def cleanstring(v):
    return re.sub(r'\s+', ' ', str(v)).strip()


def processCsv(inputFileName, outputFileName):
    with open(inputFileName, "r") as csvFile:
        dialect = csv.Sniffer().sniff(csvFile.read(1024))
        csvFile.seek(0)
        reader = csv.DictReader(csvFile, dialect=dialect)
        matchedKnownSource = None
        for name, keys in urlShortcutsKeys.items():
            if keys == reader.fieldnames:
                matchedKnownSource = name
                break
        if matchedKnownSource:
            alreadyWritten = dict()
            with open(outputFileName, 'w') as outfile:
                outfile.write("#fields\tproto\tdport\tname\tdescription\n")
                for row in reader:
                    match matchedKnownSource:
                        case 'drahgkar':
                            if (row.get('Protocol', '?') != '?') and row.get('Port', None):
                                proto, port, service, note = (
                                    cleanstring(row.get('Protocol', '')),
                                    cleanstring(row.get('Port', '')),
                                    cleanstring(row.get('Service', '')),
                                    cleanstring(row.get('Note', '')),
                                )
                        case 'iana':
                            proto, port, service, note = (
                                cleanstring(row.get('Transport Protocol', '')),
                                cleanstring(row.get('Port Number', '')),
                                cleanstring(row.get('Service Name', '')),
                                cleanstring(row.get('Description', '')),
                            )
                        case _:
                            proto, port, service, note = '', '', '', ''

                    note = re.sub(
                        r'\s*iana assigned this well-formed service name as a replacement for.*',
                        '',
                        note,
                        flags=re.IGNORECASE,
                    )
                    name = '' if name.lower() == 'unknown' else name

                    if (
                        proto
                        and (proto.lower() in ('tcp', 'udp', 'icmp'))
                        and port
                        and port.isdigit()
                        and (
                            service
                            or (
                                note
                                and not any(
                                    note.lower().startswith(prefix.lower())
                                    for prefix in ('de-registered', 'reserved', 'unassigned')
                                )
                            )
                        )
                    ):
                        if (proto, port) not in alreadyWritten:
                            alreadyWritten[(proto, port)] = f"{proto}\t{port}\t{service or ''}\t{note or ''}"
                            outfile.write(f"{alreadyWritten[(proto, port)]}\n")

                return True

    return False


###################################################################################################
# main
def main():
    parser = argparse.ArgumentParser(
        description='\n'.join([]),
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
    # https://www.iana.org/assignments/protocol-numbers/protocol-numbers-1.csv
    parser.add_argument(
        '-u',
        '--url',
        dest='inputUrls',
        nargs='*',
        type=str,
        default=urlShortcuts.keys(),
        help="One or more URLs to download from (they are NOT combined: the first one that works is used)",
    )
    parser.add_argument(
        '-i',
        '--input-file',
        dest='inputFile',
        metavar='<str>',
        type=str,
        default='',
        help="Input CSV file to use (takes precedence over -u/--urls)",
    )
    parser.add_argument(
        '-o',
        '--output-file',
        dest='outputFile',
        metavar='<str>',
        type=str,
        default='',
        help="Output filename for resultant Zeek table",
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

    if not args.outputFile:
        args.outputFile = '/tmp/iana.zeek'

    if args.inputFile and os.path.isfile(args.inputFile) and processCsv(args.inputFile, args.outputFile):
        # TODO:
        pass
    else:
        for url in args.inputUrls:
            with malcolm_utils.temporary_filename('.csv') as csvFilename:
                try:
                    if downloaded := download(urlShortcuts.get(url, url), csvFilename) and processCsv(
                        csvFilename, args.outputFile
                    ):
                        # TODO
                        break
                except Exception as e:
                    logging.critical(e)


###################################################################################################
if __name__ == '__main__':
    main()
