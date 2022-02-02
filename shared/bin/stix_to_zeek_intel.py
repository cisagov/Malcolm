#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2022 Battelle Energy Alliance, LLC.  All rights reserved.

import argparse
import logging
import json
import os
import sys

from contextlib import nullcontext
from stix2 import parse as StixParse
from stix2.exceptions import STIXError
from stix2.utils import STIXdatetime
from taxii2client.v20 import as_pages as TaxiiAsPages_v20
from taxii2client.v20 import Collection as TaxiiCollection_v20
from taxii2client.v20 import Server as TaxiiServer_v20
from taxii2client.v21 import as_pages as TaxiiAsPages_v21
from taxii2client.v21 import Collection as TaxiiCollection_v21
from taxii2client.v21 import Server as TaxiiServer_v21

import stix_zeek_utils

###################################################################################################
script_name = os.path.basename(__file__)
script_path = os.path.dirname(os.path.realpath(__file__))

###################################################################################################
# main
def main():
    parser = argparse.ArgumentParser(
        description='\n'.join(
            [
                'Outputs a Zeek intelligence framework file from "Indicator" objects in STIX™ v2.0/v2.1 JSON files.',
                '',
                'See:',
                ' - Zeek intelligence framework: https://docs.zeek.org/en/master/frameworks/intel.html',
                ' - Zeek intel types: https://docs.zeek.org/en/stable/scripts/base/frameworks/intel/main.zeek.html#type-Intel::Type',
                ' - STIX cyber-observable objects: https://docs.oasis-open.org/cti/stix/v2.1/cs01/stix-v2.1-cs01.html#_mlbmudhl16lr',
                ' - Malcolm documentation: https://github.com/idaholab/Malcolm#zeek-intelligence-framework',
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
        required=True,
        help="STIX file(s)",
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

    # we'll print the #fields header the first tim ewe print a valid row
    headerPrinted = False

    # process each given STIX input
    for infile in args.input:
        try:
            with open(infile) if ((infile is not None) and os.path.isfile(infile)) else nullcontext() as f:

                if f:
                    # this is a STIX file, open and parse it
                    try:
                        # parse the STIX file and process all "Indicator" objects
                        for obj in StixParse(f, allow_custom=True).objects:
                            if type(obj).__name__ == "Indicator":

                                # map indicator object to Zeek value(s)
                                if vals := stix_zeek_utils.map_indicator_to_zeek(indicator=obj, logger=logging):
                                    for val in vals:
                                        if not headerPrinted:
                                            print('\t'.join(['#fields'] + fields))
                                            headerPrinted = True
                                        # print the intelligence item fields according to the columns in 'fields'
                                        print('\t'.join([val[key] for key in fields]))

                    except STIXError as ve:
                        logging.error(f"{type(ve).__name__} parsing '{infile}': {ve}")

                elif infile.lower().startswith('taxii'):
                    # this is a TAXII URL, connect and retrieve STIX indicators from it

                    # taxii|2.0|discovery_url|collection_name|username|password
                    taxiiConnInfo = [stix_zeek_utils.base64_decode_if_prefixed(x) for x in infile.split('|')[1::]]
                    taxiiVersion, taxiiDisoveryURL, taxiiCollectionName, taxiiUsername, taxiiPassword = (
                        None,
                        None,
                        None,
                        None,
                        None,
                    )
                    if len(taxiiConnInfo) >= 3:
                        taxiiVersion, taxiiDisoveryURL, taxiiCollectionName = taxiiConnInfo[0:3]
                    if len(taxiiConnInfo) >= 4:
                        taxiiUsername = taxiiConnInfo[3]
                    if len(taxiiConnInfo) >= 5:
                        taxiiPassword = taxiiConnInfo[4]

                    # connect to the server with the appropriate API for the TAXII version
                    if taxiiVersion == '2.0':
                        server = TaxiiServer_v20(taxiiDisoveryURL, user=taxiiUsername, password=taxiiPassword)
                    elif taxiiVersion == '2.1':
                        server = TaxiiServer_v21(taxiiDisoveryURL, user=taxiiUsername, password=taxiiPassword)
                    else:
                        raise Exception(f'Unsupported TAXII version "{taxiiVersion}"')

                    # collect the collection URL(s) for the given collection name
                    collectionUrls = {}
                    for api_root in server.api_roots:
                        for collection in api_root.collections:
                            if collection.title.lower() == taxiiCollectionName.lower():
                                collectionUrls[collection.title] = {
                                    'id': collection.id,
                                    'url': collection.url,
                                }

                    # connect to and retrieve indicator STIX objects from the collection URL(s)
                    for title, info in collectionUrls.items():
                        collection = (
                            TaxiiCollection_v21(info['url'])
                            if taxiiVersion == '2.1'
                            else TaxiiCollection_v20(info['url'])
                        )
                        try:
                            for envelope in (
                                TaxiiAsPages_v21(
                                    collection.get_objects,
                                    per_request=stix_zeek_utils.TAXII_PAGE_SIZE,
                                    **stix_zeek_utils.TAXII_INDICATOR_FILTER,
                                )
                                if taxiiVersion == '2.1'
                                else TaxiiAsPages_v20(
                                    collection.get_objects,
                                    per_request=stix_zeek_utils.TAXII_PAGE_SIZE,
                                    **stix_zeek_utils.TAXII_INDICATOR_FILTER,
                                )
                            ):
                                try:
                                    parsed = StixParse(envelope, allow_custom=True)
                                    logging.debug(parsed.serialize(pretty=True))
                                except STIXError as ve:
                                    logging.error(f"{type(ve).__name__} for object of collection '{title}': {ve}")

                        except Exception as e:
                            logging.warning(f"{type(e).__name__} for object of collection '{title}': {e}")

        except Exception as e:
            logging.error(f"{type(e).__name__} for '{infile}': {e}")


###################################################################################################
if __name__ == '__main__':
    main()
