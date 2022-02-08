#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2022 Battelle Energy Alliance, LLC.  All rights reserved.

import argparse
import dateparser
import json
import logging
import os
import pytz
import requests
import sys

from bs4 import BeautifulSoup
from contextlib import nullcontext
from datetime import datetime
from urllib.parse import urljoin
from taxii2client.v20 import as_pages as TaxiiAsPages_v20
from taxii2client.v20 import Collection as TaxiiCollection_v20
from taxii2client.v20 import Server as TaxiiServer_v20
from taxii2client.v21 import as_pages as TaxiiAsPages_v21
from taxii2client.v21 import Collection as TaxiiCollection_v21
from taxii2client.v21 import Server as TaxiiServer_v21

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
                ' - Malcolm documentation: https://github.com/idaholab/Malcolm#zeek-intelligence-framework',
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
        help="JSON file(s), TAXII 2.x URL(s) or MISP URL(s), e.g.\n\ttaxii|2.0|http://example.com/discovery|Collection Name|user|password\n\tmisp|TODO:2.0|http://example.com/discovery|Collection Name|user|password",
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
    since = dateparser.parse(args.since).astimezone(pytz.utc) if args.since is not None else None
    defaultNow = datetime.now().astimezone(pytz.utc)

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

        # process each given feed input
        for inarg in args.input:
            try:
                with open(inarg) if ((inarg is not None) and os.path.isfile(inarg)) else nullcontext() as infile:

                    if infile:
                        ##################################################################################
                        # JSON FILE

                        # TODO: detect MISP vs. STIX for input file
                        zeekPrinter.ProcessSTIX(infile, source=os.path.splitext(os.path.basename(inarg))[0])

                    elif inarg.lower().startswith('misp'):
                        ##################################################################################
                        # MISP URL

                        # this is a MISP URL, connect and retrieve STIX indicators from it
                        # misp|misp_url|auth_key

                        mispConnInfo = [
                            zeek_threat_feed_utils.base64_decode_if_prefixed(x) for x in inarg.split('|')[1::]
                        ]
                        mispUrl, mispAuthKey = (
                            None,
                            None,
                        )
                        mispUrl = mispConnInfo[0]
                        if len(mispConnInfo) >= 2:
                            mispAuthKey = mispConnInfo[1]

                        with requests.Session() as mispSession:

                            if mispAuthKey is not None:
                                mispSession.headers.update({'Authorization': mispAuthKey})

                            # download the URL and parse as JSON to figure out what it is. it could be:
                            # - a manifest JSON (https://www.circl.lu/doc/misp/feed-osint/manifest.json)
                            # - a directory listing *containing* a manifest.json (https://www.circl.lu/doc/misp/feed-osint/)
                            # - a directory listing of misc. JSON files without a manifest.json
                            mispResponse = mispSession.get(mispUrl)
                            mispResponse.raise_for_status()
                            if mispJson := zeek_threat_feed_utils.LoadStrIfJson(mispResponse.content):
                                # the contents are JSON. determine if this is a manifest or a single event

                                if (len(mispJson.keys()) == 1) and ('Event' in mispJson):
                                    # TODO: is this always the case? anything other than "Event", or multiple objects?
                                    # this is a MISP event, process it
                                    zeekPrinter.ProcessMISP(
                                        mispJson,
                                        url=mispUrl,
                                    )

                                else:
                                    # this is a manifest, loop over, retrieve and process the MISP events it references
                                    for uri in mispJson:
                                        try:
                                            newUrl = urljoin(mispUrl, f'{uri}.json')
                                            eventTime = (
                                                datetime.utcfromtimestamp(int(mispJson[uri]['timestamp'])).astimezone(
                                                    pytz.utc
                                                )
                                                if 'timestamp' in mispJson[uri]
                                                else defaultNow
                                            )
                                            if (since is None) or (eventTime >= since):
                                                mispObjectReponse = mispSession.get(newUrl)
                                                mispObjectReponse.raise_for_status()
                                                zeekPrinter.ProcessMISP(
                                                    mispObjectReponse.json(),
                                                    url=newUrl,
                                                )
                                        except Exception as e:
                                            logging.warning(f"{type(e).__name__} for MISP object at '{newUrl}': {e}")

                            else:
                                # the contents are NOT JSON, it's probably an HTML-formatted directory listing

                                # retrieve the links listed (non-recursive, all .json files in this directory)
                                paths = zeek_threat_feed_utils.get_url_paths_from_response(
                                    mispResponse.text, parent_url=mispUrl, ext='.json'
                                )

                                # see if manifest.json exists in this directory
                                manifestPaths = [x for x in paths if x.endswith('/manifest.json')]
                                if len(manifestPaths) > 0:
                                    # the manifest.json exists!
                                    # retrieve it, then loop over it and retrieve and process the MISP events it references
                                    for url in manifestPaths:
                                        try:
                                            mispManifestResponse = mispSession.get(url)
                                            mispManifestResponse.raise_for_status()
                                            mispManifest = mispManifestResponse.json()
                                            for uri in mispManifest:
                                                try:
                                                    eventTime = (
                                                        datetime.utcfromtimestamp(
                                                            int(mispManifest[uri]['timestamp'])
                                                        ).astimezone(pytz.utc)
                                                        if 'timestamp' in mispManifest[uri]
                                                        else defaultNow
                                                    )
                                                    if (since is None) or (eventTime >= since):
                                                        newUrl = f'{mispUrl.strip("/")}/{uri}.json'
                                                        mispObjectReponse = mispSession.get(newUrl)
                                                        mispObjectReponse.raise_for_status()
                                                        zeekPrinter.ProcessMISP(
                                                            mispObjectReponse.json(),
                                                            url=newUrl,
                                                        )
                                                except Exception as e:
                                                    logging.warning(
                                                        f"{type(e).__name__} for MISP object at '{mispUrl}/{uri}.json': {e}"
                                                    )
                                        except Exception as e:
                                            logging.warning(f"{type(e).__name__} for manifest at '{url}': {e}")

                                else:
                                    # the manifest.json does not exist!
                                    # just loop over, retrieve and process the .json files in this directory
                                    for url in paths:
                                        try:
                                            mispObjectReponse = mispSession.get(url)
                                            mispObjectReponse.raise_for_status()
                                            zeekPrinter.ProcessMISP(
                                                mispObjectReponse.json(),
                                                url=url,
                                            )
                                        except Exception as e:
                                            logging.warning(f"{type(e).__name__} for MISP object at '{url}': {e}")

                    elif inarg.lower().startswith('taxii'):
                        ##################################################################################
                        # TAXI (STIX) URL

                        # this is a TAXII URL, connect and retrieve STIX indicators from it
                        # taxii|2.0|discovery_url|collection_name|username|password
                        #
                        # examples of URLs I've used successfully for testing:
                        # - "taxii|2.0|https://cti-taxii.mitre.org/taxii/|Enterprise ATT&CK"
                        # - "taxii|2.0|https://limo.anomali.com/api/v1/taxii2/taxii/|CyberCrime|guest|guest"
                        #
                        # collection_name can be specified as * to retrieve all collections (careful!)

                        taxiiConnInfo = [
                            zeek_threat_feed_utils.base64_decode_if_prefixed(x) for x in inarg.split('|')[1::]
                        ]
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
                                if (taxiiCollectionName == '*') or (
                                    collection.title.lower() == taxiiCollectionName.lower()
                                ):
                                    collectionUrls[collection.title] = {
                                        'id': collection.id,
                                        'url': collection.url,
                                    }

                        # connect to and retrieve indicator STIX objects from the collection URL(s)
                        for title, info in collectionUrls.items():
                            collection = (
                                TaxiiCollection_v21(info['url'], user=taxiiUsername, password=taxiiPassword)
                                if taxiiVersion == '2.1'
                                else TaxiiCollection_v20(info['url'], user=taxiiUsername, password=taxiiPassword)
                            )
                            try:

                                # loop over paginated results
                                for envelope in (
                                    TaxiiAsPages_v21(
                                        collection.get_objects,
                                        per_request=zeek_threat_feed_utils.TAXII_PAGE_SIZE,
                                        **zeek_threat_feed_utils.TAXII_INDICATOR_FILTER,
                                    )
                                    if taxiiVersion == '2.1'
                                    else TaxiiAsPages_v20(
                                        collection.get_objects,
                                        per_request=zeek_threat_feed_utils.TAXII_PAGE_SIZE,
                                        **zeek_threat_feed_utils.TAXII_INDICATOR_FILTER,
                                    )
                                ):
                                    zeekPrinter.ProcessSTIX(
                                        envelope, source=':'.join([x for x in [server.title, title] if x is not None])
                                    )

                            except Exception as e:
                                logging.warning(f"{type(e).__name__} for object of collection '{title}': {e}")

            except Exception as e:
                logging.warning(f"{type(e).__name__} for '{inarg}': {e}")


###################################################################################################
if __name__ == '__main__':
    main()
