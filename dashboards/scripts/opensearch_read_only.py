#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2025 Battelle Energy Alliance, LLC.  All rights reserved.

import argparse
import json
import requests
import logging
import os
import sys
import urllib3

from collections import defaultdict
from requests.auth import HTTPBasicAuth

import malcolm_utils
from malcolm_utils import str2bool, ParseCurlFile, set_logging, get_verbosity_env_var_count

###################################################################################################
scriptName = os.path.basename(__file__)
scriptPath = os.path.dirname(os.path.realpath(__file__))
urllib3.disable_warnings()


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
        '--index',
        dest='index',
        metavar='<str>',
        type=str,
        default=os.getenv('OPENSEARCH_INDEX_READ_ONLY_INDEX', '*'),
        help='Index pattern (single, wildcard or _cluster for entire cluster)',
    )
    parser.add_argument(
        '-o',
        '--opensearch',
        dest='opensearchUrl',
        metavar='<protocol://host:port>',
        type=str,
        default=os.getenv('OPENSEARCH_URL', None),
        help='OpenSearch URL',
    )
    parser.add_argument(
        '-c',
        '--opensearch-curlrc',
        dest='opensearchCurlRcFile',
        metavar='<filename>',
        type=str,
        default=os.getenv('OPENSEARCH_CREDS_CONFIG_FILE', '/var/local/curlrc/.opensearch.primary.curlrc'),
        help='cURL.rc formatted file containing OpenSearch connection parameters',
    )
    parser.add_argument(
        '-s',
        '--opensearch-ssl-verify',
        dest='opensearchSslVerify',
        type=str2bool,
        nargs='?',
        const=True,
        default=str2bool(os.getenv('OPENSEARCH_SSL_CERTIFICATE_VERIFICATION', default='False')),
        help="Verify SSL certificates for OpenSearch",
    )
    parser.add_argument(
        '--opensearch-mode',
        dest='opensearchMode',
        help="Malcolm data store mode ('opensearch-local', 'opensearch-remote', 'elasticsearch-remote')",
        type=malcolm_utils.DatabaseModeStrToEnum,
        metavar='<STR>',
        default=malcolm_utils.DatabaseModeStrToEnum(
            os.getenv(
                'OPENSEARCH_PRIMARY',
                default=malcolm_utils.DatabaseModeEnumToStr(malcolm_utils.DatabaseMode.OpenSearchLocal),
            )
        ),
        required=False,
    )
    parser.add_argument(
        '-r',
        '--read-only',
        dest='readOnly',
        type=str2bool,
        nargs='?',
        const=True,
        default=str2bool(os.getenv('OPENSEARCH_INDEX_READ_ONLY', default='True')),
        help="Set read-only (true) or read-write (false)",
    )
    parser.add_argument(
        '-d',
        '--allow-delete',
        dest='allowDelete',
        type=str2bool,
        nargs='?',
        const=True,
        default=str2bool(os.getenv('OPENSEARCH_INDEX_READ_ONLY_ALLOW_DELETE', default='False')),
        help="Set read-only, but allow delete",
    )
    parser.add_argument(
        '-n',
        '--dry-run',
        dest='dryRun',
        type=str2bool,
        nargs='?',
        const=True,
        default=str2bool(os.getenv('OPENSEARCH_INDEX_READ_ONLY_DRY_RUN', default='False')),
        help="Dry-run, do not actually PUT request",
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

    opensearchIsLocal = (args.opensearchMode == malcolm_utils.DatabaseMode.OpenSearchLocal) or (
        args.opensearchUrl == 'https://opensearch:9200'
    )
    opensearchCreds = ParseCurlFile(args.opensearchCurlRcFile)
    if not args.opensearchUrl:
        if opensearchIsLocal:
            args.opensearchUrl = 'https://opensearch:9200'
        elif 'url' in opensearchCreds:
            args.opensearchUrl = opensearchCreds['url']
    opensearchReqHttpAuth = (
        HTTPBasicAuth(opensearchCreds['user'], opensearchCreds['password'])
        if opensearchCreds['user'] is not None
        else None
    )

    osInfoResponse = requests.get(
        args.opensearchUrl,
        auth=opensearchReqHttpAuth,
        verify=args.opensearchSslVerify,
    )
    osInfo = osInfoResponse.json()
    opensearchVersion = osInfo['version']['number']
    logging.info(f'OpenSearch version is {opensearchVersion}')

    # for the whole cluster:
    # PUT _cluster/settings
    # {
    #   "transient": {
    #     "cluster.blocks.read_only":true
    #   }
    # }
    #
    # for an index:
    # PUT foobar/settings
    # {
    #   "index": {
    #     "blocks.read_only":true
    #   }
    # }

    settingsUrl = f"{args.opensearchUrl}/{args.index}/{'' if args.index == '_cluster' else '_'}settings"
    settingsInfo = {
        "transient" if args.index == "_cluster" else "index": {
            f"{'cluster.' if args.index == '_cluster' else ''}blocks.read_only{'_allow_delete' if args.allowDelete else ''}": (
                True if args.readOnly else None
            )
        }
    }
    logging.debug(f'PUT "{settingsUrl}"\n    {json.dumps(settingsInfo)}')

    if not args.dryRun:
        # make the PUT request to change the index/cluster setting and raise an exception if it fails
        putResponse = requests.put(
            settingsUrl,
            auth=opensearchReqHttpAuth,
            headers={'Content-Type': 'application/json'},
            data=json.dumps(settingsInfo),
            verify=args.opensearchSslVerify,
        )
        putResponse.raise_for_status()
        logging.debug(putResponse.json())

    # request settings to verify change(s)
    checkResponse = requests.get(
        settingsUrl,
        auth=opensearchReqHttpAuth,
        verify=args.opensearchSslVerify,
    )
    if args.index == '_cluster':
        logging.info(json.dumps(checkResponse.json()))
    else:
        for index, indexInfo in sorted(checkResponse.json().items()):
            try:
                logging.info(f"{index} - {json.dumps(indexInfo['settings']['index']['blocks'])}")
            except KeyError:
                # not found, assume that means "not read-only"
                logging.warning(f"{index} - {json.dumps({'read_only': None})}")


if __name__ == '__main__':
    main()
