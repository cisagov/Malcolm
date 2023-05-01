#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import humanfriendly
import json
import re
import requests
import os
import sys
import urllib3

from collections import defaultdict
from requests.auth import HTTPBasicAuth

import malcolm_utils
from malcolm_utils import eprint, str2bool, ParseCurlFile

###################################################################################################
debug = False
scriptName = os.path.basename(__file__)
scriptPath = os.path.dirname(os.path.realpath(__file__))
urllib3.disable_warnings()


###################################################################################################
# main
def main():
    global debug

    parser = argparse.ArgumentParser(description=scriptName, add_help=True, usage='{} <arguments>'.format(scriptName))
    parser.add_argument(
        '-v',
        '--verbose',
        dest='debug',
        type=str2bool,
        nargs='?',
        const=True,
        default=str2bool(os.getenv('OPENSEARCH_INDEX_SIZE_PRUNE_DEBUG', default='False')),
        help="Verbose output",
    )
    parser.add_argument(
        '-i',
        '--index',
        dest='index',
        metavar='<str>',
        type=str,
        default=os.getenv('OPENSEARCH_INDEX_SIZE_PRUNE_INDEX', 'arkime_sessions3-*'),
        help='Index pattern',
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
        '--opensearch-ssl-verify',
        dest='opensearchSslVerify',
        type=str2bool,
        nargs='?',
        const=True,
        default=str2bool(os.getenv('OPENSEARCH_SSL_CERTIFICATE_VERIFICATION', default='False')),
        help="Verify SSL certificates for OpenSearch",
    )
    parser.add_argument(
        '--opensearch-local',
        dest='opensearchIsLocal',
        type=str2bool,
        nargs='?',
        const=True,
        default=str2bool(os.getenv('OPENSEARCH_LOCAL', default='True')),
        help="Malcolm is using its local OpenSearch instance",
    )
    parser.add_argument(
        '--node',
        dest='node',
        metavar='<str>',
        type=str,
        default=os.getenv('OPENSEARCH_INDEX_SIZE_PRUNE_NODE', ''),
        help='Node IDs or names',
    )
    parser.add_argument(
        '-l',
        '--limit',
        dest='limit',
        metavar='<str>',
        type=str,
        default=os.getenv('OPENSEARCH_INDEX_SIZE_PRUNE_LIMIT', '0'),
        help='Index pattern size limit (e.g., 100gb, 25%, ...)',
    )
    parser.add_argument(
        '-n',
        '--dry-run',
        dest='dryrun',
        type=str2bool,
        nargs='?',
        const=True,
        default=str2bool(os.getenv('OPENSEARCH_INDEX_SIZE_PRUNE_DRY_RUN', default='False')),
        help="Dry run",
    )
    parser.add_argument(
        '-p',
        '--primary',
        dest='primaryTotals',
        type=str2bool,
        nargs='?',
        const=True,
        default=str2bool(os.getenv('OPENSEARCH_INDEX_SIZE_PRUNE_PRIMARY', default='False')),
        help="Perform totals based on primaries (vs. totals)",
    )
    parser.add_argument(
        '--name-sort',
        dest='nameSorted',
        type=str2bool,
        nargs='?',
        const=True,
        default=str2bool(os.getenv('OPENSEARCH_INDEX_SIZE_PRUNE_NAME_SORT', default='False')),
        help="Sort indices by name (vs. creation date)",
    )
    try:
        parser.error = parser.exit
        args = parser.parse_args()
    except Exception:
        parser.print_help()
        exit(2)

    debug = args.debug
    if debug:
        eprint(os.path.join(scriptPath, scriptName))
        eprint("Arguments: {}".format(sys.argv[1:]))
        eprint("Arguments: {}".format(args))
    else:
        sys.tracebacklimit = 0

    # short-circuit without printing anything else
    if args.limit == '0':
        return

    args.opensearchIsLocal = args.opensearchIsLocal or (args.opensearchUrl == 'http://opensearch:9200')
    opensearchCreds = (
        ParseCurlFile(args.opensearchCurlRcFile) if (not args.opensearchIsLocal) else defaultdict(lambda: None)
    )
    if not args.opensearchUrl:
        if args.opensearchIsLocal:
            args.opensearchUrl = 'http://opensearch:9200'
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
    if debug:
        eprint(f'OpenSearch version is {opensearchVersion}')

    totalIndices = 0
    limitMegabytes = None
    limitPercent = None
    if args.limit is not None:
        if args.limit.isdigit():
            # assume megabytes
            limitMegabytes = int(args.limit)
        elif re.match(r'^\d+(\.\d+)?\s*[kmgtp]?b?$', args.limit, flags=re.IGNORECASE):
            # parse human-friendly entered size
            limitMegabytes = (
                humanfriendly.parse_size(f"{args.limit}{'' if args.limit.lower().endswith('b') else 'b'}") // 1000000
            )
        elif args.limit.endswith('%'):
            # percentage (must calculate megabytes based on /_cat/allocation below)
            limitPercent = int(args.limit[:-1])
            if (limitPercent <= 0) or (limitPercent >= 100):
                raise Exception(f'Invalid limit percentage {args.limit}')

    if limitPercent is not None:
        # get allocation statistics for node(s) to do percentage calculation
        esDiskUsageStats = []
        osInfoResponse = requests.get(
            f'{args.opensearchUrl}/_cat/allocation{f"/{args.node}" if args.node else ""}?format=json',
            auth=opensearchReqHttpAuth,
            verify=args.opensearchSslVerify,
        )
        osInfo = osInfoResponse.json()

        # normalize allocation statistics' sizes (eg., 100mb) into bytes
        for stat in osInfo:
            if ('node' in stat) and (stat['node'] != 'UNASSIGNED'):
                esDiskUsageStats.append(
                    {
                        key: humanfriendly.parse_size(value)
                        if re.match(r'^\d+(\.\d+)?\s*[kmgtp]?b$', value, flags=re.IGNORECASE)
                        else value
                        for (key, value) in stat.items()
                    }
                )

        if debug:
            eprint(json.dumps(esDiskUsageStats))

        # esDiskUsageStats should now look like:
        # [
        #     {
        #         "shards": "17",
        #         "disk.indices": 14500000,
        #         "disk.used": 148400000000,
        #         "disk.avail": 1600000000000,
        #         "disk.total": 1800000000000,
        #         "disk.percent": "7",
        #         "host": "172.22.2.3",
        #         "ip": "172.22.2.3",
        #         "node": "opensearch"
        #     },
        #     ...
        # ]
        if len(esDiskUsageStats) != 1:
            raise Exception('Unable to determine node, please specify --node if using a percentage limit')
        elif 'disk.total' not in esDiskUsageStats[0]:
            raise Exception(
                f'Unable to determine disk.total for {esDiskUsageStats[0]["node"] if "node" in esDiskUsageStats[0] else "node"}'
            )
        limitMegabytes = int(float(esDiskUsageStats[0]['disk.total']) * (float(limitPercent) / 100.0)) // 1000000

    if (limitMegabytes is None) or (limitMegabytes <= 0):
        raise Exception(f'Invalid (or unable to calculate) limit megabytes from {args.limit}')

    # now the limit has been calculated and stored (as megabytes) in limitMegabytes
    if debug:
        eprint(
            f'Index limit for {args.index} is {humanfriendly.format_size(humanfriendly.parse_size(f"{limitMegabytes}mb"))}'
        )

    # now determine the total size of the indices from the index pattern
    osInfoResponse = requests.get(
        f'{args.opensearchUrl}/{args.index}/_stats/store',
        auth=opensearchReqHttpAuth,
        verify=args.opensearchSslVerify,
    )
    osInfo = osInfoResponse.json()
    try:
        totalSizeInMegabytes = (
            osInfo['_all']['primaries' if args.primaryTotals else 'total']['store']['size_in_bytes'] // 1000000
        )
        totalIndices = len(osInfo["indices"])
    except Exception as e:
        raise Exception(f'Error getting {args.index} size_in_bytes: {e}')
    if debug:
        eprint(
            f'Total {args.index} megabytes: is {humanfriendly.format_size(humanfriendly.parse_size(f"{totalSizeInMegabytes}mb"))}'
        )

    if totalSizeInMegabytes > limitMegabytes:
        # the indices have outgrown their bounds, we need to delete the oldest

        if debug:
            eprint(
                f'{len(osInfo)} {args.index} indices occupy {humanfriendly.format_size(humanfriendly.parse_size(f"{totalSizeInMegabytes}mb"))} ({humanfriendly.format_size(humanfriendly.parse_size(f"{limitMegabytes}mb"))} allowed)'
            )

        # get list of indexes in index pattern and sort by creation date
        osInfoResponse = requests.get(
            f'{args.opensearchUrl}/_cat/indices/{args.index}',
            params={'format': 'json', 'h': 'i,id,status,health,rep,creation.date,pri.store.size,store.size'},
            auth=opensearchReqHttpAuth,
            verify=args.opensearchSslVerify,
        )
        osInfo = sorted(osInfoResponse.json(), key=lambda k: k['i' if args.nameSorted else 'creation.date'])

        # determine how many megabytes need to be deleted and which of the oldest indices will cover that
        indicesToDelete = []
        needsDeletedMb = totalSizeInMegabytes - limitMegabytes
        sizeKey = 'pri.store.size' if args.primaryTotals else 'store.size'
        for index in osInfo:
            indexSizeMb = humanfriendly.parse_size(index[sizeKey]) // 1000000
            if needsDeletedMb > 0:
                indicesToDelete.append(index)
                needsDeletedMb = needsDeletedMb - indexSizeMb
            else:
                break

        if len(indicesToDelete) > 0:
            # we've determined we can free up space from the index pattern
            print(
                f'{"Would delete" if args.dryrun else "Deleting"} {humanfriendly.format_size(humanfriendly.parse_size(f"{sum([humanfriendly.parse_size(index[sizeKey]) // 1000000 for index in indicesToDelete])}mb"))} in {len(indicesToDelete)} indices ({indicesToDelete[0]["i"]} to {indicesToDelete[-1]["i"]} ordered by {"name" if args.nameSorted else "creation date"})'
            )

            if not args.dryrun:
                # delete the indices to free up the space indicated
                for index in indicesToDelete:
                    esDeleteResponse = requests.delete(
                        f'{args.opensearchUrl}/{index["i"]}',
                        auth=opensearchReqHttpAuth,
                        verify=args.opensearchSslVerify,
                    )
                    print(
                        f'DELETE {index["i"]} ({humanfriendly.format_size(humanfriendly.parse_size(index[sizeKey]))}): {requests.status_codes._codes[esDeleteResponse.status_code][0]}'
                    )

        else:
            # no indexes to delete
            print(f'Nothing to do: could not determine list of {args.index} indices to delete')

    else:
        # we haven't hit the limit, nothing to do
        print(
            f'Nothing to do: {totalIndices} {args.index} indices occupy {humanfriendly.format_size(humanfriendly.parse_size(f"{totalSizeInMegabytes}mb"))} of {humanfriendly.format_size(humanfriendly.parse_size(f"{limitMegabytes}mb"))} allowed'
        )


if __name__ == '__main__':
    main()
