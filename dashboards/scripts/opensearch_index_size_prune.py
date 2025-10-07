#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import humanfriendly
import logging
import json
import re
import requests
import os
import sys
import urllib3

from collections import defaultdict
from requests.auth import HTTPBasicAuth

import malcolm_utils
from malcolm_utils import str2bool, ParseCurlFile, get_iterable, set_logging, get_verbosity_env_var_count

###################################################################################################
script_name = os.path.basename(__file__)
script_path = os.path.dirname(os.path.realpath(__file__))
urllib3.disable_warnings()


def parse_args():
    parser = argparse.ArgumentParser(description=script_name, add_help=True, usage='{} <arguments>'.format(script_name))
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
        type=str,
        nargs='*',
        default=[
            os.getenv('MALCOLM_NETWORK_INDEX_PATTERN', 'arkime_sessions3-*'),
            os.getenv('ARKIME_NETWORK_INDEX_PATTERN', 'arkime_sessions3-*'),
            os.getenv('MALCOLM_OTHER_INDEX_PATTERN', 'malcolm_beats_*'),
        ],
        help='Index pattern(s)',
    )
    parser.add_argument(
        '-o',
        '--opensearch',
        dest='opensearch_url',
        metavar='<protocol://host:port>',
        type=str,
        default=os.getenv('OPENSEARCH_URL', None),
        help='OpenSearch URL',
    )
    parser.add_argument(
        '-c',
        '--opensearch-curlrc',
        dest='opensearch_curl_rc_file',
        metavar='<filename>',
        type=str,
        default=os.getenv('OPENSEARCH_CREDS_CONFIG_FILE', '/var/local/curlrc/.opensearch.primary.curlrc'),
        help='cURL.rc formatted file containing OpenSearch connection parameters',
    )
    parser.add_argument(
        '--opensearch-ssl-verify',
        dest='opensearch_ssl_verify',
        type=str2bool,
        nargs='?',
        const=True,
        default=str2bool(os.getenv('OPENSEARCH_SSL_CERTIFICATE_VERIFICATION', default='False')),
        help="Verify SSL certificates for OpenSearch",
    )
    parser.add_argument(
        '--opensearch-mode',
        dest='opensearch_mode',
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
        dest='primary_totals',
        type=str2bool,
        nargs='?',
        const=True,
        default=str2bool(os.getenv('OPENSEARCH_INDEX_SIZE_PRUNE_PRIMARY', default='False')),
        help="Perform totals based on primaries (vs. totals)",
    )
    parser.add_argument(
        '--name-sort',
        dest='name_sorted',
        type=str2bool,
        nargs='?',
        const=True,
        default=str2bool(os.getenv('OPENSEARCH_INDEX_SIZE_PRUNE_NAME_SORT', default='False')),
        help="Sort indices by name (vs. creation date)",
    )
    try:
        args = parser.parse_args()
    except SystemExit as e:
        if e.code == 2:
            parser.print_help()
        sys.exit(e.code)
    return args


def make_session(verify_ssl=False, auth=None):
    session = requests.Session()
    session.auth = auth
    session.verify = verify_ssl
    session.headers.update({'Content-Type': 'application/json'})
    return session


def setup_environment(args):
    args.verbose = set_logging(os.getenv("LOGLEVEL", ""), args.verbose, set_traceback_limit=True)
    opensearch_creds = ParseCurlFile(args.opensearch_curl_rc_file)

    opensearch_is_local = (args.opensearch_mode == malcolm_utils.DatabaseMode.OpenSearchLocal) or (
        args.opensearch_url == 'https://opensearch:9200'
    )

    if not args.opensearch_url:
        if opensearch_is_local:
            args.opensearch_url = 'https://opensearch:9200'
        elif 'url' in opensearch_creds:
            args.opensearch_url = opensearch_creds['url']

    return args, make_session(
        args.opensearch_ssl_verify,
        HTTPBasicAuth(opensearch_creds['user'], opensearch_creds['password']) if opensearch_creds.get('user') else None,
    )


def get_version(args, session):
    response = session.get(args.opensearch_url)
    response.raise_for_status()
    version = response.json()["version"]["number"]
    logging.info(f"OpenSearch version is {version}")
    return version


def calculate_percent_limit(args, session, percent):
    """Fetch node allocation data and compute limit as percentage of disk.total."""
    url = f'{args.opensearch_url}/_cat/allocation{f"/{args.node}" if args.node else ""}?format=json'
    response = session.get(url)
    response.raise_for_status()
    allocation = response.json()

    stats = [
        {
            k: (humanfriendly.parse_size(v) if re.match(r'^\d+(\.\d+)?\s*[kmgtp]?b$', v, flags=re.IGNORECASE) else v)
            for k, v in entry.items()
        }
        for entry in allocation
        if entry.get('node') != 'UNASSIGNED'
    ]

    logging.debug(json.dumps(stats))
    if len(stats) != 1 or 'disk.total' not in stats[0]:
        raise RuntimeError("Unable to determine disk.total for node")

    total_bytes = float(stats[0]['disk.total'])
    return int(total_bytes * (percent / 100.0)) // 1_000_000


def parse_limit_megabytes(args, session):
    """Determine numeric limit in megabytes from args.limit (may be size, number, or percent)."""
    if not args.limit:
        raise ValueError("No limit provided")

    if args.limit.isdigit():
        return int(args.limit)

    if re.match(r'^\d+(\.\d+)?\s*[kmgtp]?b?$', args.limit, flags=re.IGNORECASE):
        return humanfriendly.parse_size(f"{args.limit}{'' if args.limit.lower().endswith('b') else 'b'}") // 1_000_000

    if args.limit.endswith('%'):
        percent = int(args.limit[:-1])
        if percent <= 0 or percent >= 100:
            raise ValueError(f"Invalid limit percentage {args.limit}")
        return calculate_percent_limit(args, session, percent)

    raise ValueError(f"Invalid limit format: {args.limit}")


def get_total_index_size(args, session):
    """Return (total_size_mb, total_index_count) for the given index patterns."""
    total_mb = 0
    total_indices = 0
    for idx in get_iterable(args.index):
        r = session.get(f'{args.opensearch_url}/{idx}/_stats/store')
        if not r.ok:
            logging.warning(f"Failed to fetch stats for {idx}: {r.status_code}")
            continue
        info = r.json()
        try:
            total_mb += (
                info['_all']['primaries' if args.primary_totals else 'total']['store']['size_in_bytes'] // 1_000_000
            )
            total_indices += len(info["indices"])
        except KeyError:
            continue
    return total_mb, total_indices


def get_indices_for_deletion(args, session, total_size_mb, limit_mb):
    """Return list of index info dicts to delete to reduce usage below limit."""
    os_info = []
    for idx in args.index:
        r = session.get(
            f'{args.opensearch_url}/_cat/indices/{idx}',
            params={'format': 'json', 'h': 'i,id,status,health,rep,creation.date,pri.store.size,store.size'},
        )
        r.raise_for_status()
        os_info.extend(r.json())

    os_info.sort(key=lambda k: k['i' if args.name_sorted else 'creation.date'])
    needs_deleted = total_size_mb - limit_mb
    to_delete = []
    size_key = 'pri.store.size' if args.primary_totals else 'store.size'

    for index in os_info:
        idx_size_mb = humanfriendly.parse_size(index[size_key]) // 1_000_000
        if needs_deleted <= 0:
            break
        to_delete.append(index)
        needs_deleted -= idx_size_mb

    return to_delete


def delete_indices(args, session, indices):
    """Delete the provided indices, or print what would be deleted in dry-run mode."""
    logging.debug(f'{"Would delete" if args.dryrun else "Deleting"}: {indices}')
    size_key = 'pri.store.size' if args.primary_totals else 'store.size'
    total_free_mb = sum(humanfriendly.parse_size(i[size_key]) // 1_000_000 for i in indices)
    print(
        f'{"Would delete" if args.dryrun else "Deleting"} '
        f'{humanfriendly.format_size(humanfriendly.parse_size(f"{total_free_mb}mb"))} '
        f'in {len(indices)} indices ({indices[0]["i"]} to {indices[-1]["i"]} '
        f'ordered by {"name" if args.name_sorted else "creation date"})'
    )

    if not args.dryrun:
        for i in indices:
            resp = session.delete(f'{args.opensearch_url}/{i["i"]}')
            status = requests.status_codes._codes.get(resp.status_code, ['unknown'])[0]
            print(f'DELETE {i["i"]} ({humanfriendly.format_size(humanfriendly.parse_size(i[size_key]))}): {status}')


def main():
    args = parse_args()
    # short-circuit without printing anything else
    if args.limit == '0' or not args.index:
        return

    args, session = setup_environment(args)

    logging.debug(f"Running {script_name} from {script_path}")
    logging.debug(f"Arguments: {sys.argv[1:]}")
    logging.debug(f"Arguments: {args}")

    get_version(args, session)
    args.index = list(set(get_iterable(args.index)))
    logging.debug(f"Indices: {args.index}")

    limit_mb = parse_limit_megabytes(args, session)
    if limit_mb <= 0:
        raise ValueError(f"Invalid or zero limit: {args.limit}")
    logging.info(
        f'Index limit for {args.index} is {humanfriendly.format_size(humanfriendly.parse_size(f"{limit_mb}mb"))}'
    )

    total_mb, total_indices = get_total_index_size(args, session)
    logging.info(
        f'Total {args.index} size: {humanfriendly.format_size(humanfriendly.parse_size(f"{total_mb}mb"))} ({total_indices} indices)'
    )

    if total_mb <= limit_mb:
        print(
            f'Nothing to do: {total_indices} {args.index} indices occupy '
            f'{humanfriendly.format_size(humanfriendly.parse_size(f"{total_mb}mb"))} of '
            f'{humanfriendly.format_size(humanfriendly.parse_size(f"{limit_mb}mb"))} allowed'
        )
        return

    to_delete = get_indices_for_deletion(args, session, total_mb, limit_mb)
    if to_delete:
        delete_indices(args, session, to_delete)
    else:
        print(f'Nothing to do: could not determine list of {args.index} indices to delete')


if __name__ == '__main__':
    try:
        main()
    except Exception as e:
        logging.exception(f"Unexpected error: {e}")
        sys.exit(1)
