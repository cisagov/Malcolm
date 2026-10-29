#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Aggregate GitHub release downloads and GHCR package pull counts."""

import argparse
from collections import defaultdict
from datetime import datetime
import json
import logging
import os
import re
import sys

from bs4 import BeautifulSoup
from dateparser import parse as ParseDate
import github3 as github
import mmguero
import requests
from tzlocal import get_localzone

script_name = os.path.basename(__file__)
script_path = os.path.dirname(os.path.realpath(__file__))
GITHUB_API_REQUESTS_PER_PAGE = 30


def build_parser():
    parser = argparse.ArgumentParser(
        description='\n'.join(
            [
                'Display download statistics from GitHub repositories',
                '',
                '* Access to the GitHub API is done using your personal access token (PAT).'
                'See https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens',
                'for information about PATs.',
                '',
            ]
        ),
        formatter_class=argparse.RawTextHelpFormatter,
        add_help=True,
        usage=f'{script_name} <arguments>',
    )
    parser.add_argument(
        '--verbose',
        '-v',
        action='count',
        default=mmguero.get_verbosity_env_var_count("VERBOSITY"),
        help='Increase verbosity (e.g., -v, -vv, etc.)',
    )
    parser.add_argument(
        '-t',
        '--token',
        dest='githubToken',
        help='GitHub API token',
        metavar='<str>',
        type=str,
        default=os.getenv('GITHUB_TOKEN', os.getenv('GITHUB_OAUTH_TOKEN', '')),
    )
    parser.add_argument(
        '--token-file',
        dest='githubTokenFile',
        help='GitHub API token (read from filename)',
        metavar='<str>',
        type=str,
        default=os.getenv('GITHUB_TOKEN_FILE', os.getenv('GITHUB_OAUTH_TOKEN_FILE', '')),
    )
    parser.add_argument(
        '-r',
        '--repo',
        dest='repos',
        nargs='*',
        type=str,
        default=[],
        help="One or more GitHub repository/repositories (e.g., org/repo)",
    )
    parser.add_argument(
        '--date-from',
        dest='dateFromStr',
        metavar='<str>',
        type=str,
        default='Jan 1 1970',
        help="Human readable date expression for beginning of search time frame (default: Jan 1 1970)",
    )
    parser.add_argument(
        '--date-to',
        dest='dateToStr',
        metavar='<str>',
        type=str,
        default='now',
        help="Human readable date expression for ending of search time frame (default: now)",
    )
    parser.add_argument(
        '--release',
        dest='releaseRegexes',
        nargs='*',
        type=str,
        default=[],
        help="List of regular expressions against which to match releases (e.g., ^v24\\.10)",
    )
    parser.add_argument(
        '-a',
        '--asset',
        dest='assetRegexes',
        nargs='*',
        type=str,
        default=[],
        help="List of regular expressions against which to match release assets (e.g., ^\\w+.+\\.iso\\.01$, ^foobar_.*\\.tar\\.gz$",
    )
    parser.add_argument(
        '-i',
        '--image',
        dest='imageRegexes',
        nargs='*',
        type=str,
        default=[],
        help="List of regular expressions against which to match container images (e.g., ^foobar/barbaz$)",
    )
    parser.add_argument(
        '--image-tag',
        dest='imageTagRegexes',
        nargs='*',
        type=str,
        default=[],
        help="List of regular expressions against which to match container image tags (e.g., ^24\\.10)",
    )
    return parser


def compile_patterns(expressions):
    """Compile user-supplied filters, retaining their original labels."""
    return {text: re.compile(text) for text in expressions}


def matches_any(value, patterns):
    """Match the start of a value, or accept everything if filters are empty."""
    return isinstance(value, str) and (not patterns or any(regex.match(value) for regex in patterns.values()))


def parse_timestamp(value, local_zone):
    """Convert a date string or datetime into an offset-aware datetime."""
    parsed = ParseDate(value) if isinstance(value, str) else value
    if not isinstance(parsed, datetime):
        return None
    return parsed.replace(tzinfo=local_zone) if parsed.tzinfo is None else parsed


def parse_date_range(date_from, date_to):
    """Resolve the requested inclusive time window before accessing the API."""
    zone = get_localzone()
    start = parse_timestamp(date_from, zone)
    end = parse_timestamp(date_to, zone)
    if start is None or end is None:
        raise ValueError('Invalid date range: both --date-from and --date-to must be valid dates')
    if start > end:
        raise ValueError('--date-from must be earlier than or equal to --date-to')
    return start, end


def inside_range(value, date_from, date_to):
    date_value = parse_timestamp(value, date_from.tzinfo)
    return date_value is not None and date_from <= date_value <= date_to


def collect_release_downloads(repo, owner, date_from, date_to, asset_patterns, release_patterns, counts):
    """Count matching assets in matching releases for one repository."""
    if not asset_patterns or repo is None:
        return
    for release in repo.releases():
        if not inside_range(release.published_at, date_from, date_to):
            continue
        if not matches_any(release.tag_name, release_patterns):
            continue
        logging.debug('%s %s at %s', repo.full_name, release.tag_name, release.published_at)
        for asset in release.assets():
            for label, pattern in asset_patterns.items():
                if pattern.match(asset.name):
                    key = f'{owner}/{label}'
                    counts[key] = counts.get(key, 0) + asset.download_count


def iter_api_pages(session, url, extra_params=None):
    """Yield all items from a paginated GitHub REST list, stopping on failure."""
    page = 0
    while True:
        page += 1
        params = {'page': page, 'per_page': GITHUB_API_REQUESTS_PER_PAGE}
        if extra_params:
            params.update(extra_params)
        try:
            response = session.get(url, params=params, allow_redirects=True)
            response.raise_for_status()
            records = mmguero.load_str_if_json(response.content)
            if not isinstance(records, list):
                return
        except Exception as error:
            logging.error('Listing GitHub API results for %s: %s', url, error)
            return
        yield from records
        if len(records) < GITHUB_API_REQUESTS_PER_PAGE:
            return


def package_versions(session, package, tag_patterns, date_from, date_to):
    """Select matching GHCR package versions by creation time and tag."""
    owner = mmguero.deep_get(package, ['owner', 'login'])
    if not owner:
        return
    image_name = mmguero.aggressive_url_encode(package['name'])
    url = f'https://api.github.com/orgs/{owner}/packages/container/{image_name}/versions'
    for version in iter_api_pages(session, url):
        if not inside_range(version.get('created_at'), date_from, date_to):
            continue
        tags = mmguero.deep_get(version, ['metadata', 'container', 'tags']) or []
        if any(matches_any(tag, tag_patterns) for tag in tags) or not tag_patterns:
            yield version


def version_download_count(session, version):
    """Read the public GitHub package page's total-downloads figure."""
    if not version.get('html_url'):
        return 0
    try:
        response = session.get(version['html_url'], allow_redirects=True)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')
        label = soup.find('span', string='Total downloads')
        count = label.find_next('span') if label else None
        return int(count.get_text().replace(',', '')) if count else 0
    except (AttributeError, ValueError, requests.RequestException) as error:
        logging.error('Parsing package download count for %s: %s', version['html_url'], error)
        return 0


def collect_package_pull_counts(package, api_session, html_session, tag_patterns, date_from, date_to):
    """Return keyed pull counts for one matching GHCR package."""
    pulls = {}
    owner = mmguero.deep_get(package, ['owner', 'login'])
    for version in package_versions(api_session, package, tag_patterns, date_from, date_to):
        pull_count = version_download_count(html_session, version)
        if not pull_count:
            continue
        tags = mmguero.deep_get(version, ['metadata', 'container', 'tags']) or []
        if len(tags) > 1:
            suffix = f':({"|".join(tags)})'
        elif tags:
            suffix = f':{tags[0]}'
        else:
            suffix = '@' + version['name']
        pulls[f"{owner}/{package['name']}{suffix}"] = pull_count
    return pulls


def collect_image_downloads(orgs, api_session, html_session, image_patterns, tag_patterns, date_from, date_to):
    """Fetch qualifying GHCR images once for each distinct organisation."""
    pulls = {}
    if not image_patterns:
        return pulls
    for org in dict.fromkeys(orgs):
        url = f'https://api.github.com/orgs/{org}/packages'
        for package in iter_api_pages(api_session, url, {'package_type': 'container'}):
            if not isinstance(package, dict) or not matches_any(package.get('name'), image_patterns):
                continue
            pulls.update(collect_package_pull_counts(
                package, api_session, html_session, tag_patterns, date_from, date_to
            ))
    return pulls


def combine_statistics(asset_downloads, image_pulls):
    """Build JSON-friendly counters with a total for each populated section."""
    stats = {}
    if asset_downloads:
        stats['release_assets'] = {**asset_downloads, 'total': sum(asset_downloads.values())}
    if image_pulls:
        stats['image_pulls'] = {**image_pulls, 'total': sum(image_pulls.values())}
    return stats


def main():
    parser = build_parser()
    try:
        args = parser.parse_args()
    except SystemExit as error:
        if error.code == 2:
            parser.print_help()
        raise

    if not args.githubToken and args.githubTokenFile and os.path.isfile(args.githubTokenFile):
        with open(args.githubTokenFile, encoding='utf-8') as token_file:
            args.githubToken = token_file.readline().strip()

    args.verbose = mmguero.set_logging(os.getenv('LOGLEVEL', ''), args.verbose, set_traceback_limit=True)
    logging.info('%s', os.path.join(script_path, script_name))
    # Never log sys.argv or the entire Namespace: both can contain the PAT.
    logging.info('Repositories: %s', args.repos)

    date_from, date_to = parse_date_range(args.dateFromStr, args.dateToStr)
    logging.info('Searching %s to %s', date_from, date_to)
    asset_patterns = compile_patterns(args.assetRegexes)
    release_patterns = compile_patterns(args.releaseRegexes)
    image_patterns = compile_patterns(args.imageRegexes)
    tag_patterns = compile_patterns(args.imageTagRegexes)

    gh = github.login(token=args.githubToken)
    api_session = requests.Session()
    api_session.headers.update({
        'Accept': 'application/vnd.github.v3+json',
        'Authorization': f'token {args.githubToken}',
        'X-GitHub-Api-Version': '2022-11-28',
    })
    html_session = requests.Session()

    asset_downloads = defaultdict(int)
    orgs = []
    for repo_spec in args.repos:
        parts = repo_spec.split('/')
        if len(parts) != 2 or not all(parts):
            logging.warning('Skipping invalid repository: %s', repo_spec)
            continue
        owner, name = parts
        orgs.append(owner)
        if asset_patterns:
            repo = gh.repository(owner, name)
            collect_release_downloads(repo, owner, date_from, date_to, asset_patterns, release_patterns, asset_downloads)

    image_pulls = collect_image_downloads(orgs, api_session, html_session, image_patterns, tag_patterns, date_from, date_to)
    print(json.dumps(combine_statistics(asset_downloads, image_pulls)))
    return 0


if __name__ == '__main__':
    sys.exit(main())
