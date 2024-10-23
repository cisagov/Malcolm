#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import github3 as github
import json
import logging
import mmguero
import os
import re
import requests
import sys

from collections import defaultdict
from dateparser import parse as ParseDate
from datetime import datetime
from tzlocal import get_localzone
from bs4 import BeautifulSoup

###################################################################################################
script_name = os.path.basename(__file__)
script_path = os.path.dirname(os.path.realpath(__file__))

GITHUB_API_REQUESTS_PER_PAGE = 30


###################################################################################################
# main
def main():
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
        add_help=False,
        usage=f'{script_name} <arguments>',
    )
    parser.add_argument(
        '--verbose',
        '-v',
        action='count',
        default=1,
        help='Increase verbosity (e.g., -v, -vv, etc.)',
    )
    parser.add_argument(
        '-t',
        '--token',
        dest='githubToken',
        help=f'GitHub API token',
        metavar='<str>',
        type=str,
        default=os.getenv('GITHUB_TOKEN', os.getenv('GITHUB_OAUTH_TOKEN', '')),
    )
    parser.add_argument(
        '--token-file',
        dest='githubTokenFile',
        help=f'GitHub API token (read from filename)',
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
    try:
        parser.error = parser.exit
        args = parser.parse_args()
    except SystemExit:
        parser.print_help()
        sys.exit(2)

    # if the GitHub token was not obtained from environment variable or as an argument,
    #   see if it can be loaded from a file
    if (not args.githubToken) and os.path.isfile(args.githubTokenFile):
        with open(args.githubTokenFile) as f:
            args.githubToken = f.readline().strip()

    args.verbose = logging.CRITICAL - (10 * args.verbose) if args.verbose > 0 else 0
    logging.basicConfig(
        level=args.verbose, format='%(asctime)s %(levelname)s: %(message)s', datefmt='%Y-%m-%d %H:%M:%S'
    )
    logging.info(os.path.join(script_path, script_name))
    logging.info("Arguments: {}".format(sys.argv[1:]))
    logging.info("Arguments: {}".format(args))
    if args.verbose > logging.DEBUG:
        sys.tracebacklimit = 0

    # resolve the start and end times for searching
    dateFrom = ParseDate(args.dateFromStr)
    dateTo = ParseDate(args.dateToStr)
    localZone = get_localzone()
    if dateFrom.tzinfo is None:
        dateFrom = dateFrom.replace(tzinfo=localZone)
    if dateTo.tzinfo is None:
        dateTo = dateTo.replace(tzinfo=localZone)
    logging.info(f'Searching {dateFrom} to {dateTo}')

    # objects to hold our final results
    finalResults = {}
    imagePulls = defaultdict(lambda: 0)
    assetDownloads = defaultdict(lambda: 0)
    packages = []

    # compile the regular expressions used for matching asset download counts
    assetRegexes = {}
    for reStr in args.assetRegexes:
        assetRegexes[reStr] = re.compile(reStr)
    releaseRegexes = {}
    for reStr in args.releaseRegexes:
        releaseRegexes[reStr] = re.compile(reStr)
    imageRegexes = {}
    for reStr in args.imageRegexes:
        imageRegexes[reStr] = re.compile(reStr)
    imageTagRegexes = {}
    for reStr in args.imageTagRegexes:
        imageTagRegexes[reStr] = re.compile(reStr)

    # log in to GitHub given the token provided
    gh = github.login(token=args.githubToken)
    logging.info(gh)

    # unfortunately not all of the APIs we need are covered by github3 ಠ_ಥ
    #   so we have to do some manual API pulling with requests, and even (gasp)
    #   some web scraping with bs4
    ghSession = requests.Session()
    ghSession.headers = {
        'Accept': 'application/vnd.github.v3+json',
        'Authorization': f'token {args.githubToken}',
        'X-GitHub-Api-Version': '2022-11-28',
    }
    ghHTMLSession = requests.Session()

    # loop over the repos provided
    orgsPolledForImages = set()
    for repoSpec in args.repos:
        repoParts = repoSpec.split('/')
        if len(repoParts) == 2:
            if repo := gh.repository(repoParts[0], repoParts[1]):

                # loop over the releases for this repo, examining those in the search time frame
                if assetRegexes:
                    for release in repo.releases():
                        if dateFrom <= release.published_at <= dateTo and (
                            (
                                (not releaseRegexes)
                                or any([v.match(release.tag_name) for k, v in releaseRegexes.items()])
                            )
                        ):
                            logging.debug(f'{repo.full_name} {release.tag_name} at {release.published_at}')
                            # aggregate download counts for assets matching the regular expressions provided
                            for asset in release.assets():
                                for reStr, reObj in assetRegexes.items():
                                    if reObj.match(asset.name):
                                        assetDownloads[f"{repoParts[0]}/{reStr}"] = (
                                            assetDownloads[f"{repoParts[0]}/{reStr}"] + asset.download_count
                                        )

            if imageRegexes and (repoParts[0] not in orgsPolledForImages):
                # make requests to list container images in the ghcr.io repository for this organization
                page = 0
                orgsPolledForImages.add(repoParts[0])
                while True:
                    try:
                        page = page + 1
                        params = {
                            'package_type': 'container',
                            'page': page,
                            'per_page': GITHUB_API_REQUESTS_PER_PAGE,
                        }
                        pkgsResponse = ghSession.get(
                            f'https://api.github.com/orgs/{repoParts[0]}/packages',
                            params=params,
                            allow_redirects=True,
                        )
                        pkgsResponse.raise_for_status()
                        if (packagesJson := mmguero.LoadStrIfJson(pkgsResponse.content)) and isinstance(
                            packagesJson, list
                        ):
                            packages.extend(
                                [x for x in packagesJson if any([v.match(x['name']) for k, v in imageRegexes.items()])]
                            )
                            if len(packagesJson) < GITHUB_API_REQUESTS_PER_PAGE:
                                break
                        else:
                            break
                    except Exception as e:
                        logging.error(f"Listing packages: {e}")
                        break

    # for the packages we accumulated earlier, put together a list of matching image tags
    for packageInfo in packages:
        versions = []
        page = 0
        while True:
            try:
                page = page + 1
                params = {
                    'page': page,
                    'per_page': GITHUB_API_REQUESTS_PER_PAGE,
                }
                versionsResponse = ghSession.get(
                    f"https://api.github.com/orgs/{mmguero.DeepGet(packageInfo, ['owner', 'login'])}/packages/container/{mmguero.AggressiveUrlEncode(packageInfo['name'])}/versions",
                    params=params,
                    allow_redirects=True,
                )
                versionsResponse.raise_for_status()
                if (versionsJson := mmguero.LoadStrIfJson(versionsResponse.content)) and isinstance(versionsJson, list):
                    # only consider versions where the tag creation date is in our search time frame, and
                    #   the tag name(s) match the regex filter (if specified)
                    versions.extend(
                        [
                            x
                            for x in versionsJson
                            if (dateFrom <= ParseDate(x.get('created_at')) <= dateTo)
                            and (
                                (
                                    (not imageTagRegexes)
                                    or any(
                                        [
                                            v.match(t)
                                            for t in mmguero.DeepGet(x, ['metadata', 'container', 'tags'])
                                            for k, v in imageTagRegexes.items()
                                        ]
                                    )
                                )
                            )
                        ]
                    )
                    if len(versionsJson) < GITHUB_API_REQUESTS_PER_PAGE:
                        break
                else:
                    break
            except Exception as e:
                # give up
                logging.error(f"Listing package versions: {e}")
                break

        # the GitHub packages API apparently doesn't surface pull counts, so we've got to do some scraping to get that number
        for version in versions:
            try:
                if 'html_url' in version:
                    tmpResponse = ghHTMLSession.get(
                        version['html_url'],
                        allow_redirects=True,
                    )
                    tmpResponse.raise_for_status()
                    soup = BeautifulSoup(tmpResponse.text, 'html.parser')
                    # look for the "Total downloads" <span>, then get the contents of its next sibling
                    if totalDownloadsLabel := soup.find('span', string="Total downloads"):
                        if tags := mmguero.DeepGet(version, ['metadata', 'container', 'tags']):
                            tagsStr = f':{"(" if len(tags) > 1 else ""}{"|".join(tags)}{")" if len(tags) > 1 else ""}'
                        else:
                            tagsStr = '@' + version['name']
                        if pullCount := int(totalDownloadsLabel.find_next('span').text.replace(",", "")):
                            imagePulls[
                                f"{mmguero.DeepGet(packageInfo, ['owner', 'login'])}/{packageInfo['name']}{tagsStr}"
                            ] = int(pullCount)
            except Exception as e:
                logging.error(f"Parsing HTML page for package: {e}")

    # put things together for the final output
    if assetDownloads:
        finalResults['release_assets'] = assetDownloads
    if imagePulls:
        finalResults['image_pulls'] = imagePulls

    # add a total to each sub-dictionary
    for key, subDict in finalResults.items():
        subDict["total"] = sum(subDict.values())

    print(json.dumps(finalResults))

    return 0


###################################################################################################
if __name__ == '__main__':
    if main() > 0:
        sys.exit(0)
    else:
        sys.exit(1)
