# Copyright (c) 2025 Battelle Energy Alliance, LLC.  All rights reserved.

# adapted some code from tenzir/threatbus
# - https://github.com/tenzir/threatbus
# - Copyright (c) 2020, Tenzir GmbH
# - BSD 3-Clause license: https://github.com/tenzir/threatbus/blob/master/COPYING
# - Zeek Plugin: https://github.com/tenzir/threatbus/blob/master/COPYING

from bs4 import BeautifulSoup
from collections import defaultdict
from collections.abc import Iterable
from contextlib import contextmanager, nullcontext
from datetime import datetime
from dateutil.relativedelta import relativedelta
from multiprocessing import RawValue
from pymisp import MISPEvent, MISPAttribute, PyMISP
from pytz import utc as UTCTimeZone
from stix2 import parse as STIXParse
from stix2.exceptions import STIXError
from stix2.v20 import Indicator as STIX_Indicator_v20
from stix2.v21 import Indicator as STIX_Indicator_v21
from stix2patterns.v20.pattern import Pattern as STIX_Pattern_v20
from stix2patterns.v21.pattern import Pattern as STIX_Pattern_v21
from taxii2client.v20 import as_pages as TaxiiAsPages_v20
from taxii2client.v20 import Collection as TaxiiCollection_v20
from taxii2client.v20 import Server as TaxiiServer_v20
from taxii2client.v21 import as_pages as TaxiiAsPages_v21
from taxii2client.v21 import Collection as TaxiiCollection_v21
from taxii2client.v21 import Server as TaxiiServer_v21
from threading import Lock
from time import sleep, mktime
from types import GeneratorType, FunctionType, LambdaType
from typing import Tuple, Union, Iterator
from urllib.parse import urljoin, urlparse
from logging import DEBUG as LOGGING_DEBUG
import copy
import json
import mandiant_threatintel
import os
import re
import requests
import urllib3

from malcolm_utils import base64_decode_if_prefixed, LoadStrIfJson, LoadFileIfJson, isprivateip

# keys for dict returned by map_*_indicator_to_zeek for Zeek intel file fields
ZEEK_INTEL_INDICATOR = 'indicator'
ZEEK_INTEL_INDICATOR_TYPE = 'indicator_type'
ZEEK_INTEL_META_SOURCE = 'meta.source'
ZEEK_INTEL_META_DESC = 'meta.desc'
ZEEK_INTEL_META_URL = 'meta.url'
ZEEK_INTEL_META_CONFIDENCE = 'meta.confidence'
ZEEK_INTEL_META_THREAT_SCORE = 'meta.threat_score'
ZEEK_INTEL_META_VERDICT = 'meta.verdict'
ZEEK_INTEL_META_VERDICT_SOURCE = 'meta.verdict_source'
ZEEK_INTEL_META_FIRSTSEEN = 'meta.firstseen'
ZEEK_INTEL_META_LASTSEEN = 'meta.lastseen'
ZEEK_INTEL_META_ASSOCIATED = 'meta.associated'
ZEEK_INTEL_META_CATEGORY = 'meta.category'
ZEEK_INTEL_META_CAMPAIGNS = 'meta.campaigns'
ZEEK_INTEL_META_REPORTS = 'meta.reports'
ZEEK_INTEL_META_DO_NOTICE = 'meta.do_notice'
ZEEK_INTEL_CIF_TAGS = 'meta.cif_tags'
ZEEK_INTEL_CIF_CONFIDENCE = 'meta.cif_confidence'
ZEEK_INTEL_CIF_SOURCE = 'meta.cif_source'
ZEEK_INTEL_CIF_DESCRIPTION = 'meta.cif_description'
ZEEK_INTEL_CIF_FIRSTSEEN = 'meta.cif_firstseen'
ZEEK_INTEL_CIF_LASTSEEN = 'meta.cif_lastseen'

# TODO: STILL NEED TO MAP THESE:
#   - ZEEK_INTEL_META_CATEGORY
#   - ZEEK_INTEL_META_THREAT_SCORE
#   - ZEEK_INTEL_META_VERDICT
#   - ZEEK_INTEL_META_VERDICT_SOURCE
#   - ZEEK_INTEL_META_ASSOCIATED
#   - ZEEK_INTEL_META_CATEGORY
#   - ZEEK_INTEL_META_CAMPAIGNS
#   - ZEEK_INTEL_META_REPORTS

ZEEK_INTEL_WORKER_THREADS_DEFAULT = 2

TAXII_INDICATOR_FILTER = {'type': 'indicator'}
TAXII_PAGE_SIZE = 50
MISP_PAGE_SIZE_ATTRIBUTES = 500
MISP_PAGE_SIZE_EVENTS = 10
MANDIANT_PAGE_SIZE_DEFAULT = 1000
MANDIANT_MINIMUM_MSCORE_DEFAULT = 60
MANDIANT_EXCLUDE_OSINT_DEFAULT = False
MANDIANT_INCLUDE_CAMPAIGNS_DEFAULT = False
MANDIANT_INCLUDE_REPORTS_DEFAULT = False
MANDIANT_INCLUDE_THREAT_RATING_DEFAULT = False
MANDIANT_INCLUDE_MISP_DEFAULT = True
MANDIANT_INCLUDE_CATEGORY_DEFAULT = True

# See the documentation for the Zeek INTEL framework [1] and STIX-2 cyber observable objects [2]
# [1] https://docs.zeek.org/en/stable/scripts/base/frameworks/intel/main.zeek.html#type-Intel::Type
# [2] https://docs.oasis-open.org/cti/stix/v2.1/cs01/stix-v2.1-cs01.html#_mlbmudhl16lr
STIX_ZEEK_INTEL_TYPE_MAP = {
    "domain-name:value": "DOMAIN",
    "email-addr:value": "EMAIL",
    "email-message:from_ref.'value'": "EMAIL",
    "file:name": "FILE_NAME",
    "file:hashes.MD5": "FILE_HASH",
    "file:hashes.'MD5'": "FILE_HASH",
    "file:hashes.'SHA-1'": "FILE_HASH",
    "file:hashes.'SHA-256'": "FILE_HASH",
    "file:hashes.'SHA-512'": "FILE_HASH",
    "file:hashes.'SHA3-256'": "FILE_HASH",
    "file:hashes.'SHA3-512'": "FILE_HASH",
    "file:hashes.SSDEEP": "FILE_HASH",
    "file:hashes.TLSH": "FILE_HASH",
    "ipv4-addr:value": "ADDR",
    "ipv6-addr:value": "ADDR",
    "software:name": "SOFTWARE",
    "url:value": "URL",
    "user:user_id": "USER_NAME",
    "user:account_login": "USER_NAME",
    "x509-certificate:hashes.'SHA-1'": "CERT_HASH",  # Zeek only supports SHA-1
}

# See the documentation for the Zeek INTEL framework [1] and MISP attribute types [2]
# [1] https://docs.zeek.org/en/current/scripts/base/frameworks/intel/main.zeek.html#type-Intel::Type
# [2] https://www.misp-project.org/datamodels/
MISP_ZEEK_INTEL_TYPE_MAP = {
    "domain": "DOMAIN",
    "email": "EMAIL",
    "email-dst": "EMAIL",
    "email-reply-to": "EMAIL",
    "email-src": "EMAIL",
    "filename": "FILE_NAME",
    "filename|md5": ["FILE_NAME", "FILE_HASH"],
    "filename|sha1": ["FILE_NAME", "FILE_HASH"],
    "filename|sha256": ["FILE_NAME", "FILE_HASH"],
    "filename|sha512": ["FILE_NAME", "FILE_HASH"],
    "hostname": "DOMAIN",
    "ip-dst": "ADDR",
    "ip-src": "ADDR",
    "md5": "FILE_HASH",
    "pgp-public-key": "PUBKEY_HASH",
    "sha1": "FILE_HASH",
    "sha256": "FILE_HASH",
    "sha512": "FILE_HASH",
    "ssh-fingerprint": "PUBKEY_HASH",
    "target-email": "EMAIL",
    "target-user": "USER_NAME",
    "url": "URL",
    "x509-fingerprint-sha1": "CERT_HASH",
}

# See the documentation for the Zeek INTEL framework [1] and Mandiant threat intel API [2]
# [1] https://docs.zeek.org/en/current/scripts/base/frameworks/intel/main.zeek.html#type-Intel::Type
# [2] https://docs.mandiant.com/home/mati-threat-intelligence-api-v4#tag/Indicators
MANDIANT_ZEEK_INTEL_TYPE_MAP = {
    mandiant_threatintel.FQDNIndicator: 'DOMAIN',
    mandiant_threatintel.URLIndicator: 'URL',
    mandiant_threatintel.IPIndicator: 'ADDR',
    mandiant_threatintel.MD5Indicator: 'FILE_HASH',
}

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# get URL directory listing
def get_url_paths_from_response(response_text, parent_url='', ext=''):
    soup = BeautifulSoup(response_text, 'html.parser')
    return [
        parent_url + ('' if parent_url.endswith('/') else '/') + node.get('href')
        for node in soup.find_all('a')
        if node.get('href').endswith(ext)
    ]


def get_url_paths(url, session=None, ssl_verify=False, ext='', params={}):
    response = (
        requests.get(url, params=params, allow_redirects=True, verify=ssl_verify)
        if session is None
        else session.get(url, params=params, allow_redirects=True, verify=ssl_verify)
    )
    if response.ok:
        response_text = response.text
    else:
        return response.raise_for_status()
    return get_url_paths_from_response(response_text, parent_url=url, ext=ext)


# download to file
def download_to_file(url, session=None, local_filename=None, chunk_bytes=4096, ssl_verify=False, logger=None):
    tmpDownloadedFileSpec = local_filename if local_filename else os.path.basename(urlparse(url).path)
    r = (
        requests.get(url, stream=True, allow_redirects=True, verify=ssl_verify)
        if session is None
        else session.get(url, stream=True, allow_redirects=True, verify=ssl_verify)
    )
    with open(tmpDownloadedFileSpec, "wb") as f:
        for chunk in r.iter_content(chunk_size=chunk_bytes):
            if chunk:
                f.write(chunk)
    fExists = os.path.isfile(tmpDownloadedFileSpec)
    fSize = os.path.getsize(tmpDownloadedFileSpec)
    if (logger is not None) and (LOGGING_DEBUG >= logger.root.level):
        logger.debug(
            f"Download of {url} to {tmpDownloadedFileSpec} {'succeeded' if fExists else 'failed'} ({fSize} bytes)"
        )

    if fExists and (fSize > 0):
        return tmpDownloadedFileSpec
    else:
        if fExists:
            os.remove(tmpDownloadedFileSpec)
        return None


def mandiant_indicator_as_json_str(indicator, skip_attr_map={}):
    if indicator and indicator._api_response:
        return json.dumps(indicator._api_response)
    else:
        return 'unknown indicator'


def map_mandiant_indicator_to_zeek(
    indicator: mandiant_threatintel.APIResponse,
    skip_attr_map={},
    logger=None,
) -> Union[Tuple[defaultdict], None]:
    """
    Maps a Mandiant threat intelligence indicator object to Zeek intel items
    @see https://docs.zeek.org/en/current/scripts/base/frameworks/intel/main.zeek.html#type-Intel::Type
    @param indicator The indicator object (mandiant_threatintel.APIResponse) to convert
    @return a list containing the Zeek intel dict(s) from the indicator
    """
    results = []

    # get matching Zeek intel type
    if zeek_type := MANDIANT_ZEEK_INTEL_TYPE_MAP.get(type(indicator), None):

        if (logger is not None) and (LOGGING_DEBUG >= logger.root.level):
            logger.debug(mandiant_indicator_as_json_str(indicator, skip_attr_map=skip_attr_map))

        zeekItem = defaultdict(lambda: '-')
        tags = []
        sources = []

        zeekItem[ZEEK_INTEL_INDICATOR_TYPE] = "Intel::" + zeek_type

        if hasattr(indicator, 'id'):
            zeekItem[ZEEK_INTEL_META_DESC] = indicator.id
            zeekItem[ZEEK_INTEL_CIF_DESCRIPTION] = zeekItem[ZEEK_INTEL_META_DESC]
            zeekItem[ZEEK_INTEL_META_URL] = f'https://advantage.mandiant.com/indicator/{indicator.id}'
        if hasattr(indicator, 'mscore'):
            zeekItem[ZEEK_INTEL_META_CONFIDENCE] = str(indicator.mscore)
            zeekItem[ZEEK_INTEL_CIF_CONFIDENCE] = str(round(indicator.mscore / 10))
        if hasattr(indicator, 'first_seen'):
            zeekItem[ZEEK_INTEL_META_FIRSTSEEN] = str(mktime(indicator.first_seen.timetuple()))
            zeekItem[ZEEK_INTEL_CIF_FIRSTSEEN] = zeekItem[ZEEK_INTEL_META_FIRSTSEEN]
        if hasattr(indicator, 'last_seen'):
            zeekItem[ZEEK_INTEL_META_LASTSEEN] = str(mktime(indicator.last_seen.timetuple()))
            zeekItem[ZEEK_INTEL_CIF_LASTSEEN] = zeekItem[ZEEK_INTEL_META_LASTSEEN]
        if hasattr(indicator, 'sources'):
            sources.extend(list({entry['source_name'] for entry in indicator.sources if 'source_name' in entry}))
            if categories := list(
                {
                    category
                    for item in indicator.sources
                    if 'category' in item and item['category']
                    for category in item['category']
                }
            ):
                tags.extend(categories)

        if hasattr(indicator, 'misp'):
            if trueMispAttrs := [key for key, value in indicator.misp.items() if value]:
                tags.extend(trueMispAttrs)

        if tags:
            zeekItem[ZEEK_INTEL_CIF_TAGS] = ','.join([x.replace(',', '\\x2c') for x in tags])

        # The MD5Indicator class can actually have multiple types of hashes,
        #   and we want to create a zeek intel item for each. I'm accessing
        #   the underlying API response directly here (rather than through getattr)
        #   to avoid extra GET requests to the API attempting to find a value
        #   that didn't come with the initial request.
        #   Performance-wise, if we didn't get it with the indicator object in
        #   the first place it's not something we need to make an entire extra
        #   network communication to attempt.
        if (
            isinstance(indicator, mandiant_threatintel.MD5Indicator)
            and indicator._api_response
            and (hashes := indicator._api_response.get('associated_hashes', []))
        ):
            for hashish in hashes:
                if hashVal := hashish.get('value', None):
                    tmpItem = copy.deepcopy(zeekItem)
                    tmpItem[ZEEK_INTEL_INDICATOR] = hashVal
                    if newId := hashish.get('id', None):
                        tmpItem[ZEEK_INTEL_META_URL] = f'https://advantage.mandiant.com/indicator/{newId}'
                    if sources:
                        tmpItem[ZEEK_INTEL_META_SOURCE] = '\\x7c'.join([x.replace(',', '\\x2c') for x in sources])
                    results.append(tmpItem)
                    if (logger is not None) and (LOGGING_DEBUG >= logger.root.level):
                        logger.debug(tmpItem)

        elif hasattr(indicator, 'value') and (val := indicator.value):
            # handle other types besides the file hash
            zeekItem[ZEEK_INTEL_INDICATOR] = val
            if sources:
                zeekItem[ZEEK_INTEL_META_SOURCE] = '\\x7c'.join([x.replace(',', '\\x2c') for x in sources])
            results.append(zeekItem)
            if (logger is not None) and (LOGGING_DEBUG >= logger.root.level):
                logger.debug(zeekItem)

    else:
        if logger is not None:
            logger.warning(f"No matching Zeek type found for Mandiant indicator type '{indicator.__class__.__name__}'")

    return results


def stix_pattern_from_str(indicator_type: type, pattern_str: str) -> Union[STIX_Pattern_v21, STIX_Pattern_v20, None]:
    """
    Creates a stix2patterns.v20.pattern.Pattern (STIX_Pattern_v20) or a
    stix2patterns.v21.pattern.Pattern (STIX_Pattern_v21) based on the given
    pattern string depending on the type of the indicator (v2.0 or v2.1).
    Returns None if the indicator type is unsupported.
    @param indicator_type the type of the indicator object
    @param pattern_str the STIX-2 pattern
    @return the Pattern object initialized from the pattern string
    """
    if indicator_type is STIX_Indicator_v21:
        return STIX_Pattern_v21(pattern_str)
    elif indicator_type is STIX_Indicator_v20:
        return STIX_Pattern_v20(pattern_str)
    else:
        return None


def is_stix_point_equality_ioc(indicator_type: type, pattern_str: str, logger=None) -> bool:
    """
    Predicate to check if a STIX-2 pattern is a point-IoC, i.e., if the pattern
    only consists of a single EqualityComparisonExpression. However, that EqualityComparisonExpression
    may contain multiple OR'ed values, e.g.,
    "[file:hashes.'SHA-1' = '080989879772b0da6a78be8d38dba1f50279fd22' OR file:hashes.MD5 = 'a04aae944126fc3256cf4cf6de4646fb]"
    @param indicator_type the type of the indicator object
    @param pattern_str The STIX-2 pattern string to inspect
    @return True (the pattern is a point-IoC) or False (the pattern is NOT a point-IoC)
    """
    try:
        if pattern := stix_pattern_from_str(indicator_type, pattern_str):
            # InspectionListener https://github.com/oasis-open/cti-pattern-validator/blob/e926d0a14adf88de08acb908a51db1f453c13647/stix2patterns/v21/inspector.py#L5
            # E.g.,   pattern = "[domain-name:value = 'evil.com']"
            # =>           il = pattern_data(comparisons={'domain-name': [(['value'], '=', "'evil.com'")]}, observation_ops=set(), qualifiers=set())
            # =>  cybox_types = ['domain-name']
            il = pattern.inspect()
            cybox_types = list(il.comparisons.keys())

            return (
                len(il.observation_ops) == 0  # no observation operators
                and len(il.qualifiers) == 0  # no qualifiers
                and len(il.comparisons) == 1  # only one observable type (comparison) is in use
                and len(cybox_types) == 1  # must be point-indicator (one field only)
                and all(y == 3 for y in [len(x) for x in il.comparisons[cybox_types[0]]])  # ('value', '=', 'evil.com')
                and il.comparisons[cybox_types[0]][0][1] in ("=", "==")  # equality comparison
            )

        else:
            return False

    except Exception as e:
        if logger is not None:
            logger.warning(f'Parsing "{pattern_str}": {e}')
        return False


def split_stix_object_path_and_value(
    indicator_type: type, pattern_str: str, logger=None
) -> Union[Tuple[Tuple[str, str]], None]:
    """
    Splits a STIX-2 pattern from a point IoC into the object_path and the
    ioc_value of that pattern (e.g., [domain-name:value = 'evil.com'] is split
    to `domain-name:value` and `evil.com`. Returns None if the pattern is not
    a point-ioc pattern.
    @param indicator_type the type of the indicator object
    @param pattern_str the STIX-2 pattern to split
    @return the object_path and ioc_value of the pattern or None
    """
    if is_stix_point_equality_ioc(indicator_type, pattern_str, logger) and (
        pattern := stix_pattern_from_str(indicator_type, pattern_str)
    ):
        il = pattern.inspect()
        results = []

        # some of these checks are redundant (there is only one key, len(element) == 3, etc.) in is_stix_point_equality_ioc
        for comparison in list(il.comparisons.keys()):
            for element in il.comparisons[comparison]:
                if isinstance(element, Iterable) and (len(element) == 3) and (element[1] in ('=', '==')):
                    # construct object path name, e.g.:
                    #     file:hashes.'SHA-1'
                    #     software:name
                    if isinstance(element[0], Iterable):
                        object_path = ':'.join(
                            (
                                comparison.strip(),
                                '.'.join(
                                    [element[0][0].strip()] + ["'" + item.strip() + "'" for item in element[0][1:]]
                                ),
                            )
                        )
                    else:
                        object_path = ':'.join((comparison.strip(), element[0].strip()))

                    # strip quotes from IoC value
                    if element[2].startswith("'") and element[2].endswith("'"):
                        ioc_value = element[2].strip("'")
                    elif element[2].startswith('"') and element[2].endswith('"'):
                        ioc_value = element[2].strip('"')
                    else:
                        ioc_value = element[2]

                    results.append((object_path, ioc_value))

        return results

    else:
        # invalid pattern
        return None


def map_stix_indicator_to_zeek(
    indicator: Union[STIX_Indicator_v20, STIX_Indicator_v21],
    source: Union[Tuple[str], None] = None,
    logger=None,
) -> Union[Tuple[defaultdict], None]:
    """
    Maps a STIX-2 indicator to Zeek intel items
    @see https://docs.zeek.org/en/current/scripts/base/frameworks/intel/main.zeek.html#type-Intel::Type
    @param indicator The STIX-2 Indicator to convert
    @return a list containing the Zeek intel dict(s) from the STIX-2 Indicator
    """
    if (type(indicator) is not STIX_Indicator_v20) and (type(indicator) is not STIX_Indicator_v21):
        if logger is not None:
            logger.warning(f"Discarding message, expected STIX-2 Indicator: {indicator}")
        return None

    if not is_stix_point_equality_ioc(type(indicator), indicator.pattern, logger):
        if logger is not None:
            logger.warning(
                f"Zeek only supports point-IoCs. Cannot map compound pattern to a Zeek Intel item: {indicator.pattern}"
            )
        return None

    if (logger is not None) and (LOGGING_DEBUG >= logger.root.level):
        logger.debug(indicator)

    results = []
    for object_path, ioc_value in split_stix_object_path_and_value(type(indicator), indicator.pattern, logger):
        # get matching Zeek intel type
        if not (zeek_type := STIX_ZEEK_INTEL_TYPE_MAP.get(object_path, None)):
            if logger is not None:
                logger.warning(f"No matching Zeek type found for STIX-2 indicator type '{object_path}'")
            continue

        if zeek_type == "URL":
            # remove leading protocol, if any
            parsed = urlparse(ioc_value)
            scheme = f"{parsed.scheme}://"
            ioc_value = parsed.geturl().replace(scheme, "", 1)
        elif zeek_type == "ADDR":
            if not isprivateip(ioc_value):
                if re.match(".+/.+", ioc_value):
                    # elevate to subnet if possible
                    zeek_type = "SUBNET"
            else:
                # ignore private IP-space ADDR avlues
                continue

        # ... "fields containing only a hyphen are considered to be null values"
        zeekItem = defaultdict(lambda: '-')

        zeekItem[ZEEK_INTEL_META_SOURCE] = (
            '\\x7c'.join([x.replace(',', '\\x2c') for x in source])
            if source is not None and len(source) > 0
            else str(indicator.id)
        )
        zeekItem[ZEEK_INTEL_INDICATOR] = ioc_value
        zeekItem[ZEEK_INTEL_INDICATOR_TYPE] = "Intel::" + zeek_type
        if ('name' in indicator) or ('description' in indicator):
            zeekItem[ZEEK_INTEL_META_DESC] = '. '.join(
                [x for x in [indicator.get('name', None), indicator.get('description', None)] if x is not None]
            )
            zeekItem[ZEEK_INTEL_CIF_DESCRIPTION] = zeekItem[ZEEK_INTEL_META_DESC]
            # some of these are from CFM, what the heck...
            # if 'description' in indicator:
            #   "description": "severity level: Low\n\nCONFIDENCE: High",
        zeekItem[ZEEK_INTEL_META_FIRSTSEEN] = str(mktime(indicator.created.timetuple()))
        zeekItem[ZEEK_INTEL_CIF_FIRSTSEEN] = zeekItem[ZEEK_INTEL_META_FIRSTSEEN]
        zeekItem[ZEEK_INTEL_META_LASTSEEN] = str(mktime(indicator.modified.timetuple()))
        zeekItem[ZEEK_INTEL_CIF_LASTSEEN] = zeekItem[ZEEK_INTEL_META_LASTSEEN]
        tags = []
        tags.extend([x for x in indicator.get('labels', []) if x])
        tags.extend([x for x in indicator.get('indicator_types', []) if x])
        if len(tags) > 0:
            zeekItem[ZEEK_INTEL_CIF_TAGS] = ','.join([x.replace(',', '\\x2c') for x in tags])

        # TODO: revoked?
        # TODO: confidence?

        results.append(zeekItem)
        if (logger is not None) and (LOGGING_DEBUG >= logger.root.level):
            logger.debug(zeekItem)

    return results


def all_misp_event_attributes(
    attr: MISPAttribute,
    event: MISPEvent,
) -> Iterator[MISPAttribute]:
    """
    Yield attributes from:
      1. a single attr,
      2. event.attributes,
      3. all attributes from event.objects

    Yields in priority order: attr → event.attributes → object attributes.
    """
    if attr:
        yield attr

    if event:
        if event.attributes:
            yield from event.attributes

        for obj in event.objects:
            yield from obj.attributes


def map_misp_attribute_to_zeek(
    attribute: MISPAttribute,
    source: Union[Tuple[str], None] = None,
    url: Union[str, None] = None,
    description: Union[str, None] = None,
    tags: Union[Tuple[str], None] = None,
    confidence: Union[float, None] = None,
    logger=None,
) -> Union[Tuple[defaultdict], None]:
    """
    Maps a MISP attribute to Zeek intel items
    @see https://docs.zeek.org/en/current/scripts/base/frameworks/intel/main.zeek.html#type-Intel::Type
    @param attribute The MISPAttribute to convert
    @return a list containing the Zeek intel dict(s) from the MISPAttribute object
    """
    if (logger is not None) and (LOGGING_DEBUG >= logger.root.level):
        logger.debug(attribute.to_json())

    results = []

    # get matching Zeek intel type
    if not (zeek_types := MISP_ZEEK_INTEL_TYPE_MAP.get(attribute.type, None)):
        if logger is not None:
            logger.warning(f"No matching Zeek type found for MISP attribute type '{attribute.type}'")
        return None

    # some MISP indicators are actually two values together (e.g., filename|sha256)
    valTypePairs = (
        list(zip(zeek_types, attribute.value.split('|')))
        if isinstance(zeek_types, list)
        else [(zeek_types, attribute.value)]
    )

    # process type/value pairs
    for zeek_type, attribute_value in valTypePairs:
        if zeek_type == "URL":
            # remove leading protocol, if any
            parsed = urlparse(attribute_value)
            scheme = f"{parsed.scheme}://"
            attribute_value = parsed.geturl().replace(scheme, "", 1)
        elif zeek_type == "ADDR":
            if not isprivateip(attribute_value):
                if re.match(".+/.+", attribute_value):
                    # elevate to subnet if possible
                    zeek_type = "SUBNET"
            else:
                # ignore private IP-space ADDR avlues
                continue

        # ... "fields containing only a hyphen are considered to be null values"
        zeekItem = defaultdict(lambda: '-')

        if source is not None and len(source) > 0:
            zeekItem[ZEEK_INTEL_META_SOURCE] = '\\x7c'.join([x.replace(',', '\\x2c') for x in source])
        if description is not None:
            zeekItem[ZEEK_INTEL_META_DESC] = description
            zeekItem[ZEEK_INTEL_CIF_DESCRIPTION] = zeekItem[ZEEK_INTEL_META_DESC]
        if url is not None:
            zeekItem[ZEEK_INTEL_META_URL] = url
        zeekItem[ZEEK_INTEL_INDICATOR] = attribute_value
        zeekItem[ZEEK_INTEL_INDICATOR_TYPE] = "Intel::" + zeek_type
        zeekItem[ZEEK_INTEL_META_FIRSTSEEN] = str(mktime(attribute.timestamp.timetuple()))
        zeekItem[ZEEK_INTEL_CIF_FIRSTSEEN] = zeekItem[ZEEK_INTEL_META_FIRSTSEEN]
        zeekItem[ZEEK_INTEL_META_LASTSEEN] = str(mktime(attribute.timestamp.timetuple()))
        zeekItem[ZEEK_INTEL_CIF_LASTSEEN] = zeekItem[ZEEK_INTEL_META_LASTSEEN]
        if tags is not None and len(tags) > 0:
            zeekItem[ZEEK_INTEL_CIF_TAGS] = ','.join([x.replace(',', '\\x2c') for x in [attribute.category] + tags])
        else:
            zeekItem[ZEEK_INTEL_CIF_TAGS] = attribute.category.replace(',', '\\x2c')
        if confidence is not None:
            zeekItem[ZEEK_INTEL_CIF_CONFIDENCE] = str(round(confidence / 10))
            zeekItem[ZEEK_INTEL_META_CONFIDENCE] = str(confidence)

        results.append(zeekItem)
        if (logger is not None) and (LOGGING_DEBUG >= logger.root.level):
            logger.debug(zeekItem)

    return results


class FeedParserZeekPrinter(object):
    lock = None
    fields = []
    # we'll print the #fields header the first time we print a valid row
    printedHeader = False
    logger = None
    outFile = None
    since = None

    def __init__(self, extended: bool, notice: bool, cif: bool, since=None, file=None, logger=None):
        self.lock = Lock()
        self.logger = logger
        self.outFile = file
        self.since = since
        self.fields = [
            ZEEK_INTEL_INDICATOR,
            ZEEK_INTEL_INDICATOR_TYPE,
            ZEEK_INTEL_META_SOURCE,
            ZEEK_INTEL_META_DESC,
            ZEEK_INTEL_META_URL,
        ]
        if extended:
            self.fields.extend(
                [
                    ZEEK_INTEL_META_CONFIDENCE,
                    ZEEK_INTEL_META_THREAT_SCORE,
                    ZEEK_INTEL_META_VERDICT,
                    ZEEK_INTEL_META_VERDICT_SOURCE,
                    ZEEK_INTEL_META_FIRSTSEEN,
                    ZEEK_INTEL_META_LASTSEEN,
                    ZEEK_INTEL_META_ASSOCIATED,
                    ZEEK_INTEL_META_CATEGORY,
                    ZEEK_INTEL_META_CAMPAIGNS,
                    ZEEK_INTEL_META_REPORTS,
                ]
            )
        if notice:
            self.fields.extend(
                [
                    ZEEK_INTEL_META_DO_NOTICE,
                ]
            )
        if cif:
            self.fields.extend(
                [
                    ZEEK_INTEL_CIF_TAGS,
                    ZEEK_INTEL_CIF_CONFIDENCE,
                    ZEEK_INTEL_CIF_SOURCE,
                    ZEEK_INTEL_CIF_DESCRIPTION,
                    ZEEK_INTEL_CIF_FIRSTSEEN,
                    ZEEK_INTEL_CIF_LASTSEEN,
                ]
            )

    def PrintHeader(self):
        if not self.printedHeader:
            with self.lock:
                if not self.printedHeader:
                    print('\t'.join(['#fields'] + self.fields), file=self.outFile)
                    self.printedHeader = True

    def ProcessMandiant(self, indicator, skip_attr_map={}):
        result = False
        try:
            if isinstance(indicator, mandiant_threatintel.APIResponse):
                # map indicator object to Zeek value(s)
                if vals := map_mandiant_indicator_to_zeek(
                    indicator=indicator, skip_attr_map=skip_attr_map, logger=self.logger
                ):
                    for val in vals:
                        self.PrintHeader()
                        with self.lock:
                            # print the intelligence item fields according to the columns in 'fields'
                            print('\t'.join([val[key] for key in self.fields]), file=self.outFile)
                        if not result:
                            result = True

        except Exception as e:
            if self.logger is not None:
                self.logger.warning(
                    f"{type(e).__name__} for {indicator.id if hasattr(indicator, 'id') else 'indicator'}: {e}"
                )
        return result

    def ProcessSTIX(
        self,
        toParse,
        version=None,
        source: Union[Tuple[str], None] = None,
    ):
        result = False
        try:
            # parse the STIX and process all "Indicator" objects
            for obj in STIXParse(toParse, allow_custom=True, version=version).objects:
                if type(obj).__name__ == "Indicator":
                    if not result:
                        result = True
                    # map indicator object to Zeek value(s)
                    if ((self.since is None) or (obj.created >= self.since) or (obj.modified >= self.since)) and (
                        vals := map_stix_indicator_to_zeek(indicator=obj, source=source, logger=self.logger)
                    ):
                        for val in vals:
                            self.PrintHeader()
                            with self.lock:
                                # print the intelligence item fields according to the columns in 'fields'
                                print('\t'.join([val[key] for key in self.fields]), file=self.outFile)

        except STIXError as ve:
            if self.logger is not None:
                self.logger.warning(f"{type(ve).__name__}: {ve}")
        return result

    def ProcessMISP(
        self,
        toParse,
        source: Union[Tuple[str], None] = None,
        url: Union[str, None] = None,
    ):
        result = False
        if isinstance(toParse, dict):
            try:
                attr = None
                event = None
                description = ''
                if source is None:
                    source = []
                tags = []
                certainty = None

                # determine if we're processing an event or an attribute
                if (('Event' in toParse) and isinstance(toParse['Event'], dict) and ('info' in toParse['Event'])) or (
                    'info' in toParse
                ):
                    # this is an event, which may contain an array of attributes
                    event = MISPEvent()
                    event.from_dict(**toParse)

                elif ('id' in toParse) and ('type' in toParse):
                    # processing a single attribute
                    attr = MISPAttribute()
                    attr.from_dict(**toParse)
                    event = MISPEvent()
                    event.from_dict(**attr.Event)

                if attr or event:
                    if not result:
                        result = True
                    if event:
                        # format the descriptive info for the Zeek intel item
                        if hasattr(event, 'Orgc') and event.Orgc:
                            source.append(event.Orgc.name)
                        elif hasattr(event, 'orgc') and event.orgc:
                            source.append(event.orgc.name)

                        if hasattr(event, 'info') and event.info:
                            description = event.info

                        if hasattr(event, 'Tag') and (event.Tag is not None) and (len(event.Tag) > 0):
                            tags = [
                                x.name
                                for x in event.Tag
                                if not x.name.startswith('osint:certainty')
                                and not x.name.startswith('type:')
                                and not x.name.startswith('source:')
                            ]
                            source.extend([x.name[7:] for x in event.Tag if x.name.startswith('source:')])
                            certaintyTags = [
                                x.name.replace('"', '') for x in event.Tag if x.name.startswith('osint:certainty')
                            ]
                            try:
                                certainty = float(certaintyTags[0].split('=')[-1]) if len(certaintyTags) > 0 else None
                            except ValueError:
                                certainty = None

                    # loop through and process the attribute(s)
                    for attribute in all_misp_event_attributes(attr, event):
                        # map attribute to Zeek value(s)
                        if (
                            ((not hasattr(attribute, 'deleted')) or (not attribute.deleted))
                            and (
                                (self.since is None)
                                or (event and hasattr(event, 'timestamp') and (event.timestamp >= self.since))
                                or (attribute and hasattr(attribute, 'timestamp') and attribute.timestamp >= self.since)
                            )
                            and (
                                vals := map_misp_attribute_to_zeek(
                                    attribute=attribute,
                                    source=source,
                                    url=url,
                                    description=f"{description}{'. '+attribute.comment if (hasattr(attribute, 'comment') and attribute.comment) else ''}",
                                    tags=tags,
                                    confidence=certainty,
                                    logger=self.logger,
                                )
                            )
                        ):
                            for val in vals:
                                self.PrintHeader()
                                with self.lock:
                                    # print the intelligence item fields according to the columns in 'fields'
                                    print('\t'.join([val[key] for key in self.fields]), file=self.outFile)

                elif self.logger is not None:
                    self.logger.warning("Unknown MISP object format (could not determine Attribute vs. Event)")

            except Exception as e:
                if self.logger is not None:
                    self.logger.warning(e, exc_info=True)

        elif self.logger is not None:
            self.logger.warning(f"Unknown MISP object format ('{type(toParse)}')")
        return result


def UpdateFromMISP(
    connInfo,
    since,
    nowTime,
    sslVerify,
    zeekPrinter,
    logger,
    successCount,
    workerId,
):
    with requests.Session() as mispSession:
        mispSession.headers.update({'Accept': 'application/json;q=1.0,text/plain;q=0.9,text/html;q=0.9'})
        if mispAuthKey := connInfo.get('auth_key', None):
            mispSession.headers.update({'Authorization': mispAuthKey})

        mispUrl = connInfo.get('url', None)

        # download the URL and parse as JSON to figure out what it is. it could be:
        # - a manifest JSON (https://www.circl.lu/doc/misp/feed-osint/manifest.json)
        # - a directory listing *containing* a manifest.json (https://www.circl.lu/doc/misp/feed-osint/)
        # - a directory listing of misc. JSON files without a manifest.json
        # - an array of Attributes returned for a request via the MISP Automation API to an /attributes endpoint
        # - an array of Events returned for a request via the MISP Automation API to an /events endpoint
        mispResponse = mispSession.get(
            mispUrl,
            allow_redirects=True,
            verify=sslVerify,
        )
        mispResponse.raise_for_status()
        if mispJson := LoadStrIfJson(mispResponse.content):
            # the contents are JSON. determine if this is:
            #   - a single Event
            #   - an array of Events
            #   - an array of Attributes
            #   - a manifest

            if isinstance(mispJson, dict) and (len(mispJson.keys()) == 1) and ('Event' in mispJson):
                # this is a single MISP Event, process it
                if zeekPrinter.ProcessMISP(
                    mispJson,
                    url=mispUrl,
                ):
                    successCount.increment()

            elif isinstance(mispJson, list) and (len(mispJson) > 0):
                # are these Attributes or Events?
                if isinstance(mispJson[0], dict) and ('id' in mispJson[0]) and ('type' in mispJson[0]):
                    controllerType = 'attributes'
                    resultKey = 'Attribute'
                    pageSize = MISP_PAGE_SIZE_ATTRIBUTES
                elif isinstance(mispJson[0], dict) and ('info' in mispJson[0]):
                    controllerType = 'events'
                    resultKey = 'Event'
                    pageSize = MISP_PAGE_SIZE_EVENTS
                else:
                    controllerType = None
                    resultKey = None
                    pageSize = None

                if controllerType:
                    # this is an array of either Attributes or Events.
                    #   rather than handling it via additional calls with request,
                    #   let's use the MISP API to do the searching/pulling
                    #   (yeah, we're duplicating the effort of pulling the
                    #   first page, but meh, who cares?)
                    if mispObject := PyMISP(
                        mispUrl,
                        mispAuthKey,
                        sslVerify,
                        debug=logger and (LOGGING_DEBUG >= logger.root.level),
                    ):
                        # search, looping over the pages pageSize at a time
                        mispPage = 0
                        while True:
                            mispPage += 1
                            resultCount = 0
                            mispResults = mispObject.search(
                                controller=controllerType,
                                return_format='json',
                                limit=pageSize,
                                page=mispPage,
                                type_attribute=list(MISP_ZEEK_INTEL_TYPE_MAP.keys()),
                                timestamp=since,
                            )
                            if mispResults and isinstance(mispResults, dict) and (resultKey in mispResults):
                                # Attributes results
                                resultCount = len(mispResults[resultKey])
                                for item in mispResults[resultKey]:
                                    try:
                                        if zeekPrinter.ProcessMISP(
                                            item,
                                            url=mispUrl,
                                        ):
                                            successCount.increment()
                                    except Exception as e:
                                        if logger is not None:
                                            logger.warning(
                                                f"[{workerId}]: {type(e).__name__} for MISP {resultKey}: {e}"
                                            )

                            elif mispResults and isinstance(mispResults, list):
                                # Events results
                                resultCount = len(mispResults)
                                for item in mispResults:
                                    if item and isinstance(item, dict) and (resultKey in item):
                                        try:
                                            if zeekPrinter.ProcessMISP(
                                                item[resultKey],
                                                url=mispUrl,
                                            ):
                                                successCount.increment()
                                        except Exception as e:
                                            if logger is not None:
                                                logger.warning(
                                                    f"[{workerId}]: {type(e).__name__} for MISP {resultKey}: {e}"
                                                )

                            else:
                                # error or unrecognized results, set this to short circuit
                                resultCount = 0

                            if (logger is not None) and (LOGGING_DEBUG >= logger.root.level):
                                logger.debug(f"[{workerId}]: MISP search page {mispPage} returned {resultCount}")
                            if not mispResults or (resultCount < pageSize):
                                break

                else:
                    # not an Event or an Attribute? what the heck are we even doing?
                    raise Exception(f"Unknown MISP object '{json.dumps(mispJson)}'")

            elif isinstance(mispJson, dict):
                # this is a manifest, loop over, retrieve and process the MISP events it references
                for uri in mispJson:
                    try:
                        newUrl = urljoin(mispUrl, f'{uri}.json')
                        eventTime = (
                            datetime.utcfromtimestamp(int(mispJson[uri]['timestamp'])).astimezone(UTCTimeZone)
                            if 'timestamp' in mispJson[uri]
                            else defaultNow
                        )
                        if (since is None) or (eventTime >= since):
                            mispObjectReponse = mispSession.get(
                                newUrl,
                                allow_redirects=True,
                                verify=sslVerify,
                            )
                            mispObjectReponse.raise_for_status()
                            if zeekPrinter.ProcessMISP(
                                mispObjectReponse.json(),
                                url=newUrl,
                            ):
                                successCount.increment()
                    except Exception as e:
                        if logger is not None:
                            logger.warning(f"[{workerId}]: {type(e).__name__} for MISP object at '{newUrl}': {e}")

            else:
                raise Exception(f"Unknown MISP format '{type(mispJson)}'")

        else:
            # the contents are NOT JSON, it's probably an HTML-formatted directory listing

            # retrieve the links listed (non-recursive, all .json files in this directory)
            paths = get_url_paths_from_response(mispResponse.text, parent_url=mispUrl, ext='.json')

            # see if manifest.json exists in this directory
            manifestPaths = [x for x in paths if x.endswith('/manifest.json')]
            if len(manifestPaths) > 0:
                # the manifest.json exists!
                # retrieve it, then loop over it and retrieve and process the MISP events it references
                for url in manifestPaths:
                    try:
                        mispManifestResponse = mispSession.get(
                            url,
                            allow_redirects=True,
                            verify=sslVerify,
                        )
                        mispManifestResponse.raise_for_status()
                        mispManifest = mispManifestResponse.json()
                        for uri in mispManifest:
                            try:
                                eventTime = (
                                    datetime.utcfromtimestamp(int(mispManifest[uri]['timestamp'])).astimezone(
                                        UTCTimeZone
                                    )
                                    if 'timestamp' in mispManifest[uri]
                                    else defaultNow
                                )
                                if (since is None) or (eventTime >= since):
                                    newUrl = f'{mispUrl.strip("/")}/{uri}.json'
                                    mispObjectReponse = mispSession.get(
                                        newUrl,
                                        allow_redirects=True,
                                        verify=sslVerify,
                                    )
                                    mispObjectReponse.raise_for_status()
                                    if zeekPrinter.ProcessMISP(
                                        mispObjectReponse.json(),
                                        url=newUrl,
                                    ):
                                        successCount.increment()
                            except Exception as e:
                                if logger is not None:
                                    logger.warning(
                                        f"[{workerId}]: {type(e).__name__} for MISP object at '{mispUrl}/{uri}.json': {e}"
                                    )
                    except Exception as e:
                        if logger is not None:
                            logger.warning(f"[{workerId}]: {type(e).__name__} for manifest at '{url}': {e}")

            else:
                # the manifest.json does not exist!
                # just loop over, retrieve and process the .json files in this directory
                for url in paths:
                    try:
                        mispObjectReponse = mispSession.get(
                            url,
                            allow_redirects=True,
                            verify=sslVerify,
                        )
                        mispObjectReponse.raise_for_status()
                        if zeekPrinter.ProcessMISP(
                            mispObjectReponse.json(),
                            url=url,
                        ):
                            successCount.increment()
                    except Exception as e:
                        if logger is not None:
                            logger.warning(f"[{workerId}]: {type(e).__name__} for MISP object at '{url}': {e}")


def UpdateFromTAXII(
    connInfo,
    since,
    nowTime,
    sslVerify,
    zeekPrinter,
    logger,
    successCount,
    workerId,
):
    # connect to the server     with the appropriate API for the TAXII version
    taxiiUrl = connInfo.get('url', None)
    taxiiCollection = connInfo.get('collection', None)
    taxiiUsername = connInfo.get('username', None)
    taxiiPassword = connInfo.get('password', None)
    taxiiVersion = str(connInfo.get('version', None))
    if taxiiVersion == '2.0':
        TaxiiServerClass = TaxiiServer_v20
        TaxiiCollectionClass = TaxiiCollection_v20
        TaxiiAsPagesClass = TaxiiAsPages_v20
    elif taxiiVersion == '2.1':
        TaxiiServerClass = TaxiiServer_v21
        TaxiiCollectionClass = TaxiiCollection_v21
        TaxiiAsPagesClass = TaxiiAsPages_v21
    else:
        raise Exception(f"Unsupported TAXII version '{taxiiVersion}'")

    server = TaxiiServerClass(taxiiUrl, user=taxiiUsername, password=taxiiPassword, verify=sslVerify)

    # collect the collection URL(s) for the given collection name
    collectionUrls = {}
    for api_root in server.api_roots:
        for collection in api_root.collections:
            if (taxiiCollection == '*') or (collection.title.lower() == taxiiCollection.lower()):
                collectionUrls[collection.title] = {
                    'id': collection.id,
                    'url': collection.url,
                }

    # connect to and retrieve indicator STIX objects from the collection URL(s)
    for title, info in collectionUrls.items():
        collection = TaxiiCollectionClass(
            info['url'],
            user=taxiiUsername,
            password=taxiiPassword,
            verify=sslVerify,
        )
        try:
            # loop over paginated results
            for envelope in TaxiiAsPagesClass(
                collection.get_objects,
                per_request=TAXII_PAGE_SIZE,
                **TAXII_INDICATOR_FILTER,
            ):
                if zeekPrinter.ProcessSTIX(
                    envelope,
                    version=taxiiVersion,
                    source=[':'.join([x for x in [server.title, title] if x is not None])],
                ):
                    successCount.increment()

        except Exception as e:
            if logger is not None:
                logger.warning(f"[{workerId}]: {type(e).__name__} for object of collection '{title}': {e}")


def UpdateFromMandiant(
    connInfo,
    since,
    nowTime,
    sslVerify,
    zeekPrinter,
    logger,
    successCount,
    workerId,
):
    if mati_client := mandiant_threatintel.ThreatIntelClient(
        api_key=connInfo.get('api_key', None),
        secret_key=connInfo.get('secret_key', None),
        bearer_token=connInfo.get('bearer_token', None),
        api_base_url=connInfo.get('api_base_url', mandiant_threatintel.API_BASE_URL),
        client_name=connInfo.get('client_name', mandiant_threatintel.CLIENT_APP_NAME),
    ):
        skip_attr_map = defaultdict(lambda: False)
        skip_attr_map['campaigns'] = not bool(connInfo.get('include_campaigns', MANDIANT_INCLUDE_CAMPAIGNS_DEFAULT))
        skip_attr_map['category'] = not bool(connInfo.get('include_category', MANDIANT_INCLUDE_CATEGORY_DEFAULT))
        skip_attr_map['misp'] = not bool(connInfo.get('include_misp', MANDIANT_INCLUDE_MISP_DEFAULT))
        skip_attr_map['reports'] = not bool(connInfo.get('include_reports', MANDIANT_INCLUDE_REPORTS_DEFAULT))
        skip_attr_map['threat_rating'] = not bool(
            connInfo.get('include_threat_rating', MANDIANT_INCLUDE_THREAT_RATING_DEFAULT)
        )
        skip_attr_map['attributed_associations'] = True
        for indicator in mati_client.Indicators.get_list(
            start_epoch=since if since else nowTime - relativedelta(hours=24),
            end_epoch=nowTime,
            page_size=connInfo.get('page_size', MANDIANT_PAGE_SIZE_DEFAULT),
            minimum_mscore=connInfo.get('minimum_mscore', MANDIANT_MINIMUM_MSCORE_DEFAULT),
            exclude_osint=connInfo.get('exclude_osint', MANDIANT_EXCLUDE_OSINT_DEFAULT),
            include_campaigns=not skip_attr_map['campaigns'],
            include_reports=not skip_attr_map['reports'],
            include_threat_rating=not skip_attr_map['threat_rating'],
            include_misp=not skip_attr_map['misp'],
            include_category=skip_attr_map['category'],
        ):
            try:
                if zeekPrinter.ProcessMandiant(indicator, skip_attr_map=skip_attr_map):
                    successCount.increment()
            except Exception as e:
                if logger is not None:
                    logger.warning(
                        f"[{workerId}]: {type(e).__name__} for Mandiant indicator {indicator.id if isinstance(indicator, mandiant_threatintel.APIResponse) else ''}: {e}"
                    )

    else:
        raise Exception("Could not connect to Mandiant threat intelligence service")


def ProcessThreatInputWorker(threatInputWorkerArgs):
    inputQueue, zeekPrinter, since, sslVerify, defaultNow, workerThreadCount, successCount, logger = (
        threatInputWorkerArgs[0],
        threatInputWorkerArgs[1],
        threatInputWorkerArgs[2],
        threatInputWorkerArgs[3],
        threatInputWorkerArgs[4],
        threatInputWorkerArgs[5],
        threatInputWorkerArgs[6],
        threatInputWorkerArgs[7],
    )

    with workerThreadCount as workerId:
        if (logger is not None) and (LOGGING_DEBUG >= logger.root.level):
            logger.debug(f"[{workerId}]: started")

        # the queue was fully populated before we started, so we can run until there are no more elements
        while len(inputQueue) > 0:
            try:
                inarg = inputQueue.popleft()
            except IndexError:
                sleep(1)
            else:
                try:
                    with (
                        open(inarg)
                        if (isinstance(inarg, (str, bytes, os.PathLike, int)) and os.path.isfile(inarg))
                        else nullcontext()
                    ) as infile:
                        if infile:
                            ##################################################################################
                            # JSON FILE (STIX or MISP)

                            if infileJson := LoadFileIfJson(infile):
                                if isinstance(infileJson, dict):
                                    if 'type' in infileJson and 'id' in infileJson:
                                        # STIX input file
                                        if zeekPrinter.ProcessSTIX(
                                            infileJson,
                                            source=[os.path.splitext(os.path.basename(inarg))[0]],
                                        ):
                                            successCount.increment()

                                    elif (len(infileJson.keys()) == 1) and ('Event' in infileJson):
                                        # MISP input file containing "Event"
                                        if zeekPrinter.ProcessMISP(
                                            infileJson,
                                            source=[os.path.splitext(os.path.basename(inarg))[0]],
                                        ):
                                            successCount.increment()
                                    else:
                                        raise Exception(f"Could not identify content in '{inarg}'")
                                else:
                                    raise Exception(f"Could not identify content in '{inarg}'")
                            else:
                                raise Exception(f"Could not parse JSON in '{inarg}'")

                        elif isinstance(inarg, dict):
                            ##################################################################################
                            # Connection parameters specified in dict (e.g., Mandiant Threat Intel) from a YAML file
                            if ('type' in inarg) and (threatFeedType := str(inarg['type'])):
                                if threatFeedType.lower() == 'misp':
                                    UpdateFromMISP(
                                        inarg,
                                        since,
                                        defaultNow,
                                        sslVerify,
                                        zeekPrinter,
                                        logger,
                                        successCount,
                                        workerId,
                                    )
                                elif threatFeedType.lower() == 'taxii':
                                    UpdateFromTAXII(
                                        inarg,
                                        since,
                                        defaultNow,
                                        sslVerify,
                                        zeekPrinter,
                                        logger,
                                        successCount,
                                        workerId,
                                    )
                                elif threatFeedType.lower() == 'mandiant':
                                    UpdateFromMandiant(
                                        inarg,
                                        since,
                                        defaultNow,
                                        sslVerify,
                                        zeekPrinter,
                                        logger,
                                        successCount,
                                        workerId,
                                    )
                                else:
                                    raise Exception(f"Could not handle identify threat feed type '{threatFeedType}'")
                            else:
                                raise Exception(f"Could not identify threat feed type in '{inarg}'")

                        elif isinstance(inarg, str) and inarg.lower().startswith('misp'):
                            ##################################################################################
                            # MISP URL
                            # this is a MISP URL, connect and retrieve MISP indicators from it

                            mispConnInfoDict = defaultdict(lambda: None)
                            mispConnInfoDict['type'] = 'misp'
                            # misp|misp_url|auth_key
                            mispConnInfoParts = [base64_decode_if_prefixed(x) for x in inarg.split('|')[1::]]
                            mispConnInfoDict['url'] = mispConnInfoParts[0]
                            if len(mispConnInfoParts) >= 2:
                                mispConnInfoDict['auth_key'] = mispConnInfoParts[1]
                            UpdateFromMISP(
                                mispConnInfoDict,
                                since,
                                defaultNow,
                                sslVerify,
                                zeekPrinter,
                                logger,
                                successCount,
                                workerId,
                            )

                        elif isinstance(inarg, str) and inarg.lower().startswith('taxii'):
                            ##################################################################################
                            # TAXI (STIX) URL

                            taxiiConnInfoDict = defaultdict(lambda: None)
                            taxiiConnInfoDict['type'] = 'taxii'

                            # this is a TAXII URL, connect and retrieve STIX indicators from it
                            # taxii|2.0|discovery_url|collection_name|username|password
                            #
                            # examples of URLs I've used successfully for testing:
                            # - "taxii|2.0|https://cti-taxii.mitre.org/taxii/|Enterprise ATT&CK"
                            # - "taxii|2.0|https://limo.anomali.com/api/v1/taxii2/taxii/|CyberCrime|guest|guest"
                            #
                            # collection_name can be specified as * to retrieve all collections (careful!)
                            taxiiConnInfo = [base64_decode_if_prefixed(x) for x in inarg.split('|')[1::]]
                            if len(taxiiConnInfo) >= 3:
                                (
                                    taxiiConnInfoDict['version'],
                                    taxiiConnInfoDict['url'],
                                    taxiiConnInfoDict['collection'],
                                ) = taxiiConnInfo[0:3]
                            if len(taxiiConnInfo) >= 4:
                                taxiiConnInfoDict['username'] = taxiiConnInfo[3]
                            if len(taxiiConnInfo) >= 5:
                                taxiiConnInfoDict['password'] = taxiiConnInfo[4]

                            UpdateFromTAXII(
                                taxiiConnInfoDict,
                                since,
                                defaultNow,
                                sslVerify,
                                zeekPrinter,
                                logger,
                                successCount,
                                workerId,
                            )

                except Exception as e:
                    if logger is not None:
                        logger.warning(f"[{workerId}]: {type(e).__name__} for '{inarg}': {e}")

        if (logger is not None) and (LOGGING_DEBUG >= logger.root.level):
            logger.debug(f"[{workerId}]: finished")
