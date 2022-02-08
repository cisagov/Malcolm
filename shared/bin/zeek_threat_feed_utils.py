# Copyright (c) 2022 Battelle Energy Alliance, LLC.  All rights reserved.

# adapted some code from tenzir/threatbus
# - https://github.com/tenzir/threatbus
# - Copyright (c) 2020, Tenzir GmbH
# - BSD 3-Clause license: https://github.com/tenzir/threatbus/blob/master/COPYING
# - Zeek Plugin: https://github.com/tenzir/threatbus/blob/master/COPYING

import base64
import dateparser
import json
import os
import re
import requests
import tempfile
import time
import contextlib
from bs4 import BeautifulSoup
from collections import defaultdict
from collections.abc import Iterable

# for handling v2.0 and v2.1 of STIX objects
from stix2.v20 import Indicator as STIX_Indicator_v20
from stix2.v21 import Indicator as STIX_Indicator_v21
from stix2patterns.v21.pattern import Pattern as STIX_Pattern_v21
from stix2patterns.v20.pattern import Pattern as STIX_Pattern_v20
from stix2 import parse as STIXParse
from stix2.exceptions import STIXError

# for handling MISP
from pymisp import MISPEvent, MISPAttribute

# strong type checking
from typing import Tuple, Union

# to remove leading protocol from URL-type indicators
from urllib.parse import urlparse

# keys for dict returned by map_stix_indicator_to_zeek for Zeek intel file fields
ZEEK_INTEL_INDICATOR = 'indicator'
ZEEK_INTEL_INDICATOR_TYPE = 'indicator_type'
ZEEK_INTEL_META_SOURCE = 'meta.source'
ZEEK_INTEL_META_DESC = 'meta.desc'
ZEEK_INTEL_META_URL = 'meta.url'
ZEEK_INTEL_META_DO_NOTICE = 'meta.do_notice'
ZEEK_INTEL_CIF_TAGS = 'meta.cif_tags'
ZEEK_INTEL_CIF_CONFIDENCE = 'meta.cif_confidence'
ZEEK_INTEL_CIF_SOURCE = 'meta.cif_source'
ZEEK_INTEL_CIF_DESCRIPTION = 'meta.cif_description'
ZEEK_INTEL_CIF_FIRSTSEEN = 'meta.cif_firstseen'
ZEEK_INTEL_CIF_LASTSEEN = 'meta.cif_lastseen'

TAXII_INDICATOR_FILTER = {'type': 'indicator'}
TAXII_PAGE_SIZE = 50


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


def base64_decode_if_prefixed(s: str):
    if s.startswith('base64:'):
        return base64.b64decode(s[7:]).decode('utf-8')
    else:
        return s


def LoadStrIfJson(jsonStr):
    try:
        return json.loads(jsonStr)
    except ValueError as e:
        return None


def LoadFileIfJson(fileHandle):
    try:
        return json.load(fileHandle)
    except ValueError as e:
        return None


@contextlib.contextmanager
def temporary_filename(suffix=None):
    try:
        f = tempfile.NamedTemporaryFile(suffix=suffix, delete=False)
        tmp_name = f.name
        f.close()
        yield tmp_name
    finally:
        os.unlink(tmp_name)


# get URL directory listing
def get_url_paths_from_response(response_text, parent_url='', ext=''):
    soup = BeautifulSoup(response_text, 'html.parser')
    return [
        parent_url + ('' if parent_url.endswith('/') else '/') + node.get('href')
        for node in soup.find_all('a')
        if node.get('href').endswith(ext)
    ]


def get_url_paths(url, session=None, ext='', params={}):
    response = (
        requests.get(url, params=params, allow_redirects=True)
        if session is None
        else session.get(url, params=params, allow_redirects=True)
    )
    if response.ok:
        response_text = response.text
    else:
        return response.raise_for_status()
    return get_url_paths_from_response(response_text, parent_url=url, ext=ext)


# download to file
def download_to_file(url, session=None, local_filename=None, chunk_bytes=4096, logger=None):
    tmpDownloadedFileSpec = local_filename if local_filename else os.path.basename(urlparse(url).path)
    r = (
        requests.get(url, stream=True, allow_redirects=True)
        if session is None
        else session.get(url, stream=True, allow_redirects=True)
    )
    with open(tmpDownloadedFileSpec, "wb") as f:
        for chunk in r.iter_content(chunk_size=chunk_bytes):
            if chunk:
                f.write(chunk)
    fExists = os.path.isfile(tmpDownloadedFileSpec)
    fSize = os.path.getsize(tmpDownloadedFileSpec)
    if logger is not None:
        logger.debug(
            f"Download of {url} to {tmpDownloadedFileSpec} {'succeeded' if fExists else 'failed'} ({fSize} bytes)"
        )

    if fExists and (fSize > 0):
        return tmpDownloadedFileSpec
    else:
        if fExists:
            os.remove(tmpDownloadedFileSpec)
        return None


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

    if logger is not None:
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
        elif zeek_type == "ADDR" and re.match(".+/.+", ioc_value):
            # elevate to subnet if possible
            zeek_type = "SUBNET"

        # ... "fields containing only a hyphen are considered to be null values"
        zeekItem = defaultdict(lambda: '-')

        zeekItem[ZEEK_INTEL_META_SOURCE] = (
            ','.join([x.replace(',', '\\x2c') for x in source])
            if source is not None and len(source) > 0
            else str(indicator.id)
        )
        zeekItem[ZEEK_INTEL_INDICATOR] = ioc_value
        zeekItem[ZEEK_INTEL_INDICATOR_TYPE] = "Intel::" + zeek_type
        if ('name' in indicator) or ('description' in indicator):
            zeekItem[ZEEK_INTEL_META_DESC] = '. '.join(
                [x for x in [indicator.get('name', None), indicator.get('description', None)] if x is not None]
            )
            # some of these are from CFM, what the heck...
            # if 'description' in indicator:
            #   "description": "severity level: Low\n\nCONFIDENCE: High",
        zeekItem[ZEEK_INTEL_CIF_FIRSTSEEN] = str(time.mktime(indicator.created.timetuple()))
        zeekItem[ZEEK_INTEL_CIF_LASTSEEN] = str(time.mktime(indicator.modified.timetuple()))
        tags = []
        tags.extend([x for x in indicator.get('labels', []) if x])
        tags.extend([x for x in indicator.get('indicator_types', []) if x])
        if len(tags) > 0:
            zeekItem[ZEEK_INTEL_CIF_TAGS] = ','.join([x.replace(',', '\\x2c') for x in tags])

        # TODO: revoked?
        # TODO: confidence?

        results.append(zeekItem)
        if logger is not None:
            logger.debug(zeekItem)

    return results


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
    if logger is not None:
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
        elif zeek_type == "ADDR" and re.match(".+/.+", attribute_value):
            # elevate to subnet if possible
            zeek_type = "SUBNET"

        # ... "fields containing only a hyphen are considered to be null values"
        zeekItem = defaultdict(lambda: '-')

        if source is not None and len(source) > 0:
            zeekItem[ZEEK_INTEL_META_SOURCE] = ','.join([x.replace(',', '\\x2c') for x in source])
        if description is not None:
            zeekItem[ZEEK_INTEL_META_DESC] = description
        if url is not None:
            zeekItem[ZEEK_INTEL_META_URL] = url
        zeekItem[ZEEK_INTEL_INDICATOR] = attribute_value
        zeekItem[ZEEK_INTEL_INDICATOR_TYPE] = "Intel::" + zeek_type
        zeekItem[ZEEK_INTEL_CIF_FIRSTSEEN] = str(time.mktime(attribute.timestamp.timetuple()))
        zeekItem[ZEEK_INTEL_CIF_LASTSEEN] = str(time.mktime(attribute.timestamp.timetuple()))
        if tags is not None and len(tags) > 0:
            zeekItem[ZEEK_INTEL_CIF_TAGS] = ','.join([x.replace(',', '\\x2c') for x in [attribute.category] + tags])
        else:
            zeekItem[ZEEK_INTEL_CIF_TAGS] = attribute.category.replace(',', '\\x2c')
        if confidence is not None:
            zeekItem[ZEEK_INTEL_CIF_CONFIDENCE] = str(confidence)

        results.append(zeekItem)
        if logger is not None:
            logger.debug(zeekItem)

    return results


class FeedParserZeekPrinter(object):
    fields = []
    # we'll print the #fields header the first time we print a valid row
    printedHeader = False
    logger = None
    outFile = None
    since = None

    def __init__(self, notice: bool, cif: bool, since=None, file=None, logger=None):
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
            print('\t'.join(['#fields'] + self.fields), file=self.outFile)
            self.printedHeader = True

    def ProcessSTIX(
        self,
        toParse,
        source: Union[Tuple[str], None] = None,
    ):
        try:
            # parse the STIX and process all "Indicator" objects
            for obj in STIXParse(toParse, allow_custom=True).objects:
                if type(obj).__name__ == "Indicator":

                    # map indicator object to Zeek value(s)
                    if ((self.since is None) or (obj.created >= self.since) or (obj.modified >= self.since)) and (
                        vals := map_stix_indicator_to_zeek(indicator=obj, source=source, logger=self.logger)
                    ):
                        for val in vals:
                            self.PrintHeader()
                            # print the intelligence item fields according to the columns in 'fields'
                            print('\t'.join([val[key] for key in self.fields]), file=self.outFile)

        except STIXError as ve:
            if self.logger is not None:
                self.logger.warning(f"{type(ve).__name__} parsing '{infile}': {ve}")

    def ProcessMISP(
        self,
        toParse,
        source: Union[Tuple[str], None] = None,
        url: Union[str, None] = None,
    ):
        try:
            event = MISPEvent()
            event.from_dict(**toParse)

            if source is None:
                source = []

            if event.Orgc is not None:
                source.append(event.Orgc.name)

            description = event.info

            if (event.Tag is not None) and (len(event.Tag) > 0):
                tags = [
                    x.name
                    for x in event.Tag
                    if not x.name.startswith('osint:certainty')
                    and not x.name.startswith('type:')
                    and not x.name.startswith('source:')
                ]
                source.extend([x[7:] for x in event.Tag if x.name.startswith('source:')])
                certaintyTags = [x.name.replace('"', '') for x in event.Tag if x.name.startswith('osint:certainty')]
                try:
                    certainty = float(certaintyTags[0].split('=')[-1]) if len(certaintyTags) > 0 else None
                except ValueError as ve:
                    certainty = None
            else:
                tags = []
                certainty = None

            for attribute in event.attributes:

                # map event attribute to Zeek value(s)
                if (
                    ((not hasattr(attribute, 'deleted')) or (attribute.deleted == False))
                    and ((self.since is None) or (event.timestamp >= self.since) or (attribute.timestamp >= self.since))
                    and (
                        vals := map_misp_attribute_to_zeek(
                            attribute=attribute,
                            source=source,
                            url=url,
                            description=f"{description}{'. '+attribute.comment if attribute.comment else ''}",
                            tags=tags,
                            confidence=certainty,
                            logger=self.logger,
                        )
                    )
                ):
                    for val in vals:
                        self.PrintHeader()
                        # print the intelligence item fields according to the columns in 'fields'
                        print('\t'.join([val[key] for key in self.fields]), file=self.outFile)

        except Exception as e:
            if self.logger is not None:
                self.logger.warning(f'Exception: {e}')
