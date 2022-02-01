# borrows code from tenzir/threatbus
# - https://github.com/tenzir/threatbus
# - Copyright (c) 2020, Tenzir GmbH
# - BSD 3-Clause license: https://github.com/tenzir/threatbus/blob/master/COPYING
# - Zeek Plugin: https://github.com/tenzir/threatbus/blob/master/COPYING

import json
import re

from stix2.v20 import Indicator as Indicator_v20
from stix2.v21 import Indicator as Indicator_v21
from stix2patterns.v21.pattern import Pattern as Pattern_v21
from stix2patterns.v20.pattern import Pattern as Pattern_v20
from typing import Tuple, Union
from urllib.parse import urlparse
from collections import namedtuple
from collections.abc import Iterable


# See the documentation for the Zeek INTEL framework [1] and STIX-2 cyber
# observable objects [2]
# [1] https://docs.zeek.org/en/stable/scripts/base/frameworks/intel/main.zeek.html#type-Intel::Type
# [2] https://docs.oasis-open.org/cti/stix/v2.1/cs01/stix-v2.1-cs01.html#_mlbmudhl16lr
zeek_intel_type_map = {
    "domain-name:value": "DOMAIN",
    "email-addr:value": "EMAIL",
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

ZeekIntel = namedtuple("ZeekIntel", ["id", "name", "created", "intel_type", "ioc"], rename=False)


def pattern_from_str(indicator_type: type, pattern_str: str) -> Union[Pattern_v21, Pattern_v20, None]:
    if indicator_type is Indicator_v21:
        return Pattern_v21(pattern_str)
    elif indicator_type is Indicator_v20:
        return Pattern_v20(pattern_str)
    else:
        return None


def is_point_equality_ioc(indicator_type: type, pattern_str: str, logger=None) -> bool:
    """
    Predicate to check if a STIX-2 pattern is a point-IoC, i.e., if the pattern
    only consists of a single EqualityComparisonExpression. However, that EqualityComparisonExpression
    may contain multiple OR'ed values, e.g.,
    "[file:hashes.'SHA-1' = '080989879772b0da6a78be8d38dba1f50279fd22' OR file:hashes.MD5 = 'a04aae944126fc3256cf4cf6de4646fb]"
    @param pattern_str The STIX-2 pattern string to inspect
    """
    try:
        if pattern := pattern_from_str(indicator_type, pattern_str):

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
        if logger:
            logger.debug(f'Parsing "{pattern_str}": {e}')
        return False


def split_object_path_and_value(
    indicator_type: type, pattern_str: str, logger=None
) -> Union[Tuple[Tuple[str, str]], None]:
    """
    Splits a STIX-2 pattern from a point IoC into the object_path and the
    ioc_value of that pattern (e.g., [domain-name:value = 'evil.com'] is split
    to `domain-name:value` and `evil.com`. Returns None if the pattern is not
    a point-ioc pattern.
    @param pattern_str The STIX-2 pattern to split
    @return the object_path and ioc_value of the pattern or None
    """
    if not is_point_equality_ioc(indicator_type, pattern_str, logger):
        return None

    if pattern := pattern_from_str(indicator_type, pattern_str):
        il = pattern.inspect()

        results = []

        for comparison in list(il.comparisons.keys()):
            for element in il.comparisons[comparison]:
                # this check is redundant as it's also done in is_point_equality_ioc
                if isinstance(element, Iterable) and (len(element) == 3) and (element[1] in ('=', '==')):
                    # construct object path name
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
                    if element[2].startswith("'") and element[2].endswith("'"):
                        ioc_value = element[2].strip("'")
                    elif element[2].startswith('"') and element[2].endswith('"'):
                        ioc_value = element[2].strip('"')
                    else:
                        ioc_value = element[2]
                    results.append((object_path, ioc_value))

        return results

    else:
        return None


def map_indicator_to_zeek(indicator: Union[Indicator_v20, Indicator_v21], logger) -> Union[Tuple[ZeekIntel], None]:
    """
    Maps STIX-2 Indicators to strings formatted in the Zeek Intel format
    @see https://docs.zeek.org/en/current/scripts/base/frameworks/intel/main.zeek.html#type-Intel::Type
    @param indicator The STIX-2 Indicator to convert
    @return The mapped broker event or None
    """
    if (type(indicator) is not Indicator_v20) and (type(indicator) is not Indicator_v21):
        logger.warning(f"Discarding message, expected STIX-2 Indicator: {indicator}")
        return None

    if not is_point_equality_ioc(type(indicator), indicator.pattern, logger):
        logger.warning(
            f"Zeek only supports point-IoCs. Cannot map compound pattern to a Zeek Intel item: {indicator.pattern}"
        )
        return None

    results = []
    for object_path, ioc_value in split_object_path_and_value(type(indicator), indicator.pattern, logger):

        # get matching Zeek intel type
        if not (zeek_type := zeek_intel_type_map.get(object_path, None)):
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

        results.append(
            ZeekIntel(
                str(indicator.id),
                indicator.name if 'name' in indicator else '',
                indicator.created,
                zeek_type,
                ioc_value,
            )
        )

    return results
