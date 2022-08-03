#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2022 Battelle Energy Alliance, LLC.  All rights reserved.

###################################################################################################
# parse the fields names from the header of of the log file and compare them to the
# known list of total fields. if this zeek log has is a subset of the known fields,
# create a bitmap of the included fields to be included as a special tag
# which can help the logstash parser know on a line-by-line basis which fields are included.
# when logstash-filter-dissect gets this implemented, we may not have to do this:
#   - https://github.com/logstash-plugins/logstash-filter-dissect/issues/56
#   - https://github.com/logstash-plugins/logstash-filter-dissect/issues/62
#
# arguments: accepts one argument, the name of a zeek log file
# output:    returns a string suitable for use as a tag indicating the field bitset., eg., ZEEKFLDx00x01FFFFFF
#
#            ZEEKFLDx00x01FFFFFF
#                   |  └ bitmap of included fields within field list
#                   └ index into zeekLogFields list indicating (to support legacy field configurations, see below)
#
# example:
#            $ ./zeek-log-field-bitmap.py /path/to/conn.log
#            ZEEKFLDx00x01FFFFFF
#
# there are two cases we're trying to cover here by indicating the field types:
#   1. certain fields can be turned on/off in config (for example, enabling/disabling MACs or VLANs for conn.log)
#   2. a Zeek version upgrade changed the field list (see notes about DHCP.log in
#      https://docs.zeek.org/en/latest/install/release-notes.html#bro-2-6)
#
# The first case is pretty simple, because in that case the fields in the zeek log will be some subset of
# the list of all known fields for that type.
#
# The second case is more complicated because the field list could be completely different. Because of this case
# each of the entries in zeekLogFields is itself a list, with older configurations occuring earlier in the list
#
#     $ zeek-log-field-bitmap.py ./bro2.5/dhcp.log
#     ZEEKFLDx00x000003FF
#
#     $ zeek-log-field-bitmap.py ./bro2.6/dhcp.log
#     ZEEKFLDx01x00007FFF
#

import sys
import os
import json
from collections import defaultdict
from ordered_set import OrderedSet

# lists of all known fields for each type of zeek log we're concerned with mapping (ordered as in the .log file header)
# are stored in zeek-log-fields.json
FIELDS_JSON_FILE = os.path.join(os.path.dirname(os.path.realpath(__file__)), "zeek-log-fields.json")

ZEEK_LOG_DELIMITER = '\t'  # zeek log file field delimiter
ZEEK_LOG_HEADER_LOGTYPE = 'path'  # header value for zeek log type (conn, weird, etc.)
ZEEK_LOG_HEADER_FIELDS = 'fields'  # header value for zeek log fields list

# file prefix for bitmap to stdout, eg., ZEEKFLDx00x01FFFFFF
ZEEK_LOG_BITMAP_PREFIX = 'ZEEKFLD'


###################################################################################################
# print to stderr
def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)


###################################################################################################
# Set the index'th bit of v to 1 if x is truthy, else to 0, and return the new value
def set_bit(v, index, x):
    mask = 1 << index  # Compute mask, an integer with just bit 'index' set.
    v &= ~mask  # Clear the bit indicated by the mask (if x is False)
    if x:
        v |= mask  # If x was True, set the bit indicated by the mask.
    return v


###################################################################################################
# main
def main():
    errCode = os.EX_DATAERR

    dataError = False
    zeekLogFields = defaultdict(list)

    # load from json canonical list of known zeek log fields we're concerned with mapping
    zeekLogFieldsTmp = json.load(open(FIELDS_JSON_FILE, 'r'))
    if isinstance(zeekLogFieldsTmp, dict):
        for logType, listOfFieldLists in zeekLogFieldsTmp.items():
            if isinstance(logType, str) and isinstance(listOfFieldLists, list):
                zeekLogFields[str(logType)] = [OrderedSet(fieldList) for fieldList in listOfFieldLists]
            else:
                dataError = True
                break
    else:
        dataError = True

    if dataError:
        # something is wrong with the json file
        eprint("Error loading {} (not found or incorrectly formatted)".format(FIELDS_JSON_FILE))

    else:
        if (len(sys.argv) == 2) and os.path.isfile(sys.argv[1]):

            fieldsBitmap = 0

            # loop over header lines in zeek log file (beginning with '#') and extract the header values
            # into a dictionary containing, among other things:
            #   - the "path" which is the zeek log type (eg., conn, weird, etc.)
            #   - the "fields" list of field names
            headers = {}
            try:
                with open(sys.argv[1], "r", encoding='utf-8') as zeekLogFile:
                    for line in zeekLogFile:
                        if line.startswith('#'):
                            values = line.strip().split(ZEEK_LOG_DELIMITER)
                            key = values.pop(0)[1:]
                            if len(values) == 1:
                                headers[key] = values[0]
                            else:
                                headers[key] = values
                        else:
                            break
            except Exception as e:
                eprint("{} for '{}': {}".format(type(e).__name__, sys.argv[1], e))

            if (
                (ZEEK_LOG_HEADER_LOGTYPE in headers)
                and (ZEEK_LOG_HEADER_FIELDS in headers)  # the "path" header exists
                and (headers[ZEEK_LOG_HEADER_LOGTYPE] in zeekLogFields)  # the "fields" header exists
            ):  # this zeek log type is one we're concerned with mapping

                # the set of field names in *this* log file
                logFieldNames = OrderedSet(headers[ZEEK_LOG_HEADER_FIELDS])

                for versionIdx, allFieldNames in reversed(
                    list(enumerate(zeekLogFields[headers[ZEEK_LOG_HEADER_LOGTYPE]]))
                ):

                    # are this logfile's fields a subset of the complete list?
                    if logFieldNames.issubset(allFieldNames):

                        # determine which fields in the complete list are included in this log file
                        for i, fName in enumerate(allFieldNames):
                            fieldsBitmap = set_bit(fieldsBitmap, i, fName in logFieldNames)

                        # eprint(fieldsBitmap)
                        print('{0}x{1:02X}x{2:08X}'.format(ZEEK_LOG_BITMAP_PREFIX, versionIdx, fieldsBitmap))
                        errCode = os.EX_OK

        else:
            # invalid command-line arguments
            eprint("{} <Zeek log file>".format(sys.argv[0]))
            errCode = os.EX_USAGE

    return errCode


if __name__ == '__main__':
    sys.exit(main())
