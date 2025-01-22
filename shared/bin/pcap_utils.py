#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2025 Battelle Energy Alliance, LLC.  All rights reserved.

import re

###################################################################################################
PCAP_TOPIC_PORT = 30441

PCAP_MIME_TYPES = ['application/vnd.tcpdump.pcap', 'application/x-pcapng']

FILE_INFO_DICT_LIVE = "live"
FILE_INFO_DICT_NAME = "name"
FILE_INFO_DICT_NODE = "node"
FILE_INFO_DICT_SIZE = "size"
FILE_INFO_DICT_TAGS = "tags"
FILE_INFO_FILE_MIME = "mime"
FILE_INFO_FILE_TYPE = "type"


###################################################################################################
# split a PCAP filename up into tags
def tags_from_filename(filespec):
    # split tags on these characters
    tagSplitterRe = "[,-/_.]+"
    # tags to ignore explicitly
    regex = re.compile(r'^(\d+|p?cap|dmp|log|bro|zeek|suricata|m?tcpdump|m?netsniff)$', re.IGNORECASE)
    return list(filter(lambda i: not regex.search(i), map(str.strip, filter(None, re.split(tagSplitterRe, filespec)))))
