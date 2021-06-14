#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2021 Battelle Energy Alliance, LLC.  All rights reserved.

import argparse
import os
import sys
import pprint
import json
import socket
import xml.etree.ElementTree as ET

import mmguero
from mmguero import eprint

from itertools import groupby
from collections import defaultdict
from collections import OrderedDict

###################################################################################################
args = None
debug = False
script_name = os.path.basename(__file__)
script_path = os.path.dirname(os.path.realpath(__file__))
orig_path = os.getcwd()

###################################################################################################
IGNORE_FINTERPRINT_FILES = ("Operating System.xml")

###################################################################################################
# main
def main():
  global args
  global debug

  parser = argparse.ArgumentParser(description=script_name, add_help=False, usage='{} <arguments>'.format(script_name))
  parser.add_argument('-d', '--defaults', dest='accept_defaults', type=mmguero.str2bool, nargs='?', const=True, default=False, metavar='true|false', help="Accept defaults to prompts without user interaction")
  parser.add_argument('-v', '--verbose', dest='debug', type=mmguero.str2bool, nargs='?', const=True, default=False, metavar='true|false', help="Verbose/debug output")
  parser.add_argument(dest='input', metavar='<string>', type=str, nargs='+', help="Input file(s)")
  try:
    parser.error = parser.exit
    args = parser.parse_args()
  except SystemExit:
    parser.print_help()
    exit(2)

  debug = args.debug
  if debug:
    eprint(os.path.join(script_path, script_name))
    eprint("Arguments: {}".format(sys.argv[1:]))
    eprint("Arguments: {}".format(args))
  else:
    sys.tracebacklimit = 0

  # map protocol numbers to lowercase names (e.g., 6 to 'tcp'), defaulting to '-' for zeek to signify "not set"
  protomap = defaultdict(lambda: 'unknown_transport')
  protomap.update({num:name[8:].lower() for name, num in vars(socket).items() if name.startswith("IPPROTO")})

  fingerprints = defaultdict(lambda: None)

  for fingerprintFile in args.input:

    fingerprint = defaultdict(lambda: None)
    fingerprint['Payloads'] = {}

    if ((args.input is not None) and
        os.path.isfile(fingerprintFile) and
        (os.path.basename(fingerprintFile) not in IGNORE_FINTERPRINT_FILES)):

      root = ET.parse(fingerprintFile).getroot();
      if (root.tag == 'Fingerprint'):

        if (header := root.find('Header')) is not None:
          headerInfo = {};
          for child in header:
            headerInfo[child.tag] = ' '.join(child.text.split())
          fingerprint.update(headerInfo)

        for item in root.findall('./Payload'):
          filterFor = item.attrib['For'].strip() if 'For' in item.attrib else None
          if filterFor:
            payloadInfo = defaultdict(lambda: None) if filterFor not in fingerprint['Payloads'] else fingerprint['Payloads'][filterFor]
            payloadFilters = defaultdict(lambda: None) if payloadInfo['Filters'] == None else payloadInfo['Filters']
            if (descriptionItem := item.find('./Description')) is not None:
              payloadInfo['Description'] = ' '.join(descriptionItem.text.split())
            details = defaultdict(lambda: '-')
            if (returnItem := item.find('./Always/Return')) is not None:
              payloadInfo.update(returnItem.attrib)
              if (detailsItem := returnItem.find('./Details')) is not None:
                if (categoryItem := detailsItem.find('./Category')) is not None:
                  details['Category'] = categoryItem.text;
                if (roleItem := detailsItem.find('./Role')) is not None:
                  details['Role'] = roleItem.text;
                for detailItem in detailsItem.findall('./Detail'):
                  detailName = detailItem.attrib['Name'] if 'Name' in detailItem.attrib else None
                  if detailName:
                    details[detailName] = detailItem.text
            payloadInfo['Filters'] = payloadFilters
            payloadInfo['Details'] = details
            fingerprint['Payloads'][filterFor] = payloadInfo

        for item in root.findall('./Filter'):
          filterFor = item.attrib['For'].strip() if 'For' in item.attrib else None
          if filterFor in fingerprint['Payloads']:
            filterName = item.attrib['Name'] if 'Name' in item.attrib else f"{len(fingerprint['Payloads'][filterFor]['Filters'])+1}"
            filterDetails = defaultdict(lambda: '-') if filterName not in fingerprint['Payloads'][filterFor]['Filters'] else fingerprint['Payloads'][filterFor]['Filters'][filterName]
            for child in item:
              if child.text:
                filterDetails[child.tag] = int(child.text) if child.text.isdigit() else child.text
              if child.attrib:
                filterDetails[child.tag] = child.attrib

            # we're covering modbus traffic pretty thoroughly already, don't bother with duplicates/redundancy here
            onlyModbusDst = False
            onlyModbusSrc = False
            if ((filterDetails["DstPort"] == 502) and (filterDetails["SrcPort"] in [502, '-'])):
              onlyModbusDst = True
            if ((filterDetails["SrcPort"] == 502) and (filterDetails["DstPort"] in [502, '-'])):
              onlyModbusSrc = True
            if onlyModbusDst:
              del filterDetails["DstPort"]
            if onlyModbusSrc:
              del filterDetails["SrcPort"]

            fingerprint['Payloads'][filterFor]['Filters'][filterName] = filterDetails

      fingerprints[os.path.basename(fingerprintFile)] = fingerprint

  print('\t'.join(['#fields', 'proto', 'dport', 'sport', 'name', 'category', 'role']))
  for filename, fingerprint in fingerprints.items():
    if "Payloads" in fingerprint:
      for name, payload in fingerprint["Payloads"].items():
        if "Filters" in payload:
          for filtername, filters in payload["Filters"].items():
            nameItems = [x for x in list(OrderedDict.fromkeys(" ".join([fingerprint["Name"], name, filtername]).split())) if x.lower() not in ["dst", "src", "dstport", "srcport", "default"]]
            zeekItems = [protomap[filters["TransportProtocol"]],
                         filters["DstPort"] if (filters["DstPort"] != '-') else 0,
                         filters["SrcPort"] if (filters["SrcPort"] != '-') else 0,
                         " ".join(nameItems),
                         payload["Details"]["Category"],
                         payload["Details"]["Role"]]
            print('\t'.join(map(str,zeekItems)))

###################################################################################################
if __name__ == '__main__':
  main()
