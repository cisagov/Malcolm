#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import print_function

import argparse
import json
import requests
import os
import sys

GET_STATUS_API = 'api/status'
GET_INDEX_PATTERN_INFO_URI = 'api/saved_objects/_find'
GET_FIELDS_URI = 'api/index_patterns/_fields_for_wildcard'
PUT_INDEX_PATTERN_URI = 'api/saved_objects/index-pattern'

###################################################################################################
debug = False
PY3 = (sys.version_info.major >= 3)
scriptName = os.path.basename(__file__)
scriptPath = os.path.dirname(os.path.realpath(__file__))
origPath = os.getcwd()

###################################################################################################
if not PY3:
  if hasattr(__builtins__, 'raw_input'): input = raw_input

try:
  FileNotFoundError
except NameError:
  FileNotFoundError = IOError

###################################################################################################
# print to stderr
def eprint(*args, **kwargs):
  print(*args, file=sys.stderr, **kwargs)

###################################################################################################
# convenient boolean argument parsing
def str2bool(v):
  if v.lower() in ('yes', 'true', 't', 'y', '1'):
    return True
  elif v.lower() in ('no', 'false', 'f', 'n', '0'):
    return False
  else:
    raise argparse.ArgumentTypeError('Boolean value expected.')

###################################################################################################
# main
def main():
  global debug

  parser = argparse.ArgumentParser(description=scriptName, add_help=False, usage='{} <arguments>'.format(scriptName))
  parser.add_argument('-v', '--verbose', dest='debug', type=str2bool, nargs='?', const=True, default=False, help="Verbose output")
  parser.add_argument('-i', '--index', dest='index', metavar='<str>', type=str, default='sessions2-*', help='Index Pattern Name')
  parser.add_argument('-k', '--kibana', dest='url', metavar='<protocol://host:port>', type=str, default='http://localhost:5601/kibana', help='Kibana URL')
  parser.add_argument('-n', '--dry-run', dest='dryrun', type=str2bool, nargs='?', const=True, default=False, help="Dry run (no PUT)")
  try:
    parser.error = parser.exit
    args = parser.parse_args()
  except SystemExit:
    parser.print_help()
    exit(2)

  debug = args.debug
  if debug:
    eprint(os.path.join(scriptPath, scriptName))
    eprint("Arguments: {}".format(sys.argv[1:]))
    eprint("Arguments: {}".format(args))
  else:
    sys.tracebacklimit = 0

  # get version number so kibana doesn't think we're doing a XSRF when we do the PUT
  statusInfoResponse = requests.get('{}/{}'.format(args.url, GET_STATUS_API))
  statusInfoResponse.raise_for_status()
  statusInfo = statusInfoResponse.json()
  kibanaVersion = statusInfo['version']['number']
  if debug:
    eprint('Kibana version is {}'.format(kibanaVersion))

  # find the ID of the index name (probably will be the same as the name)
  getIndexInfoResponse = requests.get(
    '{}/{}'.format(args.url, GET_INDEX_PATTERN_INFO_URI),
    params={
      'type': 'index-pattern',
      'fields': 'id',
      'search': '"{}"'.format(args.index)
    }
  )
  getIndexInfoResponse.raise_for_status()
  getIndexInfo = getIndexInfoResponse.json()
  indexId = getIndexInfo['saved_objects'][0]['id'] if (len(getIndexInfo['saved_objects']) > 0) else None
  if debug:
    eprint('Index ID for {} is {}'.format(args.index, indexId))

  if indexId is not None:

    # get the current fields list
    getFieldsResponse = requests.get('{}/{}'.format(args.url, GET_FIELDS_URI),
                                     params={ 'pattern': args.index,
                                              'meta_fields': ["_source","_id","_type","_index","_score"] })
    getFieldsResponse.raise_for_status()
    getFieldsList = getFieldsResponse.json()['fields']
    if debug:
      eprint('{} would have {} fields'.format(args.index, len(getFieldsList)))

    # define field formatting map for Kibana -> Moloch drilldown
    #
    # see: https://github.com/idaholab/Malcolm/issues/133
    #      https://github.com/mmguero-dev/kibana-plugin-drilldownmenu
    #
    # fieldFormatMap is
    #    {
    #        "zeek.orig_h": {
    #            "id": "drilldown",
    #            "params": {
    #                "parsedUrl": {
    #                    "origin": "https://malcolm.local.lan",
    #                    "pathname": "/kibana/app/kibana",
    #                    "basePath": "/kibana"
    #                },
    #                "urlTemplates": [
    #                    null,
    #                    {
    #                        "url": "/idkib2mol/zeek.orig_h == {{value}}",
    #                        "label": "Moloch: zeek.orig_h == {{value}}"
    #                    }
    #                ]
    #            }
    #        },
    #        ...
    #    }
    fieldFormatMap = {}
    for field in getFieldsList:
      if field['name'][:1].isalpha():
        valQuote = '"' if field['type'] == 'string' else ''
        # for Moloch to query by database field name, see moloch issue/PR 1461/1463
        valDbPrefix = '' if field['name'].startswith('zeek') else 'db:'
        drilldownInfoParamsUrlTemplateValues = {}
        drilldownInfoParamsUrlTemplateValues['url'] = '/idkib2mol/{}{} == {}{{{{value}}}}{}'.format(valDbPrefix, field['name'], valQuote, valQuote)
        drilldownInfoParamsUrlTemplateValues['label'] = '🦉: {} == {}{{{{value}}}}{}'.format(field['name'], valQuote, valQuote)
        drilldownInfoParamsUrlTemplates = [None, drilldownInfoParamsUrlTemplateValues]

        drilldownInfoParams = {}
        drilldownInfoParams['urlTemplates'] = drilldownInfoParamsUrlTemplates

        drilldownInfo = {}
        drilldownInfo['id'] = 'drilldown'
        drilldownInfo['params'] = drilldownInfoParams

        fieldFormatMap[field['name']] = drilldownInfo

    # set the index pattern with our complete list of fields
    putIndexInfo = {}
    putIndexInfo['attributes'] = {}
    putIndexInfo['attributes']['title'] = args.index
    putIndexInfo['attributes']['fields'] = json.dumps(getFieldsList)
    putIndexInfo['attributes']['fieldFormatMap'] = json.dumps(fieldFormatMap)

    if not args.dryrun:
      putResponse = requests.put('{}/{}/{}'.format(args.url, PUT_INDEX_PATTERN_URI, indexId),
                                 headers={ 'Content-Type': 'application/json',
                                           'kbn-xsrf': 'true',
                                           'kbn-version': kibanaVersion, },
                                 data=json.dumps(putIndexInfo))
      putResponse.raise_for_status()

    # if we got this far, it probably worked!
    if args.dryrun:
      print("success (dry run only, no write performed)")
    else:
      print("success")

  else:
    print("failure (could not find Index ID for {})".format(args.index))

if __name__ == '__main__':
  main()
