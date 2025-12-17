#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2025 Battelle Energy Alliance, LLC.  All rights reserved.

import argparse
import json
import logging
import malcolm_utils
import re
import requests
import os
import sys
import urllib3

from collections import defaultdict
from requests.auth import HTTPBasicAuth
from urllib.parse import urlparse
from malcolm_constants import DatabaseMode

GET_COMPONENT_TEMPLATE_URI = '_component_template'
GET_INDEX_TEMPLATE_URI = '_index_template'
GET_SHARDS_URL = '_cat/shards?h=index,state'
GET_STATUS_API = 'api/status'
KIBANA_DATA_VIEWS_URI = 'api/data_views'
KIBANA_DATA_VIEW_URI = f'{KIBANA_DATA_VIEWS_URI}/data_view'
OPENSEARCH_GET_FIELDS_URI = 'api/index_patterns/_fields_for_wildcard'
OPENSEARCH_GET_INDEX_PATTERN_INFO_URI = 'api/saved_objects/_find'
OPENSEARCH_INDEX_PATTERN_URI = 'api/saved_objects/index-pattern'
SHARD_UNASSIGNED_STATUS = 'UNASSIGNED'
NETBOX_URL_DEFAULT = 'http://netbox:8080/netbox'

###################################################################################################
script_name = os.path.basename(__file__)
script_path = os.path.dirname(os.path.realpath(__file__))
origPath = os.getcwd()
urllib3.disable_warnings()


def parse_args():
    parser = argparse.ArgumentParser(description=script_name, add_help=True, usage=f'{script_name} <arguments>')
    parser.add_argument(
        '--verbose',
        '-v',
        action='count',
        default=malcolm_utils.get_verbosity_env_var_count("VERBOSITY"),
        help='Increase verbosity (e.g., -v, -vv, etc.)',
    )
    parser.add_argument(
        '-i',
        '--index',
        dest='index',
        metavar='<str>',
        type=str,
        default=os.getenv('MALCOLM_NETWORK_INDEX_PATTERN', 'arkime_sessions3-*'),
        help='Index Pattern Name',
    )
    parser.add_argument(
        '-d',
        '--dashboards',
        dest='dashboards_url',
        metavar='<protocol://host:port>',
        type=str,
        default=os.getenv('DASHBOARDS_URL', 'http://dashboards:5601/dashboards'),
        help='Dashboards URL',
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
        '-m',
        '--malcolm',
        dest='malcolm_url',
        metavar='<protocol://host:port>',
        type=str,
        default=os.getenv('MALCOLM_URL', ''),
        help='Malcolm URL (only used for --opensearch-mode elasticsearch-remote)',
    )
    parser.add_argument(
        '-b',
        '--netbox-url',
        dest='netbox_url',
        metavar='<protocol://host:port>',
        type=str,
        default=os.getenv('NETBOX_URL') or NETBOX_URL_DEFAULT,
        help='NetBox URL',
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
        type=malcolm_utils.str2bool,
        nargs='?',
        const=True,
        default=malcolm_utils.str2bool(os.getenv('OPENSEARCH_SSL_CERTIFICATE_VERIFICATION', default='False')),
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
                default=malcolm_utils.DatabaseModeEnumToStr(DatabaseMode.OpenSearchLocal),
            )
        ),
        required=False,
    )
    parser.add_argument(
        '-t',
        '--template',
        dest='template',
        metavar='<str>',
        type=str,
        default=None,
        help='OpenSearch template to merge',
    )
    parser.add_argument(
        '-u',
        '--unassigned',
        dest='fix_unassigned',
        type=malcolm_utils.str2bool,
        nargs='?',
        const=True,
        default=False,
        help="Set number_of_replicas for unassigned index shards to 0",
    )
    parser.add_argument(
        '-n',
        '--dry-run',
        dest='dryrun',
        type=malcolm_utils.str2bool,
        nargs='?',
        const=True,
        default=False,
        help="Dry run (no PUT)",
    )
    try:
        args = parser.parse_args()
    except SystemExit as e:
        if e.code == 2:
            parser.print_help()
        sys.exit(e.code)
    return args


def make_session(xsrf_header, verify_ssl=False, auth=None):
    session = requests.Session()
    session.auth = auth
    session.verify = verify_ssl
    session.headers.update(
        {
            'Content-Type': 'application/json',
            xsrf_header: 'true',
        }
    )

    return session


def setup_environment(args):
    args.verbose = malcolm_utils.set_logging(os.getenv("LOGLEVEL", ""), args.verbose, set_traceback_limit=True)
    opensearch_creds = malcolm_utils.ParseCurlFile(args.opensearch_curl_rc_file)

    if args.opensearch_mode == DatabaseMode.ElasticsearchRemote and args.malcolm_url:
        args.malcolm_url = malcolm_utils.remove_suffix(args.malcolm_url, '/')
    else:
        args.malcolm_url = ''

    args.netbox_url = malcolm_utils.remove_suffix(malcolm_utils.remove_suffix(args.netbox_url, '/'), '/api')
    if args.netbox_url == NETBOX_URL_DEFAULT:
        if args.opensearch_mode == DatabaseMode.ElasticsearchRemote:
            if args.malcolm_url:
                args.netbox_url = f'{args.malcolm_url}/netbox'
            else:
                args.netbox_url = None
        else:
            args.netbox_url = '/netbox'

    opensearch_is_local = (
        args.opensearch_mode == DatabaseMode.OpenSearchLocal or args.opensearch_url == 'https://opensearch:9200'
    )

    if not args.opensearch_url:
        if opensearch_is_local:
            args.opensearch_url = 'https://opensearch:9200'
        elif 'url' in opensearch_creds:
            args.opensearch_url = opensearch_creds['url']

    # if they actually just specified the name of the environment variable, resolve that for the index name
    if args.index.startswith('MALCOLM_'):
        args.index = os.getenv(args.index, '')

    return args, make_session(
        "kbn-xsrf" if args.opensearch_mode == DatabaseMode.ElasticsearchRemote else "osd-xsrf",
        args.opensearch_ssl_verify,
        (
            HTTPBasicAuth(opensearch_creds['user'], opensearch_creds['password'])
            if opensearch_creds['user'] is not None
            else None
        ),
    )


def get_versions(args, session):
    dashboards_ver = session.get(f"{args.dashboards_url}/{GET_STATUS_API}").json()["version"]["number"]
    logging.info(f"Dashboards version is {dashboards_ver}")

    opensearch_ver = session.get(args.opensearch_url).json()["version"]["number"]
    logging.info(f"OpenSearch version is {opensearch_ver}")

    return dashboards_ver, opensearch_ver


def get_index_id(args, session):
    index_id = None

    if args.opensearch_mode == DatabaseMode.ElasticsearchRemote:
        resp = session.get(f"{args.dashboards_url}/{KIBANA_DATA_VIEWS_URI}")
        resp.raise_for_status()
        for dv in resp.json().get("data_view", []):
            if (dv.get("title") == args.index) and (index_id := dv["id"]):
                break

    else:
        resp = session.get(
            f"{args.dashboards_url}/{OPENSEARCH_GET_INDEX_PATTERN_INFO_URI}",
            params={'type': 'index-pattern', 'fields': 'id', 'search': f'"{args.index}"'},
        )
        resp.raise_for_status()
        data = resp.json()
        index_id = data['saved_objects'][0]['id'] if data['saved_objects'] else None

    if index_id:
        logging.info(f'Index ID for {args.index} is {index_id}')
        return index_id
    else:
        raise ValueError(f"Could not get index ID for {args.index}")


def kibana_fields_to_opensearch_format(kibana_fields: dict):
    fields_out = []
    for name, info in kibana_fields.items():
        fields_out.append(
            {
                "name": name,
                "type": info.get("type"),
                "esTypes": info.get("esTypes") or [],
                "searchable": info.get("searchable", False),
                "aggregatable": info.get("aggregatable", False),
                "readFromDocValues": info.get("readFromDocValues", False),
            }
        )
    return fields_out


def get_fields_list(args, session, index_id):
    if args.opensearch_mode == DatabaseMode.ElasticsearchRemote:
        resp = session.get(f"{args.dashboards_url}/{KIBANA_DATA_VIEW_URI}/{index_id}")
        resp.raise_for_status()
        result = kibana_fields_to_opensearch_format(malcolm_utils.deep_get(resp.json(), ['data_view', 'fields'], {}))
    else:
        resp = session.get(
            f"{args.dashboards_url}/{OPENSEARCH_GET_FIELDS_URI}",
            params={'pattern': args.index, 'meta_fields': ["_source", "_id", "_type", "_index", "_score"]},
        )
        resp.raise_for_status()
        result = malcolm_utils.deep_get(resp.json(), ['fields'], [])

    return result


def merge_template_fields(args, session, fields):
    if not args.template:
        return fields

    try:
        # request template from OpenSearch and pull the mappings/properties (field list) out
        get_template_response = session.get(f"{args.opensearch_url}/{GET_INDEX_TEMPLATE_URI}/{args.template}")
        get_template_response.raise_for_status()
        template_json = get_template_response.json()

        fields_names = {f['name'] for f in fields if 'name' in f}
        merge_field_types = {"date", "float", "integer", "ip", "keyword", "long", "short", "text"}

        for template in template_json.get('index_templates', []):
            template_fields = malcolm_utils.deep_get(
                template, ['index_template', 'template', 'mappings', 'properties'], default={}
            )

            # also include fields from component templates into template_fields before processing
            # https://opensearch.org/docs/latest/opensearch/index-templates/#composable-index-templates
            for component_name in malcolm_utils.deep_get(template, ['index_template', 'composed_of'], default=[]):
                comp_resp = session.get(f"{args.opensearch_url}/{GET_COMPONENT_TEMPLATE_URI}/{component_name}")
                comp_resp.raise_for_status()
                comp_json = comp_resp.json()
                for component in comp_json.get('component_templates', []):
                    props = malcolm_utils.deep_get(
                        component, ['component_template', 'template', 'mappings', 'properties'], default={}
                    )
                    if props:
                        template_fields.update(props)

            # merge fields
            for name, meta in template_fields.items():
                # a field should be merged if it's not already in the list we have from Dashboards, and it's
                # in the list of types we're merging (leave more complex types like nested and geolocation
                # to be handled naturally as the data shows up)
                if name not in fields_names and meta.get('type') in merge_field_types:
                    mapped_type = (
                        'number'
                        if meta['type'] in {'float', 'integer', 'long', 'short'}
                        else 'string' if meta['type'] in {'keyword', 'text'} else meta['type']
                    )
                    # create field dict in same format as those returned by GET_FIELDS_URI
                    fields.append(
                        {
                            'name': name,
                            'esTypes': [meta['type']],
                            'type': mapped_type,
                            'searchable': True,
                            'aggregatable': "text" not in meta['type'],
                            'readFromDocValues': "text" not in meta['type'],
                        }
                    )
                    fields_names.add(name)

        return fields

    except Exception as e:
        logging.exception(f'"{e}" raised for "{args.template}", skipping template merge')
        return fields


def get_prev_field_format_map(args, session, index_id):
    if args.opensearch_mode == DatabaseMode.ElasticsearchRemote:
        resp = session.get(f"{args.dashboards_url}/{KIBANA_DATA_VIEW_URI}/{index_id}")
        resp.raise_for_status()
        return malcolm_utils.deep_get(resp.json(), ['data_view', 'fieldFormats'], {})
    else:
        resp = session.get('{}/{}/{}'.format(args.dashboards_url, OPENSEARCH_INDEX_PATTERN_URI, index_id))
        resp.raise_for_status()
        return malcolm_utils.LoadStrIfJson(
            malcolm_utils.deep_get(resp.json(), ['attributes', 'fieldFormatMap'], default="{}"), default={}
        )


def build_field_format_map(args, fields, prev_field_format_map):
    # fieldFormatMap is
    #    {
    #        "destination.port": {
    #           "id": "url",
    #           "params": {
    #             "urlTemplate": "https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml?search={{value}}",
    #             "labelTemplate": "{{value}}",
    #             "openLinkInCurrentTab": false
    #           }
    #        },
    #        ...
    #    }

    pivot_ignore_types = ['date']
    format_map = prev_field_format_map or {}

    def netbox_url(path):
        return f'{args.netbox_url}{path}' if args.netbox_url else ''

    # mapping of fields (by suffixes or exact names) -> urlTemplate
    field_map = {
        # suffixes
        '.segment.id': lambda: netbox_url('/ipam/prefixes/{{value}}'),
        '.segment.name': lambda: netbox_url('/search/?q={{value}}&obj_types=ipam.prefix&lookup=iexact'),
        '.segment.tenant': lambda: netbox_url('/search/?q={{value}}&obj_types=tenancy.tenant&lookup=iexact'),
        '.device.id': lambda: netbox_url('/dcim/devices/{{value}}'),
        '.device.name': lambda: netbox_url(
            '/search/?q={{value}}&obj_types=dcim.device&obj_types=virtualization.virtualmachine&lookup=iexact'
        ),
        '.device.cluster': lambda: netbox_url('/search/?q={{value}}&obj_types=virtualization.cluster&lookup=iexact'),
        '.device.device_type': lambda: netbox_url('/search/?q={{value}}&obj_types=dcim.devicetype'),
        '.device.manufacturer': lambda: netbox_url('/search/?q={{value}}&obj_types=dcim.manufacturer'),
        '.device.role': lambda: netbox_url('/search/?q={{value}}&obj_types=dcim.devicerole'),
        '.device.service': lambda: netbox_url('/search/?q={{value}}&obj_types=ipam.service'),
        '.device.site': lambda: netbox_url('/search/?q={{value}}&obj_types=dcim.site&lookup=iexact'),
        '.segment.site': lambda: netbox_url('/search/?q={{value}}&obj_types=dcim.site&lookup=iexact'),
        '.reference': lambda: '/refred/{{value}}',
        # exact matches
        'network.name': lambda: netbox_url('/search/?q={{value}}&obj_types=ipam.prefix&lookup=iexact'),
        'related.device_id': lambda: netbox_url('/dcim/devices/{{value}}'),
        'related.device_name': lambda: netbox_url(
            '/search/?q={{value}}&obj_types=dcim.device&obj_types=virtualization.virtualmachine&lookup=iexact'
        ),
        'related.device_type': lambda: netbox_url('/search/?q={{value}}&obj_types=dcim.devicetype'),
        'related.manufacturer': lambda: netbox_url('/search/?q={{value}}&obj_types=dcim.manufacturer'),
        'related.role': lambda: netbox_url('/search/?q={{value}}&obj_types=dcim.devicerole'),
        'related.service': lambda: netbox_url('/search/?q={{value}}&obj_types=ipam.service'),
        'related.site': lambda: netbox_url('/search/?q={{value}}&obj_types=dcim.site&lookup=iexact'),
        'zeek.files.extracted_uri': lambda: (
            (args.malcolm_url + '/{{rawValue}}')
            if (args.malcolm_url or (args.opensearch_mode != DatabaseMode.ElasticsearchRemote))
            else ''
        ),
    }
    field_map = {k: v for k, v in field_map.items() if v()}

    for f in [
        x
        for x in fields
        if x['name'][:1].isalpha() and (x['name'] not in format_map) and (x['type'] not in pivot_ignore_types)
    ]:
        name = f['name']
        fmt = {'id': 'url', 'params': {'labelTemplate': '{{value}}', 'openLinkInCurrentTab': False}}

        # lookup by exact name or suffix
        template_func = field_map.get(name) or next(
            (fn for suffix, fn in field_map.items() if name.endswith(suffix)), None
        )
        if template_func:
            fmt['params']['urlTemplate'] = template_func()
        elif args.malcolm_url or (args.opensearch_mode != DatabaseMode.ElasticsearchRemote):
            # for Arkime to query by database field name, see arkime issue/PR 1461/1463
            val_quote = '"' if f['type'] == 'string' else ''
            prefix = '' if name.startswith(('zeek', 'suricata')) else 'db:'
            fmt['params'][
                'urlTemplate'
            ] = f'{args.malcolm_url}/iddash2ark/{prefix}{name} == {val_quote}{{{{value}}}}{val_quote}'
        else:
            continue

        format_map[name] = fmt

    return format_map


def update_dashboard_index_pattern(args, session, index_id, fields, field_format_map):
    if args.opensearch_mode == DatabaseMode.ElasticsearchRemote:
        payload = {
            'data_view': {
                'title': args.index,
                'fieldFormats': field_format_map,
            }
        }
        resp = session.post(f"{args.dashboards_url}/{KIBANA_DATA_VIEW_URI}/{index_id}", json=payload)
        resp.raise_for_status()
    else:
        payload = {
            'attributes': {
                'title': args.index,
                'fields': json.dumps(fields),
                'fieldFormatMap': json.dumps(field_format_map),
            }
        }
        resp = session.put(f"{args.dashboards_url}/{OPENSEARCH_INDEX_PATTERN_URI}/{index_id}", data=json.dumps(payload))
        resp.raise_for_status()


def fix_unassigned_shards(args, session):
    resp = session.get(f"{args.opensearch_url}/{GET_SHARDS_URL}")
    for line in resp.iter_lines():
        shard_info = line.decode('utf-8').split()
        if len(shard_info) == 2 and shard_info[1] == SHARD_UNASSIGNED_STATUS:
            put_response = session.put(
                f"{args.opensearch_url}/{shard_info[0]}/_settings",
                data=json.dumps({'index': {'number_of_replicas': 0}}),
            )
            put_response.raise_for_status()


###################################################################################################
# main
def main():
    args = parse_args()
    args, session = setup_environment(args)
    get_versions(args, session)

    logging.debug(os.path.join(script_path, script_name))
    logging.debug(f"Arguments: {sys.argv[1:]}")
    logging.debug(f"Arguments: {args}")

    # find the ID of the index name (probably will be the same as the name)
    index_id = get_index_id(args, session)
    # get the current fields list
    fields = get_fields_list(args, session, index_id)
    # get the fields from the template, if specified, and merge those into the fields list
    fields = merge_template_fields(args, session, fields)
    logging.info(f'{args.index} would have {len(fields)} fields')

    # define field formatting map for Dashboards -> Arkime drilldown and other URL drilldowns
    field_format_map = build_field_format_map(args, fields, get_prev_field_format_map(args, session, index_id))

    if not args.dryrun:
        # set the index pattern with our complete list of fields
        update_dashboard_index_pattern(args, session, index_id, fields, field_format_map)
        logline = "success"
    else:
        logline = "success (dry run only, no write performed)"
    logging.info(logline)
    print(logline)

    if args.opensearch_mode == DatabaseMode.OpenSearchLocal and args.fix_unassigned and not args.dryrun:
        # set some configuration-related indexes' (e.g., opensearch/opendistro) replica count to 0
        # so we don't have yellow index state on those
        fix_unassigned_shards(args, session)


if __name__ == '__main__':
    try:
        main()
    except Exception as e:
        logging.exception(f"Unexpected error: {e}")
        sys.exit(1)
