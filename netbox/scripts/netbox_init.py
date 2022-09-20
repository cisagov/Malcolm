#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import json
import logging
import os
import pynetbox
import sys
import time

from slugify import slugify

###################################################################################################
args = None
script_name = os.path.basename(__file__)
script_path = os.path.dirname(os.path.realpath(__file__))
orig_path = os.getcwd()

###################################################################################################
DEFAULT_GROUP_NAMES = (
    'administrator',
    'standard',
)

DEFAULT_PERMISSIONS = {
    'administrator_permission': {
        'name': 'administrator_permission',
        'enabled': True,
        'groups': ['administrator'],
        'actions': [
            'view',
            'add',
            'change',
            'delete',
        ],
        'exclude_objects': [],
    },
    'standard_permission': {
        'name': 'standard_permission',
        'enabled': True,
        'groups': ['standard'],
        'actions': [
            'view',
            'add',
            'change',
            'delete',
        ],
        'exclude_objects': [
            'admin.logentry',
            'auth.group',
            'auth.permission',
            'auth.user',
            'users.admingroup',
            'users.adminuser',
            'users.objectpermission',
            'users.token',
            'users.userconfig',
        ],
    },
}

###################################################################################################
# main
def main():
    global args

    parser = argparse.ArgumentParser(
        description='\n'.join([]),
        formatter_class=argparse.RawTextHelpFormatter,
        add_help=False,
        usage='{} <arguments>'.format(script_name),
    )
    parser.add_argument(
        '--verbose',
        '-v',
        action='count',
        default=1,
        help='Increase verbosity (e.g., -v, -vv, etc.)',
    )
    parser.add_argument(
        '--wait',
        dest='wait',
        action='store_true',
        help='Wait for connection first',
    )
    parser.add_argument(
        '--no-wait',
        dest='wait',
        action='store_false',
        help='Do not wait for connection (error if connection fails)',
    )
    parser.set_defaults(wait=True)
    parser.add_argument(
        '-u',
        '--url',
        dest='netboxUrl',
        type=str,
        default=None,
        required=True,
        help="Netbox Base URL",
    )
    parser.add_argument(
        '-t',
        '--token',
        dest='netboxToken',
        type=str,
        default=None,
        required=True,
        help="Netbox API Token",
    )
    parser.add_argument(
        '-s',
        '--site',
        dest='netboxSites',
        nargs='*',
        type=str,
        default=[os.getenv('NETBOX_DEFAULT_SITE', 'default')],
        required=False,
        help="Site(s) to create",
    )
    try:
        parser.error = parser.exit
        args = parser.parse_args()
    except SystemExit:
        parser.print_help()
        exit(2)

    args.verbose = logging.ERROR - (10 * args.verbose) if args.verbose > 0 else 0
    logging.basicConfig(
        level=args.verbose, format='%(asctime)s %(levelname)s: %(message)s', datefmt='%Y-%m-%d %H:%M:%S'
    )
    logging.debug(os.path.join(script_path, script_name))
    logging.debug("Arguments: {}".format(sys.argv[1:]))
    logging.debug("Arguments: {}".format(args))
    if args.verbose > logging.DEBUG:
        sys.tracebacklimit = 0

    # create connection to netbox API
    nb = pynetbox.api(
        args.netboxUrl,
        token=args.netboxToken,
    )

    # wait for a good connection
    while args.wait:
        try:
            sitesConnTest = [x.name for x in nb.dcim.sites.all()]
            break
        except Exception as e:
            logging.info(f"{type(e).__name__}: {e}")
            logging.debug("retrying in a few seconds...")
            time.sleep(5)

    ###### GROUPS ################################################################################################
    # list existing groups
    groupsPreExisting = [x.name for x in nb.users.groups.all()]
    logging.debug(groupsPreExisting)

    # create groups that don't already exist
    for groupName in DEFAULT_GROUP_NAMES:
        if groupName not in groupsPreExisting:
            nb.users.groups.create({'name': groupName})

    # get existing groups into name->id dictionary
    groupNameIdDict = {x.name: x.id for x in nb.users.groups.all()}
    logging.debug(groupNameIdDict)

    # ###### PERMISSIONS ###########################################################################################
    # get all content types (for creating new permissions)
    allContentTypeNames = [f'{x.app_label}.{x.model}' for x in nb.extras.content_types.all()]

    # get existing permissions
    permsPreExisting = [x.name for x in nb.users.permissions.all()]
    logging.debug(permsPreExisting)

    # create permissions that don't already exist
    for permName, permConfig in DEFAULT_PERMISSIONS.items():
        if 'name' in permConfig and permConfig['name'] not in permsPreExisting:
            permConfig['groups'] = [groupNameIdDict[x] for x in permConfig['groups']]
            permConfig['object_types'] = [ct for ct in allContentTypeNames if ct not in permConfig['exclude_objects']]
            permConfig.pop('exclude_objects', None)
            nb.users.permissions.create(permConfig)

    logging.debug([x.name for x in nb.users.permissions.all()])

    # ###### PERMISSIONS ###########################################################################################
    # get existing sites
    sitesPreExisting = [x.name for x in nb.dcim.sites.all()]
    logging.debug(sitesPreExisting)

    # create sites that don't already exist
    for siteName in args.netboxSites:
        if siteName not in sitesPreExisting:
            nb.dcim.sites.create(
                {
                    "name": siteName,
                    "slug": slugify(siteName),
                },
            )

    logging.debug([f'{x.name} ({x.slug})' for x in nb.dcim.sites.all()])


###################################################################################################
if __name__ == '__main__':
    main()
