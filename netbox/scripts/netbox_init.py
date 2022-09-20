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
        default='http://localhost:8080/assets',
        required=True,
        help="NetBox Base URL",
    )
    parser.add_argument(
        '-t',
        '--token',
        dest='netboxToken',
        type=str,
        default=None,
        required=True,
        help="NetBox API Token",
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
    parser.add_argument(
        '--default-group',
        dest='defaultGroupName',
        type=str,
        default=os.getenv('REMOTE_AUTH_DEFAULT_GROUPS', 'standard'),
        required=False,
        help="Name of default group for automatic NetBox user creation",
    )
    parser.add_argument(
        '--staff-group',
        dest='staffGroupName',
        type=str,
        default=os.getenv('REMOTE_AUTH_STAFF_GROUPS', 'administrator'),
        required=False,
        help="Name of staff group for automatic NetBox user creation",
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
    DEFAULT_GROUP_NAMES = (
        args.staffGroupName,
        args.defaultGroupName,
    )

    try:
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
    except Exception as e:
        logging.error(f"{type(e).__name__} processing groups: {e}")

    ####### PERMISSIONS ###########################################################################################
    DEFAULT_PERMISSIONS = {
        f'{args.staffGroupName}_permission': {
            'name': f'{args.staffGroupName}_permission',
            'enabled': True,
            'groups': [args.staffGroupName],
            'actions': [
                'view',
                'add',
                'change',
                'delete',
            ],
            'exclude_objects': [],
        },
        f'{args.defaultGroupName}_permission': {
            'name': f'{args.defaultGroupName}_permission',
            'enabled': True,
            'groups': [args.defaultGroupName],
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

    try:
        # get all content types (for creating new permissions)
        allContentTypeNames = [f'{x.app_label}.{x.model}' for x in nb.extras.content_types.all()]

        # get existing permissions
        permsPreExisting = [x.name for x in nb.users.permissions.all()]
        logging.debug(permsPreExisting)

        # create permissions that don't already exist
        for permName, permConfig in DEFAULT_PERMISSIONS.items():
            if 'name' in permConfig and permConfig['name'] not in permsPreExisting:
                permConfig['groups'] = [groupNameIdDict[x] for x in permConfig['groups']]
                permConfig['object_types'] = [
                    ct for ct in allContentTypeNames if ct not in permConfig['exclude_objects']
                ]
                permConfig.pop('exclude_objects', None)
                nb.users.permissions.create(permConfig)

        logging.debug([x.name for x in nb.users.permissions.all()])
    except Exception as e:
        logging.error(f"{type(e).__name__} processing permissions: {e}")

    # ###### PERMISSIONS ###########################################################################################
    # get existing sites
    try:
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
    except Exception as e:
        logging.error(f"{type(e).__name__} processing sites: {e}")


###################################################################################################
if __name__ == '__main__':
    main()
