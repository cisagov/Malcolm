#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2024 Battelle Energy Alliance, LLC.  All rights reserved.

import argparse
import itertools
import json
import logging
import os
import pynetbox
import sys
import time

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
        default='http://localhost:8080/netbox',
        required=False,
        help="NetBox Base URL",
    )
    parser.add_argument(
        '-t',
        '--token',
        dest='netboxToken',
        type=str,
        default=None,
        required=False,
        help="NetBox API Token",
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
        threading=True,
    )

    # wait for a good connection
    while args.wait:
        try:
            [x.name for x in nb.dcim.sites.all()]
            break
        except Exception as e:
            logging.info(f"{type(e).__name__}: {e}")
            logging.debug("retrying in a few seconds...")
            time.sleep(5)

    # PERMISSIONS ##################################################################################################
    DEFAULT_PERMISSIONS = {
        f'staff_permissions': {
            'actions': [
                'view',
                'add',
                'change',
                'delete',
            ],
            'exclude_objects': [],
        },
        f'standard_permissions': {
            'actions': [
                'view',
                'add',
                'change',
                'delete',
            ],
            'exclude_objects': [
                'account.usertoken',
                'auth.group',
                'auth.permission',
                'contenttypes.contenttype',
                'core.autosyncrecord',
                'core.configrevision',
                'core.datafile',
                'core.datasource',
                'core.job',
                'core.managedfile',
                'core.objectchange',
                'core.objecttype',
                'db.testmodel',
                'django_rq.queue',
                'social_django.association',
                'social_django.code',
                'social_django.nonce',
                'social_django.partial',
                'social_django.usersocialauth',
                'users.group',
                'users.objectpermission',
                'users.user',
                'users.userconfig',
            ],
        },
    }

    result = {}
    try:
        # get all content types
        result['objects'] = [f'{x.app_label}.{x.model}' for x in nb.extras.object_types.all()]
        result['permissions'] = {}

        # generate the cross-product between the object types and the actions
        for permName, permConfig in {k: v for (k, v) in DEFAULT_PERMISSIONS.items()}.items():
            permConfig['object_types'] = [ct for ct in result['objects'] if ct not in permConfig['exclude_objects']]
            permissionProduct = {
                f"{obj.split('.')[0]}.{action}_{obj.split('.')[1]}": None
                for action, obj in itertools.product(permConfig["actions"], permConfig["object_types"])
            }
            try:
                result['permissions'][permName] = permissionProduct
            except pynetbox.RequestError as nbe:
                logging.warning(f"{type(nbe).__name__} processing permission \"{permName}\": {nbe}")

    except Exception as e:
        logging.error(f"{type(e).__name__} processing permissions: {e}")

    print(json.dumps(result))


###################################################################################################
if __name__ == '__main__':
    main()
