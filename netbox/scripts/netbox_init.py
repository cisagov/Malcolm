#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2023 Battelle Energy Alliance, LLC.  All rights reserved.

import argparse
import ipaddress
import itertools
import json
import logging
import os
import pynetbox
import randomcolor
import re
import sys
import time
import malcolm_utils

from collections.abc import Iterable
from datetime import datetime
from slugify import slugify
from netbox_library_import import import_library

###################################################################################################
args = None
script_name = os.path.basename(__file__)
script_path = os.path.dirname(os.path.realpath(__file__))
orig_path = os.getcwd()


###################################################################################################
def get_iterable(x):
    if isinstance(x, Iterable) and not isinstance(x, str):
        return x
    else:
        return (x,)


def is_ip_address(x):
    try:
        ipaddress.ip_address(x)
        return True
    except Exception:
        return False


def is_ip_v4_address(x):
    try:
        ipaddress.IPv4Address(x)
        return True
    except Exception:
        return False


def is_ip_v6_address(x):
    try:
        ipaddress.IPv6Address(x)
        return True
    except Exception:
        return False


def is_ip_network(x):
    try:
        ipaddress.ip_network(x)
        return True
    except Exception:
        return False


def min_hash_value_by_value(x):
    return next(
        iter(list({k: v for k, v in sorted(x.items(), key=lambda item: item[1])}.values())),
        None,
    )


def min_hash_value_by_key(x):
    return next(
        iter(list({k: v for k, v in sorted(x.items(), key=lambda item: item[0])}.values())),
        None,
    )


def max_hash_value_by_value(x):
    try:
        *_, last = iter(list({k: v for k, v in sorted(x.items(), key=lambda item: item[1])}.values()))
    except Exception:
        last = None
    return last


def max_hash_value_by_key(x):
    try:
        *_, last = iter(list({k: v for k, v in sorted(x.items(), key=lambda item: item[0])}.values()))
    except Exception:
        last = None
    return last


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
        '--net-map',
        dest='netMapFileName',
        type=str,
        default=None,
        required=False,
        help="Filename of JSON file containing network subnet/host name mapping",
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
    parser.add_argument(
        '-m',
        '--manufacturer',
        dest='manufacturers',
        nargs='*',
        type=str,
        default=[os.getenv('NETBOX_DEFAULT_MANUFACTURER', 'Unspecified')],
        required=False,
        help="Manufacturers to create",
    )
    parser.add_argument(
        '-r',
        '--role',
        dest='roles',
        nargs='*',
        type=str,
        default=[os.getenv('NETBOX_DEFAULT_ROLE', 'Unspecified')],
        required=False,
        help="Role(s) to create",
    )
    parser.add_argument(
        '-y',
        '--device-type',
        dest='deviceTypes',
        nargs='*',
        type=str,
        default=[os.getenv('NETBOX_DEFAULT_DEVICE_TYPE', 'Unspecified')],
        required=False,
        help="Device types(s) to create",
    )
    parser.add_argument(
        '-n',
        '--netbox',
        dest='netboxDir',
        type=str,
        default=os.getenv('NETBOX_PATH', '/opt/netbox'),
        required=False,
        help="NetBox installation directory",
    )
    parser.add_argument(
        '-l',
        '--library',
        dest='libraryDir',
        type=str,
        default=os.getenv('NETBOX_DEVICETYPE_LIBRARY_PATH', '/opt/netbox-devicetype-library'),
        required=False,
        help="Directory containing NetBox device type library",
    )
    parser.add_argument(
        '-p',
        '--preload',
        dest='preloadDir',
        type=str,
        default=os.getenv('NETBOX_PRELOAD_PATH', '/opt/netbox-preload'),
        required=False,
        help="Directory containing netbox-initializers files to preload",
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
    sites = {}
    groups = {}
    permissions = {}
    vrfs = {}
    prefixes = {}
    devices = {}
    interfaces = {}
    ipAddresses = {}
    deviceTypes = {}
    roles = {}
    manufacturers = {}
    randColor = randomcolor.RandomColor(seed=datetime.now().timestamp())

    # wait for a good connection
    while args.wait:
        try:
            [x.name for x in nb.dcim.sites.all()]
            break
        except Exception as e:
            logging.info(f"{type(e).__name__}: {e}")
            logging.debug("retrying in a few seconds...")
            time.sleep(5)

    # GROUPS #####################################################################################################
    DEFAULT_GROUP_NAMES = (
        args.staffGroupName,
        args.defaultGroupName,
    )

    try:
        groupsPreExisting = {x.name: x for x in nb.users.groups.all()}
        logging.debug(f"groups (before): { {k:v.id for k, v in groupsPreExisting.items()} }")

        # create groups that don't already exist
        for groupName in [x for x in DEFAULT_GROUP_NAMES if x not in groupsPreExisting]:
            try:
                nb.users.groups.create({'name': groupName})
            except pynetbox.RequestError as nbe:
                logging.warning(f"{type(nbe).__name__} processing group \"{groupName}\": {nbe}")

        groups = {x.name: x for x in nb.users.groups.all()}
        logging.debug(f"groups (after): { {k:v.id for k, v in groups.items()} }")
    except Exception as e:
        logging.error(f"{type(e).__name__} processing groups: {e}")

    # PERMISSIONS ##################################################################################################
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

        permsPreExisting = {x.name: x for x in nb.users.permissions.all()}
        logging.debug(f"permissions (before): { {k:v.id for k, v in permsPreExisting.items()} }")

        # create permissions that don't already exist
        for permName, permConfig in {
            k: v for (k, v) in DEFAULT_PERMISSIONS.items() if v.get('name', None) and v['name'] not in permsPreExisting
        }.items():
            permConfig['groups'] = [groups[x].id for x in permConfig['groups']]
            permConfig['object_types'] = [ct for ct in allContentTypeNames if ct not in permConfig['exclude_objects']]
            permConfig.pop('exclude_objects', None)
            try:
                nb.users.permissions.create(permConfig)
            except pynetbox.RequestError as nbe:
                logging.warning(f"{type(nbe).__name__} processing permission \"{permConfig['name']}\": {nbe}")

        permissions = {x.name: x for x in nb.users.permissions.all()}
        logging.debug(f"permissions (after): { {k:v.id for k, v in permissions.items()} }")
    except Exception as e:
        logging.error(f"{type(e).__name__} processing permissions: {e}")

    # ###### MANUFACTURERS #########################################################################################
    try:
        manufacturersPreExisting = {x.name: x for x in nb.dcim.manufacturers.all()}
        logging.debug(f"Manufacturers (before): { {k:v.id for k, v in manufacturersPreExisting.items()} }")

        # create manufacturers that don't already exist
        for manufacturerName in [x for x in args.manufacturers if x not in manufacturersPreExisting]:
            try:
                nb.dcim.manufacturers.create(
                    {
                        "name": manufacturerName,
                        "slug": slugify(manufacturerName),
                    },
                )
            except pynetbox.RequestError as nbe:
                logging.warning(f"{type(nbe).__name__} processing manufacturer \"{manufacturerName}\": {nbe}")

        manufacturers = {x.name: x for x in nb.dcim.manufacturers.all()}
        logging.debug(f"Manufacturers (after): { {k:v.id for k, v in manufacturers.items()} }")
    except Exception as e:
        logging.error(f"{type(e).__name__} processing manufacturers: {e}")

    # ###### ROLES #################################################################################################
    try:
        rolesPreExisting = {x.name: x for x in nb.dcim.device_roles.all()}
        logging.debug(f"Roles (before): { {k:v.id for k, v in rolesPreExisting.items()} }")

        # create roles that don't already exist
        for roleName in [x for x in args.roles if x not in rolesPreExisting]:
            try:
                nb.dcim.device_roles.create(
                    {
                        "name": roleName,
                        "slug": slugify(roleName),
                        "vm_role": True,
                        "color": randColor.generate()[0][1:],
                    },
                )
            except pynetbox.RequestError as nbe:
                logging.warning(f"{type(nbe).__name__} processing role \"{roleName}\": {nbe}")

        roles = {x.name: x for x in nb.dcim.device_roles.all()}
        logging.debug(f"Roles (after): { {k:v.id for k, v in roles.items()} }")
    except Exception as e:
        logging.error(f"{type(e).__name__} processing roles: {e}")

    # ###### DEVICE TYPES ##########################################################################################
    try:
        deviceTypesPreExisting = {x.model: x for x in nb.dcim.device_types.all()}
        logging.debug(f"Device types (before): { {k:v.id for k, v in deviceTypesPreExisting.items()} }")

        # create device types that don't already exist
        for deviceTypeModel in [x for x in args.deviceTypes if x not in deviceTypesPreExisting]:
            try:
                manuf = min_hash_value_by_value(manufacturers)
                nb.dcim.device_types.create(
                    {
                        "model": deviceTypeModel,
                        "slug": slugify(deviceTypeModel),
                        "manufacturer": manuf.id if manuf else None,
                    },
                )
            except pynetbox.RequestError as nbe:
                logging.warning(f"{type(nbe).__name__} processing device type \"{deviceTypeModel}\": {nbe}")

        deviceTypes = {x.model: x for x in nb.dcim.device_types.all()}
        logging.debug(f"Device types (after): { {k:v.id for k, v in deviceTypes.items()} }")
    except Exception as e:
        logging.error(f"{type(e).__name__} processing device types: {e}")

    # ###### SITES #################################################################################################
    try:
        sitesPreExisting = {x.name: x for x in nb.dcim.sites.all()}
        logging.debug(f"sites (before): { {k:v.id for k, v in sitesPreExisting.items()} }")

        # create sites that don't already exist
        for siteName in [x for x in args.netboxSites if x not in sitesPreExisting]:
            try:
                nb.dcim.sites.create(
                    {
                        "name": siteName,
                        "slug": slugify(siteName),
                    },
                )
            except pynetbox.RequestError as nbe:
                logging.warning(f"{type(nbe).__name__} processing site \"{siteName}\": {nbe}")

        sites = {x.name: x for x in nb.dcim.sites.all()}
        logging.debug(f"sites (after): { {k:v.id for k, v in sites.items()} }")
    except Exception as e:
        logging.error(f"{type(e).__name__} processing sites: {e}")

    # ###### Net Map ###############################################################################################
    try:
        # load net-map.json from file
        netMapJson = None
        if args.netMapFileName is not None and os.path.isfile(args.netMapFileName):
            with open(args.netMapFileName) as f:
                netMapJson = json.load(f)
        if netMapJson is not None:
            # create new VRFs
            vrfPreExisting = {x.name: x for x in nb.ipam.vrfs.all()}
            logging.debug(f"VRFs (before): { {k:v.id for k, v in vrfPreExisting.items()} }")

            for segment in [
                x
                for x in get_iterable(netMapJson)
                if isinstance(x, dict)
                and (x.get('type', '') == "segment")
                and x.get('name', None)
                and is_ip_network(x.get('address', None))
                and x['name'] not in vrfPreExisting
            ]:
                try:
                    nb.ipam.vrfs.create(
                        {
                            "name": segment['name'],
                            "enforce_unique": True,
                        },
                    )
                except pynetbox.RequestError as nbe:
                    logging.warning(f"{type(nbe).__name__} processing VRF \"{segment['name']}\": {nbe}")

            vrfs = {x.name: x for x in nb.ipam.vrfs.all()}
            logging.debug(f"VRFs (after): { {k:v.id for k, v in vrfs.items()} }")

            # create prefixes in VRFs

            prefixesPreExisting = {x.prefix: x for x in nb.ipam.prefixes.all()}
            logging.debug(f"prefixes (before): { {k:v.id for k, v in prefixesPreExisting.items()} }")

            for segment in [
                x
                for x in get_iterable(netMapJson)
                if isinstance(x, dict)
                and (x.get('type', '') == "segment")
                and x.get('name', None)
                and is_ip_network(x.get('address', None))
                and x['name'] in vrfs
            ]:
                try:
                    site = min_hash_value_by_value(sites)
                    nb.ipam.prefixes.create(
                        {
                            "prefix": segment['address'],
                            "site": site.id if site else None,
                            "vrf": vrfs[segment['name']].id,
                        },
                    )
                except pynetbox.RequestError as nbe:
                    logging.warning(
                        f"{type(nbe).__name__} processing prefix \"{segment['address']}\" (\"{segment['name']}\"): {nbe}"
                    )

            prefixes = {x.prefix: x for x in nb.ipam.prefixes.all()}
            logging.debug(f"prefixes (after): { {k:v.id for k, v in prefixes.items()} }")

            # create hosts as devices
            devicesPreExisting = {x.name: x for x in nb.dcim.devices.all()}
            logging.debug(f"devices (before): { {k:v.id for k, v in devicesPreExisting.items()} }")

            for host in [
                x
                for x in get_iterable(netMapJson)
                if isinstance(x, dict)
                and (x.get('type', '') == "host")
                and x.get('name', None)
                and x.get('address', None)
                and x['name'] not in devicesPreExisting
            ]:
                try:
                    site = min_hash_value_by_value(sites)
                    dType = min_hash_value_by_value(deviceTypes)
                    role = min_hash_value_by_value(roles)
                    deviceCreated = nb.dcim.devices.create(
                        {
                            "name": host['name'],
                            "site": site.id if site else None,
                            "device_type": dType.id if dType else None,
                            "role": role.id if role else None,
                        },
                    )
                    if deviceCreated is not None:
                        # create interface for the device
                        if is_ip_address(host['address']):
                            hostVrf = max_hash_value_by_key(
                                {
                                    ipaddress.ip_network(k): v
                                    for k, v in prefixes.items()
                                    if ipaddress.ip_address(host['address']) in ipaddress.ip_network(k)
                                }
                            )
                            nb.dcim.interfaces.create(
                                {
                                    "device": deviceCreated.id,
                                    "name": "default",
                                    "type": "other",
                                    "vrf": hostVrf.id if hostVrf else None,
                                },
                            )
                        elif re.match(r'^([0-9a-f]{2}[:-]){5}([0-9a-f]{2})$', host['address'].lower()):
                            nb.dcim.interfaces.create(
                                {
                                    "device": deviceCreated.id,
                                    "name": "default",
                                    "type": "other",
                                    "mac_address": host['address'].lower(),
                                },
                            )

                except pynetbox.RequestError as nbe:
                    logging.warning(f"{type(nbe).__name__} processing device \"{host['name']}\": {nbe}")

            devices = {x.name: x for x in nb.dcim.devices.all()}
            logging.debug(f"devices (after): { {k:v.id for k, v in devices.items()} }")
            interfaces = {x.device.id: x for x in nb.dcim.interfaces.all()}
            logging.debug(f"interfaces (after): { {k:v.id for k, v in interfaces.items()} }")

            # and associate IP addresses with them
            ipAddressesPreExisting = {f"{x.address}:{x.vrf.id if x.vrf else ''}": x for x in nb.ipam.ip_addresses.all()}
            logging.debug(f"IP addresses (before): { {k:v.id for k, v in ipAddressesPreExisting.items()} }")

            for host in [
                x
                for x in get_iterable(netMapJson)
                if isinstance(x, dict)
                and (x.get('type', '') == "host")
                and x.get('name', None)
                and is_ip_address(x.get('address', None))
                and x['name'] in devices
            ]:
                try:
                    hostVrf = max_hash_value_by_key(
                        {
                            ipaddress.ip_network(k): v
                            for k, v in prefixes.items()
                            if ipaddress.ip_address(host['address']) in ipaddress.ip_network(k)
                        }
                    )
                    hostKey = f"{host['address']}/{'32' if is_ip_v4_address(host['address']) else '128'}:{hostVrf.id if hostVrf else ''}"
                    if hostKey not in ipAddressesPreExisting:
                        ipCreated = nb.ipam.ip_addresses.create(
                            {
                                "address": host['address'],
                                "vrf": hostVrf.id if hostVrf else None,
                                "assigned_object_type": "dcim.interface",
                                "assigned_object_id": interfaces[devices[host['name']].id].id,
                            },
                        )
                        if ipCreated is not None:
                            # update device to set this as its primary IPv4 address
                            deviceForIp = nb.dcim.devices.get(id=devices[host['name']].id)
                            if deviceForIp is not None:
                                if is_ip_v4_address(host['address']):
                                    deviceForIp.primary_ip4 = ipCreated
                                elif is_ip_v6_address(host['address']):
                                    deviceForIp.primary_ip = ipCreated
                                deviceForIp.save()

                except pynetbox.RequestError as nbe:
                    logging.warning(f"{type(nbe).__name__} processing address \"{host['address']}\": {nbe}")

            ipAddresses = {f"{x.address}:{x.vrf}": x for x in nb.ipam.ip_addresses.all()}
            logging.debug(f"IP addresses (after): { {k:v.id for k, v in ipAddresses.items()} }")

    except Exception as e:
        logging.error(f"{type(e).__name__} processing net map JSON \"{args.netMapFileName}\": {e}")

    # ###### Netbox-Initializers ###################################################################################
    netboxVenvPy = os.path.join(os.path.join(os.path.join(args.netboxDir, 'venv'), 'bin'), 'python')
    manageScript = os.path.join(os.path.join(args.netboxDir, 'netbox'), 'manage.py')
    if os.path.isfile(netboxVenvPy) and os.path.isfile(manageScript) and os.path.isdir(args.preloadDir):
        try:
            with malcolm_utils.pushd(os.path.dirname(manageScript)):
                retcode, output = malcolm_utils.run_process(
                    [
                        netboxVenvPy,
                        os.path.basename(manageScript),
                        "load_initializer_data",
                        "--path",
                        args.preloadDir,
                    ],
                    logger=logging,
                )
                if retcode == 0:
                    logging.debug(f"netbox-initializers: {retcode} {output}")
                else:
                    logging.error(f"Error processing netbox-initializers: {retcode} {output}")

        except Exception as e:
            logging.error(f"{type(e).__name__} processing netbox-initializers: {e}")

    # ###### Library ###############################################################################################
    if os.path.isdir(args.libraryDir):
        try:
            counter = import_library(nb, args.libraryDir)
            logging.debug(f"import library results: { counter }")

        except Exception as e:
            logging.error(f"{type(e).__name__} processing library: {e}")


###################################################################################################
if __name__ == '__main__':
    main()
