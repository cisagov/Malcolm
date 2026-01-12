#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2026 Battelle Energy Alliance, LLC.  All rights reserved.

import argparse
import glob
import gzip
import logging
import magic
import os
import pynetbox
import randomcolor
import sys
import tarfile
import tempfile
import time
import malcolm_utils

from distutils.dir_util import copy_tree
from datetime import datetime
from slugify import slugify

###################################################################################################
script_name = os.path.basename(__file__)
script_path = os.path.dirname(os.path.realpath(__file__))
orig_path = os.getcwd()


###################################################################################################
def parse_args():
    parser = argparse.ArgumentParser(
        description='\n'.join([]),
        formatter_class=argparse.RawTextHelpFormatter,
        add_help=True,
        usage='{} <arguments>'.format(script_name),
    )
    parser.add_argument(
        '--verbose',
        '-v',
        action='count',
        default=malcolm_utils.get_verbosity_env_var_count("VERBOSITY"),
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
        dest='netbox_url',
        type=str,
        default=os.getenv('NETBOX_URL') or 'http://netbox:8080/netbox',
        required=False,
        help="NetBox Base URL",
    )
    parser.add_argument(
        '-t',
        '--token',
        dest='netbox_token',
        type=str,
        default=None,
        required=False,
        help="NetBox API Token",
    )
    parser.add_argument(
        '-s',
        '--site',
        dest='netbox_sites',
        nargs='*',
        type=str,
        default=[os.getenv('NETBOX_DEFAULT_SITE', 'default')],
        required=False,
        help="Site(s) to create",
    )
    parser.add_argument(
        '--read-only-group',
        dest='read_only_group_name',
        type=str,
        default=os.getenv('ROLE_NETBOX_READ_ACCESS', 'netbox_read_access'),
        required=False,
        help="Name of read-only group for automatic NetBox user creation",
    )
    parser.add_argument(
        '--read-write-group',
        dest='read_write_group_name',
        type=str,
        default=os.getenv('ROLE_NETBOX_READ_WRITE_ACCESS', 'netbox_read_write_access'),
        required=False,
        help="Name of read/write group for automatic NetBox user creation",
    )
    parser.add_argument(
        '--admin-group',
        dest='admin_group_name',
        type=str,
        default=os.getenv('ROLE_ADMIN', 'admin'),
        required=False,
        help="Name of administrator group for automatic NetBox user creation",
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
        dest='device_types',
        nargs='*',
        type=str,
        default=[os.getenv('NETBOX_DEFAULT_DEVICE_TYPE', 'Unspecified')],
        required=False,
        help="Device types(s) to create",
    )
    parser.add_argument(
        '-n',
        '--netbox',
        dest='netbox_dir',
        type=str,
        default=os.getenv('NETBOX_PATH', '/opt/netbox'),
        required=False,
        help="NetBox installation directory",
    )
    parser.add_argument(
        '-l',
        '--library',
        dest='library_dir',
        type=str,
        default=os.getenv('NETBOX_DEVICETYPE_LIBRARY_IMPORT_PATH', '/opt/netbox-devicetype-library-import'),
        required=False,
        help="Directory containing NetBox Device-Type-Library-Import project and library repo",
    )
    parser.add_argument(
        '-p',
        '--preload',
        dest='preload_dir',
        type=str,
        default=os.getenv('NETBOX_PRELOAD_PATH', '/opt/netbox-preload'),
        required=False,
        help="Directory containing netbox-initializers files to preload",
    )
    parser.add_argument(
        '--preload-backup',
        dest='preload_backup_file',
        type=str,
        default=os.getenv('NETBOX_PRELOAD_GZ', default=''),
        required=False,
        help="Database dump .gz file to preload into postgreSQL",
    )
    parser.add_argument(
        '--postgres-host',
        dest='postgres_host',
        type=str,
        default=os.getenv('POSTGRES_HOST', 'postgres'),
        required=False,
        help="postgreSQL host for preloading an entire database dump .gz (specified with --preload-backup or loaded from the --preload directory)",
    )
    parser.add_argument(
        '--postgres-port',
        dest='postgres_port',
        type=int,
        default=int(os.getenv('PGPORT', '5432')),
        required=False,
        help="postgreSQL port for use with --postgres-host",
    )
    parser.add_argument(
        '--postgres-db',
        dest='postgres_db',
        type=str,
        default=os.getenv('POSTGRES_NETBOX_DB', 'netbox'),
        required=False,
        help="postgreSQL database name",
    )
    parser.add_argument(
        '--postgres-user',
        dest='postgres_user',
        type=str,
        default=os.getenv('POSTGRES_NETBOX_USER', 'netbox'),
        required=False,
        help="postgreSQL user name",
    )
    parser.add_argument(
        '--postgres-password',
        dest='postgres_password',
        type=str,
        default=os.getenv('POSTGRES_NETBOX_PASSWORD', ''),
        required=False,
        help="postgreSQL password",
    )
    try:
        args = parser.parse_args()
    except SystemExit as e:
        if e.code == 2:
            parser.print_help()
        sys.exit(e.code)

    args.verbose = malcolm_utils.set_logging(os.getenv("LOGLEVEL", ""), args.verbose, set_traceback_limit=True)
    args.netbox_token = args.netbox_token or os.getenv('NETBOX_TOKEN') or os.getenv('SUPERUSER_API_TOKEN')

    logging.debug(os.path.join(script_path, script_name))
    logging.debug(f"Arguments: {sys.argv[1:]}")
    logging.debug(f"Arguments: {args}")

    return args


def determine_database_backup_file(args):
    result = args.preload_backup_file

    if (not os.path.isfile(result)) and os.path.isdir(args.preload_dir):
        preload_files = [
            x
            for x in list(filter(os.path.isfile, glob.glob(os.path.join(args.preload_dir, '*.gz'))))
            if not x.endswith('.media.tar.gz')
        ]
        preload_files.sort(key=lambda x: os.path.getmtime(x))
        result = next(iter(preload_files), '')

    logging.debug(f"determine_database_backup_file: {result}")
    return result


def stop_netbox():
    success = True

    # stop the netbox processes (except this one)
    cmd = [
        'bash',
        '-c',
        "supervisorctl status netbox:* | grep -v :initialization | awk '{ print $1 }' | xargs -r -L 1 -P 4 supervisorctl stop",
    ]
    err, results = malcolm_utils.run_process(cmd, logger=logging)
    if err != 0:
        logging.error(f'{err} stopping netbox:*: {results}')
        success = False

    logging.debug(f"stop_netbox: {success}")
    return success


def start_netbox():
    success = True

    # start back up the netbox processes (except initialization)
    cmd = [
        'bash',
        '-c',
        "supervisorctl status netbox:* | grep -v :initialization | awk '{ print $1 }' | xargs -r -L 1 -P 4 supervisorctl start",
    ]
    err, results = malcolm_utils.run_process(cmd, logger=logging)
    if err != 0:
        logging.error(f'{err} starting netbox:*: {results}')
        success = False

    logging.debug(f"start_netbox: {success}")
    return success


def execute_restore_commands(args, database_file):
    success = False

    os_env = os.environ.copy()
    os_env['PGPASSWORD'] = args.postgres_password

    # drop the existing netbox database
    cmd = [
        'dropdb',
        '-h',
        args.postgres_host,
        '-p',
        str(args.postgres_port),
        '-U',
        args.postgres_user,
        '-f',
        args.postgres_db,
    ]
    err, results = malcolm_utils.run_process(cmd, env=os_env, logger=logging)
    if err != 0:
        logging.warning(f'{err} dropping NetBox database: {results}')

    # create a new netbox database
    cmd = [
        'createdb',
        '-h',
        args.postgres_host,
        '-p',
        str(args.postgres_port),
        '-U',
        args.postgres_user,
        args.postgres_db,
    ]
    err, results = malcolm_utils.run_process(cmd, env=os_env, logger=logging)
    if err != 0:
        raise Exception(f'Error {err} creating new NetBox database: {results}')

    # load the backed-up psql dump
    cmd = [
        'psql',
        '-h',
        args.postgres_host,
        '-p',
        str(args.postgres_port),
        '-U',
        args.postgres_user,
    ]
    with (
        gzip.open(database_file, 'rt')
        if 'application/gzip' in magic.from_file(database_file, mime=True)
        else open(database_file, 'r')
    ) as f:
        err, results = malcolm_utils.run_process(cmd, env=os_env, logger=logging, stdin=f.read())
    if (err == 0) and results:
        success = True
    else:
        raise Exception(f'Error {err} loading NetBox database: {results}')

    # with idaholab/Malcolm#280 we switched to use prefix.description instead of VRF for identifying subnets in NetBox,
    # this will migrate ipam_vrf.name to ipam_prefix.description if we're coming from an older backup
    cmd = [
        'psql',
        '-h',
        args.postgres_host,
        '-p',
        str(args.postgres_port),
        '-U',
        args.postgres_user,
        '-c',
        "UPDATE ipam_prefix SET description = (SELECT name from ipam_vrf WHERE id = ipam_prefix.vrf_id) WHERE ((description = '') IS NOT FALSE) AND (vrf_id > 0)",
    ]
    err, results = malcolm_utils.run_process(cmd, env=os_env, logger=logging)
    if err != 0:
        logging.error(f'{err} migrating ipam_vrf.name to ipam_prefix.description: {results}')

    # don't restore users_user, tokens, etc: they're created by Malcolm and may not be the same on this instance
    cmd = [
        'psql',
        '-h',
        args.postgres_host,
        '-p',
        str(args.postgres_port),
        '-U',
        {args.postgres_user},
        '-c',
        'TRUNCATE users_user CASCADE',
    ]
    err, results = malcolm_utils.run_process(cmd, env=os_env, logger=logging)
    if err != 0:
        logging.error(f'{err} truncating table users_user table: {results}')

    logging.debug(f"execute_restore_commands({database_file}): {success}")
    return success


def perform_migrations(netbox_venv_py, manage_script):
    success = True

    with malcolm_utils.pushd(os.path.dirname(manage_script)):
        # migrations if needed
        cmd = [
            netbox_venv_py,
            os.path.basename(manage_script),
            "migrate",
            "--check",
        ]
        err, results = malcolm_utils.run_process(cmd, logger=logging)
        if err != 0:
            for operation in [
                [
                    "migrate",
                    "--no-input",
                ],
                [
                    "trace_paths",
                    "--no-input",
                ],
                [
                    "remove_stale_contenttypes",
                    "--no-input",
                ],
                [
                    "clearsessions",
                ],
                [
                    "reindex",
                    "--lazy",
                ],
            ]:

                cmd = [netbox_venv_py, os.path.basename(manage_script)] + operation
                err, results = malcolm_utils.run_process(cmd, logger=logging)
                if (err != 0) or (not results):
                    logging.error(f'{err} performing NetBox {cmd[2]}: {results}')
                    success = False

        # create users_user for superuser
        cmd = [
            netbox_venv_py,
            os.path.basename(manage_script),
            "shell",
            "--interface",
            "python",
        ]
        with open('/usr/local/bin/netbox_superuser_create.py', 'r') as f:
            err, results = malcolm_utils.run_process(cmd, logger=logging, stdin=f.read())
        if (err != 0) or (not results):
            logging.error(f'{err} setting up superuser: {results}')
            success = False

    logging.debug(f"perform_migrations: {success}")
    return success


def restore_media_directory(args, database_file):
    success = False

    preload_database_file_parts = os.path.splitext(database_file)
    media_file_name = preload_database_file_parts[0] + ".media.tar.gz"
    media_path = os.path.join(args.netbox_dir, os.path.join('netbox', 'media'))
    if os.path.isfile(media_file_name) and os.path.isdir(media_path):
        try:
            malcolm_utils.RemoveEmptyFolders(media_path, removeRoot=False)
            with tarfile.open(media_file_name) as t:
                t.extractall(media_path)
                success = True
        except Exception as e:
            logging.error(f"{type(e).__name__} processing restoring {os.path.basename(media_file_name)}: {e}")

    logging.debug(f"restore_media_directory: {success}")
    return success


def restore_database_backup(args, netbox_venv_py, manage_script):
    database_file = determine_database_backup_file(args)
    if not os.path.isfile(database_file):
        return False

    # we're loading an existing database directly with postgreSQL
    # this should pretty much match what is in control.py:netboxRestore
    successes = []
    try:
        stop_netbox()
        successes.append(execute_restore_commands(args, database_file))
        start_netbox()
        successes.append(perform_migrations(netbox_venv_py, manage_script))
        restore_media_directory(args, database_file)
    except Exception as e:
        logging.error(f"{type(e).__name__} restoring {os.path.basename(database_file)}: {e}")

    logging.debug(f"restore_database_backup: {successes and all(successes)}")
    return successes and all(successes)


def initialize_netbox_api(args):
    nb = pynetbox.api(
        args.netbox_url,
        token=args.netbox_token,
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

    return nb


def ensure_default_groups(args, nb):
    # GROUPS #####################################################################################################
    groups = {}

    default_group_names = (
        args.admin_group_name,
        args.read_only_group_name,
        args.read_write_group_name,
    )
    try:
        groups_pre_existing = {x.name: x for x in nb.users.groups.all()}
        logging.debug(f"groups (before): { {k:v.id for k, v in groups_pre_existing.items()} }")

        # create groups that don't already exist
        for group_name in [x for x in default_group_names if x and (x not in groups_pre_existing)]:
            try:
                nb.users.groups.create({'name': group_name})
            except pynetbox.RequestError as nbe:
                logging.warning(f"{type(nbe).__name__} processing group \"{group_name}\": {nbe}")

        groups = {x.name: x for x in nb.users.groups.all()}
        logging.debug(f"groups (after): { {k:v.id for k, v in groups.items()} }")
    except Exception as e:
        logging.error(f"{type(e).__name__} processing groups: {e}")

    return groups


def ensure_default_permissions(args, nb, groups):
    permissions = {}

    # PERMISSIONS for default groups ###############################################################################
    default_group_permissions = {
        f'{args.admin_group_name}_permission': {
            'name': f'{args.admin_group_name}_permission',
            'enabled': True,
            'groups': [args.admin_group_name],
            'actions': [
                'view',
                'add',
                'change',
                'delete',
            ],
            'constraints': {},
            'include_objects': ['*'],
            'exclude_objects': [],
        },
    }

    groups_default_permissions = {
        args.read_write_group_name: [
            'view',
            'add',
            'change',
            'delete',
        ],
        args.read_only_group_name: [
            'view',
        ],
    }
    for group_name, group_actions in groups_default_permissions.items():
        default_group_permissions[f'{group_name}_permission'] = {
            'name': f'{group_name}_permission',
            'enabled': True,
            'groups': [group_name],
            'actions': group_actions,
            'constraints': {},
            'include_objects': ['*'],
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
                'users.token',
                'users.user',
                'users.userconfig',
            ],
        }
        default_group_permissions[f'{group_name}_user_config_permission'] = {
            'name': f'{group_name}_user_config_permission',
            'enabled': True,
            'groups': [group_name],
            'actions': [
                'view',
                'change',
            ],
            'constraints': {
                "user": "$user",
            },
            'include_objects': [
                'users.userconfig',
            ],
            'exclude_objects': [],
        }
        default_group_permissions[f'{group_name}_token_manage_permission'] = {
            'name': f'{group_name}_token_manage_permission',
            'enabled': True,
            'groups': [group_name],
            'actions': [
                'add',
                'view',
                'change',
                'delete',
            ],
            'constraints': {
                "user": "$user",
            },
            'include_objects': ['users.token'],
            'exclude_objects': [],
        }

    try:
        # get all content types (for creating new permissions)
        all_object_type_names = [f'{x.app_label}.{x.model}' for x in nb.extras.object_types.all()]

        perms_pre_existing = {x.name: x for x in nb.users.permissions.all()}
        logging.debug(f"permissions (before): { {k:v.id for k, v in perms_pre_existing.items()} }")

        # create permissions that don't already exist
        for perm_name, perm_config in {
            k: v
            for (k, v) in default_group_permissions.items()
            if v.get('name', None) and v['name'] not in perms_pre_existing
        }.items():
            perm_config['groups'] = [groups[x].id for x in perm_config['groups']]
            perm_config['object_types'] = [
                ct
                for ct in (
                    all_object_type_names if ('*' in perm_config['include_objects']) else perm_config['include_objects']
                )
                if ct not in perm_config['exclude_objects']
            ]
            perm_config.pop('exclude_objects', None)
            perm_config.pop('include_objects', None)
            try:
                nb.users.permissions.create(perm_config)
            except pynetbox.RequestError as nbe:
                logging.warning(f"{type(nbe).__name__} processing permission \"{perm_config['name']}\": {nbe}")

        permissions = {x.name: x for x in nb.users.permissions.all()}
        logging.debug(f"permissions (after): { {k:v.id for k, v in permissions.items()} }")
    except Exception as e:
        logging.error(f"{type(e).__name__} processing permissions: {e}")

    return permissions


def ensure_default_manufacturers(args, nb):
    manufacturers = {}

    # ###### MANUFACTURERS #########################################################################################
    try:
        manufacturers_pre_existing = {x.name: x for x in nb.dcim.manufacturers.all()}
        logging.debug(f"manufacturers (before): { {k:v.id for k, v in manufacturers_pre_existing.items()} }")

        # create manufacturers that don't already exist
        for manufacturer_name in [x for x in args.manufacturers if x not in manufacturers_pre_existing]:
            try:
                nb.dcim.manufacturers.create(
                    {
                        "name": manufacturer_name,
                        "slug": slugify(manufacturer_name),
                    },
                )
            except pynetbox.RequestError as nbe:
                logging.warning(f"{type(nbe).__name__} processing manufacturer \"{manufacturer_name}\": {nbe}")

        manufacturers = {x.name: x for x in nb.dcim.manufacturers.all()}
        logging.debug(f"manufacturers (after): { {k:v.id for k, v in manufacturers.items()} }")
    except Exception as e:
        logging.error(f"{type(e).__name__} processing manufacturers: {e}")

    return manufacturers


def ensure_default_roles(args, nb):
    roles = {}

    # ###### ROLES #################################################################################################
    try:
        roles_pre_existing = {x.name: x for x in nb.dcim.device_roles.all()}
        logging.debug(f"roles (before): { {k:v.id for k, v in roles_pre_existing.items()} }")

        rand_color = randomcolor.RandomColor(seed=datetime.now().timestamp())

        # create roles that don't already exist
        for role_name in [x for x in args.roles if x not in roles_pre_existing]:
            try:
                nb.dcim.device_roles.create(
                    {
                        "name": role_name,
                        "slug": slugify(role_name),
                        "vm_role": True,
                        "color": rand_color.generate()[0][1:],
                    },
                )
            except pynetbox.RequestError as nbe:
                logging.warning(f"{type(nbe).__name__} processing role \"{role_name}\": {nbe}")

        roles = {x.name: x for x in nb.dcim.device_roles.all()}
        logging.debug(f"roles (after): { {k:v.id for k, v in roles.items()} }")
    except Exception as e:
        logging.error(f"{type(e).__name__} processing roles: {e}")

    return roles


def ensure_default_device_types(args, nb, manufacturers):
    device_types = {}

    # ###### DEVICE TYPES ##########################################################################################
    try:
        device_types_pre_existing = {x.model: x for x in nb.dcim.device_types.all()}
        logging.debug(f"device types (before): { {k:v.id for k, v in device_types_pre_existing.items()} }")

        # create device types that don't already exist
        for device_type_model in [x for x in args.device_types if x not in device_types_pre_existing]:
            try:
                manuf = malcolm_utils.min_hash_value_by_value(manufacturers)
                nb.dcim.device_types.create(
                    {
                        "model": device_type_model,
                        "slug": slugify(device_type_model),
                        "manufacturer": manuf.id if manuf else None,
                    },
                )
            except pynetbox.RequestError as nbe:
                logging.warning(f"{type(nbe).__name__} processing device type \"{device_type_model}\": {nbe}")

        device_types = {x.model: x for x in nb.dcim.device_types.all()}
        logging.debug(f"device types (after): { {k:v.id for k, v in device_types.items()} }")
    except Exception as e:
        logging.error(f"{type(e).__name__} processing device types: {e}")

    return device_types


def ensure_default_sites(args, nb):
    sites = {}

    # ###### SITES #################################################################################################
    try:
        sites_pre_existing = {x.name: x for x in nb.dcim.sites.all()}
        logging.debug(f"sites (before): { {k:v.id for k, v in sites_pre_existing.items()} }")

        # create sites that don't already exist
        for site_name in [x for x in args.netbox_sites if x not in sites_pre_existing]:
            try:
                nb.dcim.sites.create(
                    {
                        "name": site_name,
                        "slug": slugify(site_name),
                    },
                )
            except pynetbox.RequestError as nbe:
                logging.warning(f"{type(nbe).__name__} processing site \"{site_name}\": {nbe}")

        sites = {x.name: x for x in nb.dcim.sites.all()}
        logging.debug(f"sites (after): { {k:v.id for k, v in sites.items()} }")
    except Exception as e:
        logging.error(f"{type(e).__name__} processing sites: {e}")

    return sites


def fix_missing_prefix_descriptions(nb):
    # ###### Missing prefix descriptions from VRF names (see idaholab/Malcolm#280) ##################################
    try:
        for prefix in [x for x in nb.ipam.prefixes.filter(description__empty=True) if x.vrf]:
            logging.debug(f"Updating prefix {str(prefix)}'s description to {str(prefix.vrf)}")
            prefix.update(
                {
                    "description": str(prefix.vrf),
                }
            )

    except Exception as e:
        logging.error(f"{type(e).__name__} migrating prefix VRF to prefix description: {e}")


def process_netbox_initializers(args, netbox_venv_py, manage_script):
    success = False

    # ###### Netbox-Initializers ###################################################################################
    # We're doing the netbox initializers even if we did a database backup preload, as we always want to
    #   honor there being something in here. If things already got loaded upas part of the backup preload,
    #   no big deal, those things will just fail for already existing.
    if os.path.isfile(netbox_venv_py) and os.path.isfile(manage_script) and os.path.isdir(args.preload_dir):
        try:
            with malcolm_utils.pushd(os.path.dirname(manage_script)):
                # make a local copy of the YMLs to preload
                with tempfile.TemporaryDirectory() as tmp_preload_dir:
                    copy_tree(args.preload_dir, tmp_preload_dir)
                    retcode, output = malcolm_utils.run_process(
                        [
                            netbox_venv_py,
                            os.path.basename(manage_script),
                            "load_initializer_data",
                            "--path",
                            tmp_preload_dir,
                        ],
                        logger=logging,
                    )
                    if retcode == 0:
                        logging.debug(f"netbox-initializers: {output}")
                        success = True
                    else:
                        logging.error(f"{retcode} processing netbox-initializers: {output}")

        except Exception as e:
            logging.error(f"{type(e).__name__} processing netbox-initializers: {e}")

    return success


def process_device_type_library_import(args, netbox_venv_py):
    success = False

    # ######  Device-Type-Library-Import ###########################################################################
    if os.path.isdir(args.library_dir):
        try:
            with malcolm_utils.pushd(args.library_dir):
                os_env = os.environ.copy()
                os_env['NETBOX_URL'] = args.netbox_url
                os_env['NETBOX_TOKEN'] = args.netbox_token
                os_env['REPO_URL'] = 'local'
                cmd = [netbox_venv_py, 'nb-dt-import.py']
                err, results = malcolm_utils.run_process(
                    cmd,
                    logger=logging,
                    env=os_env,
                )
                if (err == 0) and results:
                    logging.debug(f"nb-dt-import.py: {results}")
                    success = True
                else:
                    logging.error(f"{err} running nb-dt-import.py: {results}")

        except Exception as e:
            logging.error(f"{type(e).__name__} processing library: {e}")

    return success


###################################################################################################
# main
def main():
    args = parse_args()

    netbox_venv_py = os.path.join(os.path.join(os.path.join(args.netbox_dir, 'venv'), 'bin'), 'python')
    manage_script = os.path.join(os.path.join(args.netbox_dir, 'netbox'), 'manage.py')

    # if there is a database backup .gz in the preload directory, load it up (preferring the newest
    # if there are multiple) instead of populating via API
    preload_database_success = restore_database_backup(args, netbox_venv_py, manage_script)

    # only proceed to do the regular population if if we didn't preload a database backup, or
    #   if we attempted (and failed) but they didn't explicitly specify a backup file
    if not preload_database_success and (not args.preload_backup_file):
        nb = initialize_netbox_api(args)
        groups = ensure_default_groups(args, nb)
        permissions = ensure_default_permissions(args, nb, groups)
        manufacturers = ensure_default_manufacturers(args, nb)
        roles = ensure_default_roles(args, nb)
        device_types = ensure_default_device_types(args, nb, manufacturers)
        sites = ensure_default_sites(args, nb)
        fix_missing_prefix_descriptions(nb)

    process_netbox_initializers(args, netbox_venv_py, manage_script)

    if not preload_database_success and (not args.preload_backup_file):
        process_device_type_library_import(args, netbox_venv_py)


###################################################################################################
if __name__ == '__main__':
    try:
        main()
    except Exception as e:
        logging.exception(f"Unexpected error: {e}")
        sys.exit(1)
