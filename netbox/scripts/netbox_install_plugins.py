#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2025 Battelle Energy Alliance, LLC.  All rights reserved.

import argparse
import ast
import json
import logging
import os
import sys
import malcolm_utils
from tempfile import TemporaryDirectory

from datetime import datetime
from packaging.version import Version
from distutils import dir_util

###################################################################################################
script_name = os.path.basename(__file__)
script_path = os.path.dirname(os.path.realpath(__file__))
orig_path = os.getcwd()


###################################################################################################
def get_installed_packages(venvPy):
    packagesInstalled = {}
    cmd = [
        venvPy,
        "-m",
        "pip",
        "--no-color",
        "--no-input",
        "--disable-pip-version-check",
        "list",
        "--local",
        "--format",
        "json",
        "--verbose",
    ]
    err, results = malcolm_utils.run_process(cmd, stderr=False, logger=logging)
    if (err == 0) and results and (len(results) > 0):
        try:
            packagesInstalled = {item['name']: item for item in malcolm_utils.LoadStrIfJson(results[0])}
        except Exception as e:
            logging.error(f"{type(e).__name__} getting list of installed Python packages: {e}")

    return packagesInstalled


###################################################################################################
def install_package_dir_if_needed(
    packageDir,
    venvPy,
    preinstalledPackagesDict={},
):
    installResult = False

    # First do a "dry run" install to determine what would happen. The report from this will
    #   help us determine if the package actually needs installed or not, as pip always treats
    #   installations from local directories as "new installs" and would uninstall/reinstall
    #   no matter what, which we want to avoid if we don't need it.
    pluginNeedsInstall = False
    with malcolm_utils.temporary_filename(suffix='.json') as dryRunInstallReportFileName:
        cmd = [
            venvPy,
            "-m",
            "pip",
            "--no-color",
            "--no-input",
            "--disable-pip-version-check",
            "install",
            "--upgrade",
            "--dry-run",
            "--progress-bar",
            "off",
            "--report",
            dryRunInstallReportFileName,
            packageDir,
        ]
        err, results = malcolm_utils.run_process(cmd, logger=logging)
        if (err == 0) and os.path.isfile(dryRunInstallReportFileName):
            with open(dryRunInstallReportFileName, 'r') as f:
                dryRunReport = malcolm_utils.LoadFileIfJson(f)
                wouldInstallInfo = {
                    malcolm_utils.deep_get(installItem, ['metadata', 'name']): malcolm_utils.deep_get(
                        installItem, ['metadata', 'version']
                    )
                    for installItem in dryRunReport.get('install', [])
                }
            pluginNeedsInstall = any(
                [
                    package_name
                    for package_name, new_version in wouldInstallInfo.items()
                    if (package_name not in preinstalledPackagesDict)
                    or (Version(new_version) > Version(preinstalledPackagesDict[package_name]['version']))
                ]
            )
        else:
            pluginNeedsInstall = True

    if pluginNeedsInstall:
        with TemporaryDirectory() as tmpPackageDir:
            dir_util.copy_tree(packageDir, tmpPackageDir, preserve_symlinks=True)
            with malcolm_utils.temporary_filename(suffix='.json') as installReportFileName:
                cmd = [
                    venvPy,
                    "-m",
                    "pip",
                    "--no-color",
                    "--no-input",
                    "--disable-pip-version-check",
                    "install",
                    "--upgrade",
                    "--progress-bar",
                    "off",
                    "--report",
                    installReportFileName,
                    tmpPackageDir,
                ]
                err, results = malcolm_utils.run_process(cmd, logger=logging)
                installResult = err == 0

    return installResult


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
        '-n',
        '--netbox',
        dest='netboxDir',
        type=str,
        default=os.getenv('NETBOX_PATH', '/opt/netbox'),
        required=False,
        help="NetBox installation directory",
    )
    parser.add_argument(
        '--netbox-config',
        dest='netboxConfigDir',
        type=str,
        default=os.getenv('NETBOX_CONFIG_PATH', '/etc/netbox/config'),
        required=False,
        help="NetBox config directory (containing plugins.py, etc.)",
    )
    parser.add_argument(
        '-c',
        '--custom-plugins',
        dest='customPluginsDir',
        type=str,
        default=os.getenv('NETBOX_CUSTOM_PLUGINS_PATH', '/opt/netbox-custom-plugins'),
        required=False,
        help="Parent directory containing custom NetBox plugins to install",
    )
    try:
        args = parser.parse_args()
    except SystemExit as e:
        if e.code == 2:
            parser.print_help()
        sys.exit(e.code)

    args.verbose = malcolm_utils.set_logging(os.getenv("LOGLEVEL", ""), args.verbose, set_traceback_limit=True)

    logging.debug(os.path.join(script_path, script_name))
    logging.debug(f"Arguments: {sys.argv[1:]}")
    logging.debug(f"Arguments: {args}")

    return args


def write_local_settings(args):
    success = False

    # set a variable in local_settings.py for netbox-helathcheck-plugin
    #   see https://github.com/netbox-community/netbox-healthcheck-plugin/issues/12#issuecomment-2451665212
    netboxSettingsPyDir = os.path.join(args.netboxDir, os.path.join('netbox', 'netbox'))
    if os.path.isdir(netboxSettingsPyDir):
        try:
            localSettingsPyContents = "import os\n\nREDIS_URL = f\"redis://{os.environ.get('REDIS_USERNAME', '')}:{os.environ.get('REDIS_PASSWORD', '')}@{os.environ.get('REDIS_HOST', 'redis')}:{os.environ.get('REDIS_PORT', '6379')}/{os.environ.get('REDIS_NETBOX_DATABASE', os.environ.get('REDIS_DATABASE', '0'))}\"\n"
            with open(f"{netboxSettingsPyDir}/local_settings.py", 'w') as f:
                f.write(localSettingsPyContents)
            success = True
        except Exception as e:
            logging.error(f"{type(e).__name__} writing local_settings.py: {e}")

    return success


def install_requirements(args, netboxVenvPy, packagesInstalled):
    if os.path.isdir(os.path.join(args.customPluginsDir, 'requirements')):
        requirementsSubDirs = [
            malcolm_utils.remove_suffix(f.path, '/')
            for f in os.scandir(os.path.join(args.customPluginsDir, 'requirements'))
            if f.is_dir()
        ]
        for packageDir in requirementsSubDirs:
            packageInstalled = install_package_dir_if_needed(packageDir, netboxVenvPy, packagesInstalled)
            logging.info(f"{os.path.basename(packageDir)} (dependency): {'' if packageInstalled else 'not ' }installed")


def perform_migrations(netboxVenvPy, manageScript, pluginNames):
    success = True

    with malcolm_utils.pushd(os.path.dirname(manageScript)):
        for plugin in pluginNames:
            cmd = [
                netboxVenvPy,
                os.path.basename(manageScript),
                "makemigrations",
                plugin,
            ]
            err, results = malcolm_utils.run_process(cmd, logger=logging)
            if err != 0:
                logging.warning(f'{err} making migrations for {plugin}: {results}')
                success = False

        cmd = [netboxVenvPy, os.path.basename(manageScript), "migrate"]
        err, results = malcolm_utils.run_process(cmd, logger=logging)
        if err != 0:
            logging.warning(f'{err} migrating: {results}')
            success = False

        cmd = [
            netboxVenvPy,
            os.path.basename(manageScript),
            "collectstatic",
            "--no-input",
        ]
        err, results = malcolm_utils.run_process(cmd, logger=logging)
        if err != 0:
            logging.warning(f'{err} collecting static files: {results}')
            success = False

    return success


def install_plugins(args):
    if not os.path.isdir(args.customPluginsDir) or not os.path.isfile(os.path.join(args.netboxConfigDir, 'plugins.py')):
        return

    netboxVenvPy = os.path.join(os.path.join(os.path.join(args.netboxDir, 'venv'), 'bin'), 'python')
    manageScript = os.path.join(os.path.join(args.netboxDir, 'netbox'), 'manage.py')

    # get a list of what packages/plugins already installed (package names and versions in a dict)
    packagesInstalled = get_installed_packages(netboxVenvPy)

    # if there is a "requirements" subdirectory, handle that first as it contains dependencies
    install_requirements(args, netboxVenvPy, packagesInstalled)

    # now install the plugins directories
    installedOrUpdatedPlugins = []
    global pluginsListModified
    global pluginsListFound
    pluginsListModified = False
    pluginsListFound = False
    customPluginSubdirs = [
        malcolm_utils.remove_suffix(f.path, '/')
        for f in os.scandir(args.customPluginsDir)
        if f.is_dir() and (os.path.basename(f) != 'requirements')
    ]
    for pluginDir in customPluginSubdirs:
        if pluginInstalled := install_package_dir_if_needed(pluginDir, netboxVenvPy, packagesInstalled):
            installedOrUpdatedPlugins.append(pluginDir)
        logging.info(f"{os.path.basename(pluginDir)}: {'' if pluginInstalled else 'not ' }installed")

    # for any packages that were newly installed (or updated, we'll be thorough) we need to make
    #   sure the package name is in the plugins.py
    logging.info(f"Plugins installed or updated: {installedOrUpdatedPlugins}")
    if installedOrUpdatedPlugins:
        # get updated list of installed packages
        packagesInstalled = get_installed_packages(netboxVenvPy)

    # now get the names of the NetBox plugins installed
    pluginNames = []

    # first get a list of __init__.py files for potential plugins installed in the package location(s)
    cmd = [
        '/usr/bin/rg',
        '--files-with-matches',
        '--iglob',
        '__init__.py',
        r'\bPluginConfig\b',
        list({package['location'] for package in packagesInstalled.values() if 'location' in package}),
    ]
    err, results = malcolm_utils.run_process(cmd, stderr=False, logger=logging)
    if results:
        # process each of those potential plugin __init__.py files
        for pluginInitFileName in results:
            try:
                if os.path.isfile(pluginInitFileName):
                    # parse the Python of the __init__.py into an abstract syntax tree
                    with open(pluginInitFileName, 'r') as f:
                        node = ast.parse(f.read())
                        # look at each Class defined in this code
                        for c in [n for n in node.body if isinstance(n, ast.ClassDef)]:
                            # plugins are classes with "PluginConfig" for a parent
                            if any([baseClass.id == 'PluginConfig' for baseClass in c.bases]):
                                # this ia a plugin class, so iterate over its members (functions,
                                #   variables, etc.) to find its name
                                for item in c.body:
                                    # the name is defined as an assignment (ast.Assign)
                                    if isinstance(item, ast.Assign):
                                        # does this assignment have a target called 'name'?
                                        for target in item.targets:
                                            if isinstance(target, ast.Name) and target.id == 'name':
                                                # check if the value assigned to 'name' is a constant
                                                if isinstance(item.value, ast.Constant):
                                                    pluginNames.append(item.value.value)
            except Exception as e:
                logging.error(f"{type(e).__name__} identifying NetBox plugin names: {e}")

    if pluginNames:
        pluginNames = list(set(pluginNames))
        # at this point we have a list of plugin names for all of the plugin classes!
        #   we need to make sure they exist in plugins.py

        # Load and parse the plugins.py file
        pluginsListFound = False
        with open(os.path.join(args.netboxConfigDir, 'plugins.py'), 'r') as pluginFile:
            code = pluginFile.read()
            tree = ast.parse(code)

        # Walk the AST to find the PLUGINS assignment
        class PluginListModifier(ast.NodeTransformer):
            def visit_Assign(self, node):
                global pluginsListFound
                global pluginsListModified
                if isinstance(node.targets[0], ast.Name) and node.targets[0].id == 'PLUGINS':
                    pluginsListFound = True
                    # Check if the node's value is a list
                    if isinstance(node.value, ast.List):
                        # Get the existing plugin names in the list
                        existingPlugins = {elt.s for elt in node.value.elts if isinstance(elt, ast.Str)}
                        # Add new plugins if they aren't already in the list
                        for plugin in pluginNames:
                            if plugin not in existingPlugins:
                                node.value.elts.append(ast.Constant(value=plugin))
                                pluginsListModified = True
                return node

        # Modify the AST
        modifier = PluginListModifier()
        modifiedTree = modifier.visit(tree)

        # # If PLUGINS was not found, add it at the end of the module
        if not pluginsListFound:
            logging.debug('here')
            modifiedTree.body.append(
                ast.Assign(
                    targets=[ast.Name(id='PLUGINS', ctx=ast.Store())],
                    value=ast.List(elts=[ast.Constant(value=plugin) for plugin in pluginNames], ctx=ast.Load()),
                )
            )
            pluginsListModified = True

        # Unparse the modified AST back into code
        modifiedCode = ast.unparse(ast.fix_missing_locations(modifiedTree))

        # Write the modified code back to the file
        with open(os.path.join(args.netboxConfigDir, 'plugins.py'), 'w') as pluginFile:
            pluginFile.write(modifiedCode)

    if installedOrUpdatedPlugins or pluginsListModified:
        perform_migrations(netboxVenvPy, manageScript, pluginNames)


###################################################################################################
# main
def main():
    args = parse_args()
    write_local_settings(args)
    install_plugins(args)


###################################################################################################
if __name__ == '__main__':
    main()
