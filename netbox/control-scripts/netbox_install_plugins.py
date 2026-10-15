#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2026 Battelle Energy Alliance, LLC.  All rights reserved.

import argparse
import ast
import logging
import os
import sys
import malcolm_utils
from tempfile import TemporaryDirectory

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
    logging.debug(f"getting installed packages with: {cmd}")
    err, results = malcolm_utils.run_process(cmd, stderr=False, logger=logging)
    if (err == 0) and results and (len(results) > 0):
        try:
            packagesInstalled = {item['name']: item for item in malcolm_utils.LoadStrIfJson(results[0])}
            logging.debug(f"found {len(packagesInstalled)} installed package(s)")
        except Exception as e:
            logging.error(f"{type(e).__name__} getting list of installed Python packages: {e}")
    else:
        logging.warning(f"pip list returned err={err}, unable to determine installed packages")

    return packagesInstalled


###################################################################################################
def install_package_dir_if_needed(
    packageDir,
    venvPy,
    preinstalledPackagesDict={},
):
    installResult = False
    targetDir = os.getenv('NETBOX_CUSTOM_VENV_PACKAGES_PATH', '')

    # First do a "dry run" install to determine what would happen. The report from this will
    #   help us determine if the package actually needs installed or not, as pip always treats
    #   installations from local directories as "new installs" and would uninstall/reinstall
    #   no matter what, which we want to avoid if we don't need it.
    pluginNeedsInstall = False
    logging.debug(f"evaluating whether {packageDir} needs (re)install")
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
        ]
        if os.path.isdir(targetDir):
            cmd.extend(['--target', targetDir])
        cmd.append(packageDir)
        logging.debug(f"dry-run install command: {cmd}")
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
            logging.debug(f"dry-run would install/upgrade: {wouldInstallInfo}")
            pluginNeedsInstall = any(
                [
                    package_name
                    for package_name, new_version in wouldInstallInfo.items()
                    if (package_name not in preinstalledPackagesDict)
                    or (Version(new_version) > Version(preinstalledPackagesDict[package_name]['version']))
                ]
            )
        else:
            logging.debug(f"dry-run install failed or produced no report (err={err}), assuming install is needed")
            pluginNeedsInstall = True

    if pluginNeedsInstall:
        logging.info(f"installing/upgrading {packageDir}")
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
                ]
                if os.path.isdir(targetDir):
                    cmd.extend(['--target', targetDir])
                cmd.append(tmpPackageDir)
                logging.debug(f"install command: {cmd}")
                err, results = malcolm_utils.run_process(cmd, logger=logging)
                installResult = err == 0
                if not installResult:
                    logging.warning(f"install of {packageDir} failed with err={err}: {results}")
    else:
        logging.debug(f"{packageDir} is already up to date, skipping install")

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

    # set a variable in local_settings.py for netbox-healthcheck-plugin
    #   see https://github.com/netbox-community/netbox-healthcheck-plugin/issues/12#issuecomment-2451665212
    netboxSettingsPyDir = os.path.join(args.netboxDir, os.path.join('netbox', 'netbox'))
    if os.path.isdir(netboxSettingsPyDir):
        try:
            localSettingsPyContents = "import os\n\nREDIS_URL = f\"redis://{os.environ.get('REDIS_USERNAME', '')}:{os.environ.get('REDIS_PASSWORD', '')}@{os.environ.get('REDIS_HOST', 'redis')}:{os.environ.get('REDIS_PORT', '6379')}/{os.environ.get('REDIS_NETBOX_DATABASE', os.environ.get('REDIS_DATABASE', '0'))}\"\n"
            with open(f"{netboxSettingsPyDir}/local_settings.py", 'w') as f:
                f.write(localSettingsPyContents)
            success = True
            logging.debug(f"wrote local_settings.py to {netboxSettingsPyDir}")
        except Exception as e:
            logging.error(f"{type(e).__name__} writing local_settings.py: {e}")
    else:
        logging.warning(f"{netboxSettingsPyDir} does not exist, skipping local_settings.py")

    return success


def install_requirements(args, netboxVenvPy, packagesInstalled):
    if os.path.isdir(os.path.join(args.customPluginsDir, 'requirements')):
        requirementsSubDirs = [
            malcolm_utils.remove_suffix(f.path, '/')
            for f in os.scandir(os.path.join(args.customPluginsDir, 'requirements'))
            if f.is_dir()
        ]
        logging.debug(f"found {len(requirementsSubDirs)} requirements subdirectory(ies): {requirementsSubDirs}")
        for packageDir in requirementsSubDirs:
            packageInstalled = install_package_dir_if_needed(packageDir, netboxVenvPy, packagesInstalled)
            logging.info(f"{os.path.basename(packageDir)} (dependency): {'' if packageInstalled else 'not ' }installed")
    else:
        logging.debug(f"no requirements subdirectory found under {args.customPluginsDir}")


def perform_migrations(netboxVenvPy, manageScript, pluginNames):
    success = True

    logging.info(f"performing migrations for plugin(s): {pluginNames}")
    with malcolm_utils.pushd(os.path.dirname(manageScript)):
        for plugin in pluginNames:
            cmd = [
                netboxVenvPy,
                os.path.basename(manageScript),
                "makemigrations",
                plugin,
                "--no-input",
                "--no-color",
            ]
            logging.debug(f"makemigrations command for {plugin}: {cmd}")
            err, results = malcolm_utils.run_process(cmd, logger=logging)
            if err != 0:
                logging.warning(f'{err} making migrations for {plugin}: {results}')
                success = False
            else:
                logging.debug(f"makemigrations succeeded for {plugin}")

        cmd = [
            netboxVenvPy,
            os.path.basename(manageScript),
            "migrate",
            "--no-input",
            "--no-color",
        ]
        logging.debug(f"migrate command: {cmd}")
        err, results = malcolm_utils.run_process(cmd, logger=logging)
        if err != 0:
            logging.warning(f'{err} migrating: {results}')
            success = False
        else:
            logging.debug("migrate succeeded")

    return success


def _plugin_search_locations(packages_installed):
    """Return sorted, existing package locations, including pip --target installs."""
    locations = {
        package['location']
        for package in packages_installed.values()
        if isinstance(package.get('location'), str) and os.path.isdir(package['location'])
    }
    custom_location = os.getenv('NETBOX_CUSTOM_VENV_PACKAGES_PATH', '')
    if os.path.isdir(custom_location):
        locations.add(custom_location)
    return sorted(locations)


def _is_plugin_config_class(node):
    """Recognize direct classes derived from NetBox's PluginConfig."""
    return isinstance(node, ast.ClassDef) and any(
        (isinstance(base, ast.Name) and base.id == 'PluginConfig')
        or (isinstance(base, ast.Attribute) and base.attr == 'PluginConfig')
        for base in node.bases
    )


def _static_plugin_name(item):
    """Extract a nonempty literal `name = ...` assignment, if present."""
    if not isinstance(item, ast.Assign):
        return None
    if not any(isinstance(target, ast.Name) and target.id == 'name' for target in item.targets):
        return None
    if isinstance(item.value, ast.Constant) and isinstance(item.value.value, str):
        return item.value.value or None
    return None


def _plugin_names_from_init(path):
    """Parse declared plugin names without importing or executing plugin code."""
    with open(path, 'r', encoding='utf-8') as handle:
        tree = ast.parse(handle.read(), filename=path)
    names = []
    for node in tree.body:
        if _is_plugin_config_class(node):
            logging.debug("found PluginConfig subclass '%s' in %s", node.name, path)
            name_found = False
            for item in node.body:
                name = _static_plugin_name(item)
                if name:
                    logging.info("discovered plugin name '%s' from class '%s' in %s", name, node.name, path)
                    names.append(name)
                    name_found = True
            if not name_found:
                logging.debug(
                    "class '%s' in %s has no valid literal 'name' assignment; skipping",
                    node.name,
                    path,
                )
    return names


def discover_plugin_names(search_locations):
    """Return ordered, unique plugin names from valid package directories."""
    if not search_locations:
        logging.debug('No package directories available for PluginConfig discovery')
        return []
    cmd = [
        '/usr/bin/rg',
        '--files-with-matches',
        '--iglob',
        '__init__.py',
        r'\bPluginConfig\b',
        *search_locations,
    ]
    logging.debug('PluginConfig search command: %s', cmd)
    error, paths = malcolm_utils.run_process(cmd, stderr=False, logger=logging)
    if error not in (0, 1):
        logging.warning('PluginConfig lookup returned error %s', error)
    logging.debug('rg found %d candidate __init__.py file(s): %s', len(paths or []), paths)
    names = set()
    for path in sorted(set(paths or [])):
        logging.debug('inspecting %s for PluginConfig subclasses', path)
        try:
            if os.path.isfile(path):
                names.update(_plugin_names_from_init(path))
            else:
                logging.debug('%s does not exist (or is not a file), skipping', path)
        except (OSError, SyntaxError, UnicodeError, ValueError) as error:
            logging.warning('Skipping invalid plugin configuration in %s: %s', path, error)
        except Exception as error:
            logging.error(
                '%s identifying NetBox plugin names in %s: %s',
                type(error).__name__,
                path,
                error,
            )
    return sorted(names)


def _last_top_level_plugins_assignment(tree):
    """Find the effective top-level PLUGINS assignment, not one in a function."""
    for node in reversed(tree.body):
        if isinstance(node, ast.Assign) and any(
            isinstance(target, ast.Name) and target.id == 'PLUGINS' for target in node.targets
        ):
            return node
    return None


def _append_missing_plugin_names(assignment, names):
    """Append only unknown names to an existing literal list."""
    installed = {
        value.value
        for value in assignment.value.elts
        if isinstance(value, ast.Constant) and isinstance(value.value, str)
    }
    logging.debug('existing plugins already listed: %s', sorted(installed))
    missing = []
    for name in names:
        if name in installed:
            logging.debug("'%s' already present in PLUGINS list, not re-adding", name)
        else:
            logging.info("adding '%s' to PLUGINS list in plugins.py", name)
            missing.append(name)
            installed.add(name)
    assignment.value.elts.extend(ast.Constant(value=name) for name in missing)
    return bool(missing)


def register_plugin_names(config_path, plugin_names):
    """Add missing plugin names to a top-level PLUGINS list, if statically defined."""
    names = sorted(set(plugin_names))
    if not names:
        return False
    logging.debug('parsing %s', config_path)
    with open(config_path, 'r', encoding='utf-8') as handle:
        tree = ast.parse(handle.read(), filename=config_path)

    existing = _last_top_level_plugins_assignment(tree)
    if existing:
        logging.debug('found existing top-level PLUGINS assignment in plugins.py')
        if not isinstance(existing.value, ast.List):
            logging.warning('PLUGINS exists but is dynamically defined; leaving config unchanged')
            return False
        if not _append_missing_plugin_names(existing, names):
            logging.debug('plugins.py already contains all discovered plugin names, no rewrite needed')
            return False
    else:
        logging.debug('no top-level PLUGINS assignment found in plugins.py, appending a new one')
        for name in names:
            logging.info("adding '%s' to PLUGINS list in plugins.py", name)
        tree.body.append(
            ast.Assign(
                targets=[ast.Name(id='PLUGINS', ctx=ast.Store())],
                value=ast.List(elts=[ast.Constant(value=name) for name in names], ctx=ast.Load()),
            )
        )
    logging.info('writing updated plugins.py to %s', config_path)
    with open(config_path, 'w', encoding='utf-8') as handle:
        handle.write(ast.unparse(ast.fix_missing_locations(tree)))
    return True


def _install_custom_plugin_dirs(args, netbox_venv_py, installed_packages):
    """Install custom plugin packages, returning those actually changed."""
    candidates = sorted(
        malcolm_utils.remove_suffix(item.path, '/')
        for item in os.scandir(args.customPluginsDir)
        if item.is_dir() and item.name != 'requirements'
    )
    updated = []
    logging.debug('Candidate plugin directories: %s', candidates)
    for directory in candidates:
        installed = install_package_dir_if_needed(directory, netbox_venv_py, installed_packages)
        if installed:
            updated.append(directory)
        logging.info("%s: %sinstalled", os.path.basename(directory), '' if installed else 'not ')
    return updated


def install_plugins(args):
    if not os.path.isdir(args.customPluginsDir) or not os.path.isfile(os.path.join(args.netboxConfigDir, 'plugins.py')):
        logging.debug(
            f"skipping plugin install: customPluginsDir={args.customPluginsDir} "
            f"(exists={os.path.isdir(args.customPluginsDir)}), "
            f"plugins.py exists={os.path.isfile(os.path.join(args.netboxConfigDir, 'plugins.py'))}"
        )
        return

    netboxVenvPy = os.path.join(os.path.join(os.path.join(args.netboxDir, 'venv'), 'bin'), 'python')
    manageScript = os.path.join(os.path.join(args.netboxDir, 'netbox'), 'manage.py')

    # get a list of what packages/plugins already installed (package names and versions in a dict)
    packagesInstalled = get_installed_packages(netboxVenvPy)
    logging.debug(f"{len(packagesInstalled)} package(s) currently installed in venv")

    # if there is a "requirements" subdirectory, handle that first as it contains dependencies
    install_requirements(args, netboxVenvPy, packagesInstalled)

    # Install custom plugins separately from their static configuration discovery.
    installedOrUpdatedPlugins = _install_custom_plugin_dirs(args, netboxVenvPy, packagesInstalled)
    # for any packages that were newly installed (or updated, we'll be thorough) we need to make
    # sure the package name is in plugins.py.
    logging.info('Plugins installed or updated: %s', installedOrUpdatedPlugins)
    if installedOrUpdatedPlugins:
        # get updated list of installed packages
        logging.debug("refreshing installed package list after install/update")
        packagesInstalled = get_installed_packages(netboxVenvPy)

    # Keep discovery independent of pip list so --target installs are included.
    search_locations = _plugin_search_locations(packagesInstalled)
    logging.debug('Searching package directories for plugins: %s', search_locations)
    pluginNames = discover_plugin_names(search_locations)
    pluginsListModified = False
    if pluginNames:
        logging.info('plugin names to ensure are registered in plugins.py: %s', pluginNames)
        pluginsListModified = register_plugin_names(os.path.join(args.netboxConfigDir, 'plugins.py'), pluginNames)
    else:
        logging.debug('No plugins found; plugins.py left untouched')

    if installedOrUpdatedPlugins or pluginsListModified:
        logging.debug("changes detected, running migrations")
        perform_migrations(netboxVenvPy, manageScript, pluginNames)
    else:
        logging.debug("no new/updated plugins and no plugins.py changes, skipping migrations")


def collect_static(args):
    netboxVenvPy = os.path.join(os.path.join(os.path.join(args.netboxDir, 'venv'), 'bin'), 'python')
    manageScript = os.path.join(os.path.join(args.netboxDir, 'netbox'), 'manage.py')

    success = True

    logging.info("collecting static files")
    with malcolm_utils.pushd(os.path.dirname(manageScript)):
        cmd = [
            netboxVenvPy,
            os.path.basename(manageScript),
            "collectstatic",
            "--no-input",
            "--no-color",
        ]
        logging.debug(f"collectstatic command: {cmd}")
        err, results = malcolm_utils.run_process(cmd, logger=logging)
        if err != 0:
            logging.warning(f'{err} collecting static files: {results}')
            success = False
        else:
            logging.debug("collectstatic succeeded")

    return success


###################################################################################################
# main
def main():
    args = parse_args()
    write_local_settings(args)
    install_plugins(args)
    collect_static(args)


###################################################################################################
if __name__ == '__main__':
    main()
