#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import getpass
import logging
import os
import platform
import shutil
import sys
import tempfile

from collections import defaultdict

try:
    from pwd import getpwuid
except ImportError:
    getpwuid = None

from mmguero import eprint, Which
import mmguero

###################################################################################################
PLATFORM_WINDOWS = "Windows"
PLATFORM_MAC = "Darwin"
PLATFORM_LINUX = "Linux"
PLATFORM_LINUX_CENTOS = 'centos'
PLATFORM_LINUX_DEBIAN = 'debian'
PLATFORM_LINUX_FEDORA = 'fedora'
PLATFORM_LINUX_UBUNTU = 'ubuntu'

# URLS for figuring things out if something goes wrong
FLUENTBIT_INSTALL_URLS = defaultdict(
    lambda: 'https://docs.fluentbit.io/manual/installation/getting-started-with-fluent-bit'
)
FLUENTBIT_INSTALL_URLS[PLATFORM_WINDOWS] = 'https://docs.fluentbit.io/manual/installation/windows'
FLUENTBIT_INSTALL_URLS[PLATFORM_LINUX] = 'https://docs.fluentbit.io/manual/installation/linux'
FLUENTBIT_INSTALL_URLS[PLATFORM_LINUX_UBUNTU] = 'https://docs.fluentbit.io/manual/installation/linux/ubuntu'
FLUENTBIT_INSTALL_URLS[PLATFORM_LINUX_DEBIAN] = 'https://docs.fluentbit.io/manual/installation/linux/debian'
FLUENTBIT_INSTALL_URLS[PLATFORM_LINUX_CENTOS] = 'https://docs.fluentbit.io/manual/installation/linux/redhat-centos'
FLUENTBIT_INSTALL_URLS[PLATFORM_MAC] = 'https://docs.fluentbit.io/manual/installation/macos'
HOMEBREW_INSTALL_URLS = defaultdict(lambda: 'https://brew.sh/')

###################################################################################################
args = None
script_name = os.path.basename(__file__)
script_path = os.path.dirname(os.path.realpath(__file__))
orig_path = os.getcwd()

###################################################################################################
class Installer(object):

    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    def __init__(self):
        self.command_debug = logging.getLogger(__name__).getEffectiveLevel() <= logging.DEBUG

        logging.info(type(self).__name__)

        self.platform = platform.system()
        self.scriptUser = getpass.getuser()

        self.checkPackageCmds = []
        self.installPackageCmds = []

        self.tempDirName = tempfile.mkdtemp()

    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    def __del__(self):
        shutil.rmtree(self.tempDirName, ignore_errors=True)

    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    def run_process(self, command, stdout=True, stderr=True, stdin=None, privileged=False, retry=0, retrySleepSec=5):

        # if privileged, put the sudo command at the beginning of the command
        if privileged and (len(self.sudoCmd) > 0):
            command = self.sudoCmd + command

        return mmguero.RunProcess(
            command,
            stdout=stdout,
            stderr=stderr,
            stdin=stdin,
            retry=retry,
            retrySleepSec=retrySleepSec,
            debug=self.command_debug,
        )

    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    def package_is_installed(self, package):
        result = False
        for cmd in self.checkPackageCmds:
            ecode, out = self.run_process(cmd + [package])
            if ecode == 0:
                result = True
                break
        return result

    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    def install_package(self, packages):

        result = False
        pkgs = []

        for package in packages:
            if not self.package_is_installed(package):
                pkgs.append(package)

        if len(pkgs) > 0:
            for cmd in self.installPackageCmds:
                ecode, out = self.run_process(cmd + pkgs, privileged=True)
                if ecode == 0:
                    result = True
                    break
        else:
            result = True

        return result

    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    def install_fluentbit(self, bin='fluent-bit'):
        if Which(bin, debug=self.command_debug):
            logging.info(f'{bin} is already installed, check your package manager for updates')
            return True
        else:
            return False


###################################################################################################
class LinuxInstaller(Installer):

    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    def __init__(self):
        super().__init__()

        self.distro = None
        self.codename = None
        self.release = None

        # determine the distro (e.g., ubuntu) and code name (e.g., bionic) if applicable

        # check /etc/os-release values first
        if os.path.isfile('/etc/os-release'):
            osInfo = dict()

            with open("/etc/os-release", 'r') as f:
                for line in f:
                    try:
                        k, v = line.rstrip().split("=")
                        osInfo[k] = v.strip('"')
                    except:
                        pass

            if ('NAME' in osInfo) and (len(osInfo['NAME']) > 0):
                distro = osInfo['NAME'].lower().split()[0]

            if ('VERSION_CODENAME' in osInfo) and (len(osInfo['VERSION_CODENAME']) > 0):
                codename = osInfo['VERSION_CODENAME'].lower().split()[0]

            if ('VERSION_ID' in osInfo) and (len(osInfo['VERSION_ID']) > 0):
                release = osInfo['VERSION_ID'].lower().split()[0]

        # try lsb_release next
        if self.distro is None:
            err, out = self.run_process(['lsb_release', '-is'], stderr=False)
            if (err == 0) and (len(out) > 0):
                self.distro = out[0].lower()

        if self.codename is None:
            err, out = self.run_process(['lsb_release', '-cs'], stderr=False)
            if (err == 0) and (len(out) > 0):
                self.codename = out[0].lower()

        if self.release is None:
            err, out = self.run_process(['lsb_release', '-rs'], stderr=False)
            if (err == 0) and (len(out) > 0):
                self.release = out[0].lower()

        # try release-specific files
        if self.distro is None:
            if os.path.isfile('/etc/centos-release'):
                distroFile = '/etc/centos-release'
            if os.path.isfile('/etc/redhat-release'):
                distroFile = '/etc/redhat-release'
            elif os.path.isfile('/etc/issue'):
                distroFile = '/etc/issue'
            else:
                distroFile = None
            if distroFile is not None:
                with open(distroFile, 'r') as f:
                    distroVals = f.read().lower().split()
                    distroNums = [x for x in distroVals if x[0].isdigit()]
                    self.distro = distroVals[0]
                    if (self.release is None) and (len(distroNums) > 0):
                        self.release = distroNums[0]

        if self.distro is None:
            self.distro = "linux"

        logging.info(
            f"distro: {self.distro}{f' {self.codename}' if self.codename else ''}{f' {self.release}' if self.release else ''}"
        )

        if not self.codename:
            self.codename = self.distro

        # on Linux this script requires root, or sudo, unless we're in local configuration-only mode
        if os.getuid() == 0:
            self.scriptUser = "root"
            self.sudoCmd = []
        else:
            self.sudoCmd = ["sudo", "-n"]
            err, out = self.run_process(['whoami'], privileged=True)
            if (err != 0) or (len(out) == 0) or (out[0] != 'root'):
                raise Exception(f'{script_name} must be run as root, or {self.sudoCmd} must be available')

        # determine command to use to query if a package is installed
        if Which('dpkg', debug=self.command_debug):
            os.environ["DEBIAN_FRONTEND"] = "noninteractive"
            self.checkPackageCmds.append(['dpkg', '-s'])
        elif Which('rpm', debug=self.command_debug):
            self.checkPackageCmds.append(['rpm', '-q'])
        elif Which('dnf', debug=self.command_debug):
            self.checkPackageCmds.append(['dnf', 'list', 'installed'])
        elif Which('yum', debug=self.command_debug):
            self.checkPackageCmds.append(['yum', 'list', 'installed'])

        # determine command to install a package from the distro's repos
        if Which('apt-get', debug=self.command_debug):
            self.installPackageCmds.append(['apt-get', 'install', '-y', '-qq'])
        elif Which('apt', debug=self.command_debug):
            self.installPackageCmds.append(['apt', 'install', '-y', '-qq'])
        elif Which('dnf', debug=self.command_debug):
            self.installPackageCmds.append(['dnf', '-y', 'install', '--nobest'])
        elif Which('yum', debug=self.command_debug):
            self.installPackageCmds.append(['yum', '-y', 'install'])

    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    def install_fluentbit(self):
        result = super().install_fluentbit('fluent-bit')

        if not result and mmguero.YesOrNo(
            'Attempt to install fluent-bit via convenience script (please read https://docs.fluentbit.io/manual/installation/linux)?',
            default=False,
        ):
            # download and run the fluent-bit installer script
            scriptUrl = "https://raw.githubusercontent.com/fluent/fluent-bit/master/install.sh"
            tempFileName = os.path.join(self.tempDirName, 'install.sh')
            if mmguero.DownloadToFile(
                scriptUrl,
                tempFileName,
                debug=self.command_debug,
            ):
                os.chmod(tempFileName, 493)  # 493 = 0o755
                err, out = self.run_process(([tempFileName]), privileged=True)
                if err == 0:
                    logging.debug("Installation of fluent-bit apparently succeeded")
                    result = True

                    # we don't necessarily want to start a system service, so disable that for now
                    err, out = self.run_process(['systemctl', 'stop', 'fluent-bit'], privileged=True)
                    if err == 0:
                        err, out = self.run_process(['systemctl', 'disable', 'fluent-bit'], privileged=True)
                        if err != 0:
                            logging.debug(f"Disabling fluent-bit service failed: {out}")
                    else:
                        logging.debug(f"Stopping fluent-bit service failed: {out}")

                else:
                    logging.error(f"Installation of fluent-bit failed: {out}")
            else:
                logging.error(f"Downloading {scriptUrl} to {tempFileName} failed")

        return result


###################################################################################################
class MacInstaller(Installer):

    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    def __init__(self, debug=False):
        super().__init__()

        self.sudoCmd = []

        # first see if brew is already installed and runnable
        err, out = self.run_process(['brew', 'info'])
        self.useBrew = err == 0

        if self.useBrew:
            self.checkPackageCmds.append(['brew', 'ls', '--versions'])
            self.installPackageCmds.append(['brew', 'install'])

    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    def install_fluentbit(self):
        result = super().install_fluentbit('fluent-bit')

        if not result:
            if self.useBrew:
                if mmguero.YesOrNo(
                    'Attempt to install fluent-bit with brew?',
                    default=False,
                ):
                    if self.install_package(['fluent-bit']):
                        logging.debug("Installation of fluent-bit apparently succeeded")
                        result = True
                    else:
                        logging.error(f"Installation of fluent-bit failed")
            else:
                logging.error(
                    f'Follow the steps at {HOMEBREW_INSTALL_URLS[self.platform]} to install Homebrew, then re-run {script_name}'
                )

        return result


###################################################################################################
class WindowsInstaller(Installer):

    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    def __init__(self):
        super().__init__()

    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    def install_fluentbit(self):
        result = super().install_fluentbit('fluent-bit.exe')


###################################################################################################
# main
def main():
    global args

    parser = argparse.ArgumentParser(
        description='\n'.join(
            [
                'Do some stuff.',
            ]
        ),
        formatter_class=argparse.RawTextHelpFormatter,
        add_help=False,
        usage='{} <arguments>'.format(script_name),
    )
    parser.add_argument('--verbose', '-v', action='count', default=0, help='Increase verbosity (e.g., -v, -vv, etc.)')
    try:
        parser.error = parser.exit
        args = parser.parse_args()
    except SystemExit:
        parser.print_help()
        exit(2)

    levels = [logging.WARNING, logging.INFO, logging.DEBUG]
    args.verbose = levels[min(args.verbose, len(levels) - 1)]
    logging.basicConfig(
        level=args.verbose, format='%(asctime)s %(levelname)s: %(message)s', datefmt='%Y-%m-%d %H:%M:%S'
    )
    logging.debug(os.path.join(script_path, script_name))
    logging.debug("Arguments: {}".format(sys.argv[1:]))
    logging.debug("Arguments: {}".format(args))
    if args.verbose > logging.DEBUG:
        sys.tracebacklimit = 0

    installerPlatform = platform.system()
    if installerPlatform == PLATFORM_LINUX:
        installer = LinuxInstaller()
    elif installerPlatform == PLATFORM_MAC:
        installer = MacInstaller()
    elif installerPlatform == PLATFORM_WINDOWS:
        installer = WindowsInstaller()

    success = hasattr(installer, 'install_fluentbit') and installer.install_fluentbit()
    if not success:
        logging.error(
            f'Follow the steps at {HOMEBREW_INSTALL_URLS[installerPlatform]} to install fluent-bit manually, then re-run {script_name}'
        )

    if success and hasattr(installer, 'next_step'):
        installer.next_step()


###################################################################################################
if __name__ == '__main__':
    main()
