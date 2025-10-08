#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2025 Battelle Energy Alliance, LLC.  All rights reserved.

import sys
import os

# Add the project root directory to the Python path
script_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.abspath(os.path.join(script_dir, ".."))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

sys.dont_write_bytecode = True

import argparse
import datetime
import errno
import fileinput
import getpass
import glob
import json
import logging
import os
import pathlib
import platform
import pprint
import math
import re
import shutil
import sys
import tarfile
import tempfile
import time

try:
    from pwd import getpwuid
except ImportError:
    getpwuid = None
from collections import defaultdict, namedtuple
from enum import IntEnum

from malcolm_constants import (
    PLATFORM_WINDOWS,
    PLATFORM_MAC,
    PLATFORM_LINUX,
    PLATFORM_LINUX_CENTOS,
    PLATFORM_LINUX_DEBIAN,
    PLATFORM_LINUX_FEDORA,
    PLATFORM_LINUX_UBUNTU,
    PLATFORM_LINUX_ROCKY,
    PLATFORM_LINUX_ALMA,
    PLATFORM_LINUX_AMAZON,
    PROFILE_MALCOLM,
    PROFILE_HEDGEHOG,
    PROFILE_KEY,
    CONTAINER_RUNTIME_KEY,
    DatabaseMode,
    DATABASE_MODE_LABELS,
    DATABASE_MODE_ENUMS,
    MALCOLM_DB_DIR,
    MALCOLM_PCAP_DIR,
    MALCOLM_LOGS_DIR,
)

from malcolm_common import (
    AskForString,
    BoundPathReplacer,
    ChooseMultiple,
    ChooseOne,
    DetermineYamlFileFormat,
    DialogInit,
    DialogBackException,
    DialogCanceledException,
    DisplayMessage,
    DOCKER_COMPOSE_INSTALL_URLS,
    DOCKER_INSTALL_URLS,
    DotEnvDynamic,
    DownloadToFile,
    DumpYaml,
    EnvValue,
    HOMEBREW_INSTALL_URLS,
    KubernetesDynamic,
    LoadYaml,
    MalcolmCfgRunOnceFile,
    GetMalcolmPath,
    SetMalcolmPath,
    OrchestrationFramework,
    OrchestrationFrameworksSupported,
    RequestsDynamic,
    ScriptPath,
    UpdateEnvFiles,
    UserInputDefaultsBehavior,
    UserInterfaceMode,
    ValidNetBoxSubnetFilter,
    YAMLDynamic,
    YesOrNo,
)
from malcolm_utils import (
    ChownRecursive,
    CountUntilException,
    deep_get,
    deep_set,
    flatten,
    get_iterable,
    LoadFileIfJson,
    log_level_is_debug,
    remove_prefix,
    remove_suffix,
    run_process,
    set_logging,
    get_verbosity_env_var_count,
    same_file_or_dir,
    str2bool,
    touch,
    which,
    GetPlatformOSRelease
)

###################################################################################################
DOCKER_COMPOSE_INSTALL_VERSION = "2.23.0"

DEB_GPG_KEY_FINGERPRINT = '0EBFCD88'  # used to verify GPG key for Docker Debian repository

MAC_BREW_DOCKER_PACKAGE = 'docker'
MAC_BREW_DOCKER_COMPOSE_PACKAGE = 'docker-compose'
MAC_BREW_DOCKER_SETTINGS = '/Users/{}/Library/Group Containers/group.com.docker/settings.json'

BACK_LABEL = 'Go Back'

LOGSTASH_JAVA_OPTS_DEFAULT = '-server -Xmx3g -Xms3g -Xss2048k -XX:-HeapDumpOnOutOfMemoryError -Djava.security.egd=file:/dev/./urandom -Dlog4j.formatMsgNoLookups=true'
OPENSEARCH_JAVA_OPTS_DEFAULT = '-server -Xmx10g -Xms10g -Xss256k -XX:-HeapDumpOnOutOfMemoryError -Djava.security.egd=file:/dev/./urandom -Dlog4j.formatMsgNoLookups=true'

###################################################################################################
ScriptName = os.path.basename(__file__)
origPath = os.getcwd()

###################################################################################################
args = None
raw_args = None
requests_imported = None
yaml_imported = None
kube_imported = None
dotenv_imported = None

###################################################################################################
TrueOrFalseQuote = lambda x: "'true'" if x else "'false'"
TrueOrFalseNoQuote = lambda x: 'true' if x else 'false'
MaxAskForValueCount = 100

str2percent = lambda val: max(min(100, int(remove_suffix(val, '%'))), 0) if val else 0


class ConfigOptions(IntEnum):
    Preconfig = 0
    UidGuid = 1
    NodeName = 2
    RunProfile = 3
    DatabaseMode = 4
    LogstashRemote = 5
    ContainerResources = 6
    RestartMode = 7
    RequireHTTPS = 8
    DockerNetworking = 9
    StorageLocations = 10
    ILMISM = 11
    StorageManagement = 12
    AutoArkime = 13
    AutoSuricata = 14
    SuricataRuleUpdate = 15
    AutoZeek = 16
    ICS = 17
    Enrichment = 18
    OpenPorts = 19
    FileCarving = 20
    ZeekIntel = 21
    NetBox = 22
    Capture = 23
    DarkMode = 24
    PostConfig = 25


###################################################################################################
# get interactive user response to Y/N question
def InstallerYesOrNo(
    question,
    default=None,
    forceInteraction=False,
    defaultBehavior=UserInputDefaultsBehavior.DefaultsPrompt | UserInputDefaultsBehavior.DefaultsAccept,
    uiMode=UserInterfaceMode.InteractionInput | UserInterfaceMode.InteractionDialog,
    yesLabel='Yes',
    noLabel='No',
    extraLabel=None,
):
    defBehavior = defaultBehavior
    if args.acceptDefaultsNonInteractive and not forceInteraction:
        defBehavior = defBehavior + UserInputDefaultsBehavior.DefaultsNonInteractive

    return YesOrNo(
        question,
        default=default,
        defaultBehavior=defBehavior,
        uiMode=uiMode,
        yesLabel=yesLabel,
        noLabel=noLabel,
        extraLabel=extraLabel,
    )


###################################################################################################
# get interactive user response string
def InstallerAskForString(
    question,
    default=None,
    forceInteraction=False,
    defaultBehavior=UserInputDefaultsBehavior.DefaultsPrompt | UserInputDefaultsBehavior.DefaultsAccept,
    uiMode=UserInterfaceMode.InteractionInput | UserInterfaceMode.InteractionDialog,
    extraLabel=None,
):
    defBehavior = defaultBehavior
    if args.acceptDefaultsNonInteractive and not forceInteraction:
        defBehavior = defBehavior + UserInputDefaultsBehavior.DefaultsNonInteractive

    return AskForString(
        question,
        default=default,
        defaultBehavior=defBehavior,
        uiMode=uiMode,
        extraLabel=extraLabel,
    )


###################################################################################################
# choose one from a list
def InstallerChooseOne(
    prompt,
    choices=[],
    forceInteraction=False,
    defaultBehavior=UserInputDefaultsBehavior.DefaultsPrompt | UserInputDefaultsBehavior.DefaultsAccept,
    uiMode=UserInterfaceMode.InteractionInput | UserInterfaceMode.InteractionDialog,
    extraLabel=None,
):
    defBehavior = defaultBehavior
    if args.acceptDefaultsNonInteractive and not forceInteraction:
        defBehavior = defBehavior + UserInputDefaultsBehavior.DefaultsNonInteractive

    return ChooseOne(
        prompt,
        choices=choices,
        defaultBehavior=defBehavior,
        uiMode=uiMode,
        extraLabel=extraLabel,
    )


###################################################################################################
# choose multiple from a list
def InstallerChooseMultiple(
    prompt,
    choices=[],
    forceInteraction=False,
    defaultBehavior=UserInputDefaultsBehavior.DefaultsPrompt | UserInputDefaultsBehavior.DefaultsAccept,
    uiMode=UserInterfaceMode.InteractionInput | UserInterfaceMode.InteractionDialog,
    extraLabel=None,
):
    defBehavior = defaultBehavior
    if args.acceptDefaultsNonInteractive and not forceInteraction:
        defBehavior = defBehavior + UserInputDefaultsBehavior.DefaultsNonInteractive

    return ChooseMultiple(
        prompt,
        choices=choices,
        defaultBehavior=defBehavior,
        uiMode=uiMode,
        extraLabel=extraLabel,
    )


###################################################################################################
# display a message to the user without feedback
def InstallerDisplayMessage(
    message,
    forceInteraction=False,
    defaultBehavior=UserInputDefaultsBehavior.DefaultsPrompt | UserInputDefaultsBehavior.DefaultsAccept,
    uiMode=UserInterfaceMode.InteractionInput | UserInterfaceMode.InteractionDialog,
    extraLabel=None,
):
    defBehavior = defaultBehavior
    if args.acceptDefaultsNonInteractive and not forceInteraction:
        defBehavior = defBehavior + UserInputDefaultsBehavior.DefaultsNonInteractive

    return DisplayMessage(
        message,
        defaultBehavior=defBehavior,
        uiMode=uiMode,
        extraLabel=extraLabel,
    )


def DetermineUid(
    scriptUser,
    scriptPlatform,
    referencePath,
):
    defaultUid = '1000'
    defaultGid = '1000'
    if ((scriptPlatform == PLATFORM_LINUX) or (scriptPlatform == PLATFORM_MAC)) and (scriptUser == "root"):
        if pathUid := os.stat(referencePath).st_uid:
            defaultUid = str(pathUid)
        if pathGid := os.stat(referencePath).st_gid:
            defaultGid = str(pathGid)

    uid = defaultUid
    gid = defaultGid
    try:
        if scriptPlatform == PLATFORM_LINUX:
            uid = str(os.getuid())
            gid = str(os.getgid())
            if (uid == '0') or (gid == '0'):
                raise Exception('it is preferrable not to run Malcolm as root, prompting for UID/GID instead')
    except Exception:
        uid = defaultUid
        gid = defaultGid

    return uid, gid


###################################################################################################
class Installer(object):
    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    def __init__(self, orchMode, configOnly=False):
        self.orchMode = orchMode
        self.configOnly = configOnly
        self.debug = log_level_is_debug(args.verbose)

        self.platform = platform.system()
        self.scriptUser = getpass.getuser()

        self.checkPackageCmds = []
        self.installPackageCmds = []
        self.requiredPackages = []
        self.dockerComposeCmd = None

        self.tempDirName = tempfile.mkdtemp()

        self.pipCmd = None
        self.ensure_pip()

        self.totalMemoryGigs = 0.0
        self.totalCores = 0

    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    def __del__(self):
        shutil.rmtree(self.tempDirName, ignore_errors=True)

    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    def run_process(self, command, stdout=True, stderr=True, stdin=None, privileged=False, retry=0, retrySleepSec=5):
        # if privileged, put the sudo command at the beginning of the command
        if privileged and (len(self.sudoCmd) > 0):
            command = self.sudoCmd + command

        return run_process(
            command,
            stdout=stdout,
            stderr=stderr,
            stdin=stdin,
            retry=retry,
            retrySleepSec=retrySleepSec,
            debug=self.debug,
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
    def install_required_packages(self):
        if len(self.requiredPackages) > 0:
            logging.info(f"Installing required packages: {self.requiredPackages}")
        return self.install_package(self.requiredPackages)

    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    def ensure_pip(self, prompt_to_bootstrap=False):
        if not self.pipCmd:
            if which('pip3', debug=self.debug):
                self.pipCmd = 'pip3'
            else:
                err, out = self.run_process([sys.executable, '-m', 'pip', '--version'])
                if out and (err == 0):
                    self.pipCmd = [sys.executable, '-m', 'pip']
                elif prompt_to_bootstrap and InstallerYesOrNo(
                    f"Python's pip package manager is not available, attempt to install with \"ensurepip\"?",
                    default=False,
                    forceInteraction=True,
                ):
                    err, out = self.run_process([sys.executable, '-m', 'ensurepip', '--upgrade'])
                    if out and (err == 0):
                        err, out = self.run_process([sys.executable, '-m', 'pip', '--version'])
                        if out and (err == 0):
                            self.pipCmd = [sys.executable, '-m', 'pip']

        return self.pipCmd

    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    def install_docker_images(self, docker_image_file, malcolm_install_path):
        result = False
        composeFile = os.path.join(malcolm_install_path, 'docker-compose.yml')

        if self.orchMode is OrchestrationFramework.DOCKER_COMPOSE:
            if (
                docker_image_file
                and os.path.isfile(docker_image_file)
                and InstallerYesOrNo(
                    f'Load Malcolm images from {docker_image_file}?', default=True, forceInteraction=True
                )
            ):
                ecode, out = self.run_process([args.runtimeBin, 'load', '-q', '-i', docker_image_file], privileged=True)
                if ecode == 0:
                    result = True
                else:
                    logging.error(f"Loading Malcolm images failed: {out}")

            elif (
                os.path.isfile(composeFile)
                and self.dockerComposeCmd
                and InstallerYesOrNo(f'Pull Malcolm images?', default=False, forceInteraction=False)
            ):
                for priv in (False, True):
                    pullCmd = [self.dockerComposeCmd, '-f', composeFile, '--profile=malcolm', 'pull', '--quiet']
                    ecode, out = self.run_process(pullCmd, privileged=priv)
                    if ecode == 0:
                        break
                    elif any('unrecognized arguments: --quiet' in s for s in out):
                        pullCmd.remove('--quiet')
                        ecode, out = self.run_process(pullCmd, privileged=priv)
                        if ecode == 0:
                            break

                if ecode == 0:
                    result = True
                else:
                    logging.error(f"Pulling Malcolm images failed: {out}")

        return result

    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    def install_malcolm_files(self, malcolm_install_file, default_config_dir):
        global args
        result = False
        installPath = None
        if (
            malcolm_install_file
            and os.path.isfile(malcolm_install_file)
            and InstallerYesOrNo(
                f'Extract Malcolm runtime files from {malcolm_install_file}?', default=True, forceInteraction=True
            )
        ):
            # determine and create destination path for installation
            loopBreaker = CountUntilException(MaxAskForValueCount, 'Invalid installation path')
            while loopBreaker.increment():
                defaultPath = os.path.join(origPath, 'Malcolm')
                installPath = InstallerAskForString(
                    f'Enter installation path for Malcolm [{defaultPath}]', default=defaultPath, forceInteraction=True
                )
                if len(installPath) == 0:
                    installPath = defaultPath
                if os.path.isdir(installPath):
                    logging.error(f"{installPath} already exists, please specify a different installation path")
                else:
                    try:
                        os.makedirs(installPath)
                    except Exception:
                        pass
                    if os.path.isdir(installPath):
                        break
                    else:
                        logging.error(f"Failed to create {installPath}, please specify a different installation path")

            # extract runtime files
            if installPath and os.path.isdir(installPath):
                SetMalcolmPath(installPath)
                logging.info(f"Created {installPath} for Malcolm runtime files")

                # extract the .tar.gz and chown the results
                extUid, extGid = DetermineUid(self.scriptUser, self.platform, malcolm_install_file)
                tar = tarfile.open(malcolm_install_file)
                try:
                    tar.extractall(path=installPath, numeric_owner=True)
                finally:
                    tar.close()
                ChownRecursive(installPath, extUid, extGid)

                # .tar.gz normally will contain an intermediate subdirectory. if so, move files back one level
                childDir = glob.glob(f'{installPath}/*/')
                if (len(childDir) == 1) and os.path.isdir(childDir[0]):
                    logging.debug(f"{installPath} only contains {childDir[0]}")
                    for f in os.listdir(childDir[0]):
                        shutil.move(os.path.join(childDir[0], f), installPath)
                    shutil.rmtree(childDir[0], ignore_errors=True)

                # create the config directory for the .env files
                if default_config_dir:
                    args.configDir = os.path.join(installPath, 'config')
                try:
                    os.makedirs(args.configDir)
                except OSError as exc:
                    if (exc.errno == errno.EEXIST) and os.path.isdir(args.configDir):
                        pass
                    else:
                        raise
                logging.info(f"Created {args.configDir} for Malcolm configuration files")

                # verify the installation worked
                if os.path.isfile(os.path.join(installPath, "docker-compose.yml")):
                    logging.info(f"Malcolm runtime files extracted to {installPath}")
                    result = True
                else:
                    logging.error(f"Malcolm install file extracted to {installPath}, but missing runtime files")

        return result, installPath

    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    def tweak_malcolm_runtime(self, malcolm_install_path):
        global raw_args
        global dotenv_imported

        configFiles = []

        if self.orchMode is OrchestrationFramework.DOCKER_COMPOSE:
            # determine docker-compose files
            if not args.configFile:
                # get a list of all of the docker-compose files
                configFiles = glob.glob(os.path.join(malcolm_install_path, 'docker-compose*.yml'))

            elif os.path.isfile(args.configFile):
                # single docker-compose file explicitly specified
                configFiles = [os.path.realpath(args.configFile)]
                malcolm_install_path = os.path.dirname(configFiles[0])

        elif self.orchMode is OrchestrationFramework.KUBERNETES:
            if args.configFile and os.path.isfile(args.configFile):
                configFiles = [os.path.realpath(args.configFile)]
                malcolm_install_path = os.path.realpath(os.path.join(ScriptPath, ".."))
            else:
                raise Exception(f"{self.orchMode} requires specifying kubeconfig file via -f/--config-file")

        if (not args.configDir) or (not os.path.isdir(args.configDir)):
            raise Exception("Could not determine configuration directory containing Malcolm's .env files")

        if self.orchMode is OrchestrationFramework.DOCKER_COMPOSE:
            # guestimate how much memory we should use based on total system memory

            logging.info(
                f'{malcolm_install_path} with "{configFiles}" and "{args.configDir}", system memory is {self.totalMemoryGigs} GiB'
            )

            if self.totalMemoryGigs >= 63.0:
                osMemory = '24g'
                lsMemory = '4g'
            elif self.totalMemoryGigs >= 30.0:
                osMemory = '16g'
                lsMemory = '3g'
            elif self.totalMemoryGigs >= 15.0:
                osMemory = '10g'
                lsMemory = '2500m'
            elif self.totalMemoryGigs >= 11.0:
                logging.warning(f"Detected only {self.totalMemoryGigs} GiB of memory; performance will be suboptimal")
                osMemory = '6g'
                lsMemory = '2g'
            elif self.totalMemoryGigs >= 7.0:
                logging.warning(f"Detected only {self.totalMemoryGigs} GiB of memory; performance will be suboptimal")
                osMemory = '4g'
                lsMemory = '2g'
            elif self.totalMemoryGigs > 0.0:
                logging.warning(f"Detected only {self.totalMemoryGigs} GiB of memory; performance will be suboptimal")
                osMemory = '3500m'
                lsMemory = '2g'
            else:
                logging.error("Failed to determine system memory size, using defaults; performance may be suboptimal")
                osMemory = '8g'
                lsMemory = '3g'
        else:
            osMemory = '16g'
            lsMemory = '3g'

        # see Tuning and Profiling Logstash Performance
        # - https://www.elastic.co/guide/en/logstash/current/tuning-logstash.html
        # - https://www.elastic.co/guide/en/logstash/current/logstash-settings-file.html
        # - https://www.elastic.co/guide/en/logstash/current/multiple-pipelines.html
        # we don't want it too high, as in Malcolm Logstash also competes with OpenSearch, etc. for resources
        if self.orchMode is OrchestrationFramework.DOCKER_COMPOSE:
            if self.totalCores > 16:
                lsWorkers = 6
            elif self.totalCores >= 12:
                lsWorkers = 4
            else:
                lsWorkers = 3
        else:
            lsWorkers = 6

        if args.osMemory:
            osMemory = args.osMemory
        if args.lsMemory:
            lsMemory = args.lsMemory
        if args.lsWorkers:
            lsWorkers = args.lsWorkers

        if args.opensearchPrimaryMode not in DATABASE_MODE_ENUMS.keys():
            raise Exception(f'"{args.opensearchPrimaryMode}" is not valid for --opensearch')

        if args.opensearchSecondaryMode and (args.opensearchSecondaryMode not in DATABASE_MODE_ENUMS.keys()):
            raise Exception(f'"{args.opensearchSecondaryMode}" is not valid for --opensearch-secondary')

        opensearchPrimaryMode = DatabaseMode.OpenSearchLocal
        opensearchPrimaryUrl = 'https://opensearch:9200'
        opensearchPrimarySslVerify = False
        opensearchPrimaryLabel = 'local OpenSearch'
        opensearchSecondaryMode = DatabaseMode.DatabaseUnset
        opensearchSecondaryUrl = ''
        opensearchSecondarySslVerify = False
        opensearchSecondaryLabel = 'remote OpenSearch'
        dashboardsUrl = 'http://dashboards:5601/dashboards'
        logstashHost = 'logstash:5044'
        syslogPortDict = defaultdict(lambda: 0)
        sftpOpen = False
        behindReverseProxy = False
        traefikLabels = False
        dockerNetworkExternalName = ""
        zeekIntelParamsProvided = False
        zeekIntelCronExpression = '0 0 * * *'
        zeekIntelFeedSince = '7 days ago'
        zeekIntelItemExipration = '-1min'
        zeekIntelOnStartup = True
        nginxResolverIpv4Off = False
        nginxResolverIpv6Off = False

        prevStep = None
        currentStep = ConfigOptions.Preconfig
        while True:
            prevStep = currentStep
            currentStep = ConfigOptions(int(currentStep) + 1)
            try:
                ###################################################################################
                if currentStep == ConfigOptions.Preconfig:
                    pass

                ###################################################################################
                elif currentStep == ConfigOptions.UidGuid:
                    # figure out what UID/GID to run non-root processes under docker as
                    puid, pgid = DetermineUid(self.scriptUser, self.platform, malcolm_install_path)
                    defaultUid, defaultGid = puid, pgid

                    loopBreaker = CountUntilException(MaxAskForValueCount, 'Invalid UID/GID')
                    while (
                        (not puid.isdigit())
                        or (not pgid.isdigit())
                        or (
                            not InstallerYesOrNo(
                                f'Malcolm processes will run as UID {puid} and GID {pgid}. Is this OK?',
                                default=True,
                            )
                        )
                    ) and loopBreaker.increment():
                        puid = InstallerAskForString(
                            'Enter user ID (UID) for running non-root Malcolm processes', default=defaultUid
                        )
                        pgid = InstallerAskForString(
                            'Enter group ID (GID) for running non-root Malcolm processes', default=defaultGid
                        )

                ###################################################################################
                elif currentStep == ConfigOptions.NodeName:
                    pcapNodeName = InstallerAskForString(
                        f'Enter the node name to associate with network traffic metadata',
                        default=args.pcapNodeName,
                        extraLabel=BACK_LABEL,
                    )

                ###################################################################################
                elif currentStep == ConfigOptions.RunProfile:
                    malcolmProfile = (
                        PROFILE_MALCOLM
                        if InstallerYesOrNo(
                            'Run with Malcolm (all containers) or Hedgehog (capture only) profile?',
                            default=args.malcolmProfile,
                            yesLabel='Malcolm',
                            noLabel='Hedgehog',
                            extraLabel=BACK_LABEL,
                        )
                        else PROFILE_HEDGEHOG
                    )

                ###################################################################################
                elif currentStep == ConfigOptions.DatabaseMode:
                    if (malcolmProfile == PROFILE_MALCOLM) and InstallerYesOrNo(
                        'Should Malcolm use and maintain its own OpenSearch instance?',
                        default=DATABASE_MODE_ENUMS[args.opensearchPrimaryMode] == DatabaseMode.OpenSearchLocal,
                        extraLabel=BACK_LABEL,
                    ):
                        opensearchPrimaryMode = DatabaseMode.OpenSearchLocal

                    else:
                        databaseModeChoice = ''
                        allowedDatabaseModes = {
                            DATABASE_MODE_LABELS[DatabaseMode.OpenSearchLocal]: [
                                DatabaseMode.OpenSearchLocal,
                                'local OpenSearch',
                            ],
                            DATABASE_MODE_LABELS[DatabaseMode.OpenSearchRemote]: [
                                DatabaseMode.OpenSearchRemote,
                                'remote OpenSearch',
                            ],
                            DATABASE_MODE_LABELS[DatabaseMode.ElasticsearchRemote]: [
                                DatabaseMode.ElasticsearchRemote,
                                'remote Elasticsearch',
                            ],
                        }
                        if malcolmProfile != PROFILE_MALCOLM:
                            del allowedDatabaseModes[DATABASE_MODE_LABELS[DatabaseMode.OpenSearchLocal]]
                        loopBreaker = CountUntilException(MaxAskForValueCount, 'Invalid primary document store mode')
                        while databaseModeChoice not in list(allowedDatabaseModes.keys()) and loopBreaker.increment():
                            databaseModeChoice = InstallerChooseOne(
                                'Select primary Malcolm document store',
                                choices=[
                                    (x, allowedDatabaseModes[x][1], x == args.opensearchPrimaryMode)
                                    for x in list(allowedDatabaseModes.keys())
                                ],
                                extraLabel=BACK_LABEL,
                            )
                        opensearchPrimaryMode = allowedDatabaseModes[databaseModeChoice][0]
                        opensearchPrimaryLabel = allowedDatabaseModes[databaseModeChoice][1]

                    if opensearchPrimaryMode in (DatabaseMode.OpenSearchRemote, DatabaseMode.ElasticsearchRemote):
                        loopBreaker = CountUntilException(MaxAskForValueCount, f'Invalid {opensearchPrimaryLabel} URL')
                        opensearchPrimaryUrl = ''
                        while (len(opensearchPrimaryUrl) <= 1) and loopBreaker.increment():
                            opensearchPrimaryUrl = InstallerAskForString(
                                f'Enter primary {opensearchPrimaryLabel} connection URL (e.g., https://192.168.1.123:9200)',
                                default=args.opensearchPrimaryUrl,
                                extraLabel=BACK_LABEL,
                            )
                        opensearchPrimarySslVerify = opensearchPrimaryUrl.lower().startswith(
                            'https'
                        ) and InstallerYesOrNo(
                            f'Require SSL certificate validation for communication with {opensearchPrimaryLabel} instance?',
                            default=args.opensearchPrimarySslVerify,
                            extraLabel=BACK_LABEL,
                        )

                    if opensearchPrimaryMode == DatabaseMode.ElasticsearchRemote:
                        loopBreaker = CountUntilException(MaxAskForValueCount, f'Invalid Kibana connection URL')
                        dashboardsUrl = ''
                        while (len(dashboardsUrl) <= 1) and loopBreaker.increment():
                            dashboardsUrl = InstallerAskForString(
                                f'Enter Kibana connection URL (e.g., https://192.168.1.123:5601)',
                                default=args.dashboardsUrl,
                                extraLabel=BACK_LABEL,
                            )

                ###################################################################################
                elif currentStep == ConfigOptions.LogstashRemote:
                    if malcolmProfile != PROFILE_MALCOLM:
                        loopBreaker = CountUntilException(MaxAskForValueCount, f'Invalid Logstash host and port')
                        logstashHost = ''
                        while (len(logstashHost) <= 1) and loopBreaker.increment():
                            logstashHost = InstallerAskForString(
                                f'Enter Logstash host and port (e.g., 192.168.1.123:5044)',
                                default=args.logstashHost,
                                extraLabel=BACK_LABEL,
                            )

                    if (malcolmProfile == PROFILE_MALCOLM) and InstallerYesOrNo(
                        'Forward Logstash logs to a secondary remote document store?',
                        default=(
                            DATABASE_MODE_ENUMS[args.opensearchSecondaryMode]
                            in (DatabaseMode.OpenSearchRemote, DatabaseMode.ElasticsearchRemote)
                        ),
                        extraLabel=BACK_LABEL,
                    ):
                        databaseModeChoice = ''
                        allowedDatabaseModes = {
                            DATABASE_MODE_LABELS[DatabaseMode.OpenSearchRemote]: [
                                DatabaseMode.OpenSearchRemote,
                                'remote OpenSearch',
                            ],
                            DATABASE_MODE_LABELS[DatabaseMode.ElasticsearchRemote]: [
                                DatabaseMode.ElasticsearchRemote,
                                'remote Elasticsearch',
                            ],
                        }
                        loopBreaker = CountUntilException(MaxAskForValueCount, 'Invalid secondary document store mode')
                        while databaseModeChoice not in list(allowedDatabaseModes.keys()) and loopBreaker.increment():
                            databaseModeChoice = InstallerChooseOne(
                                'Select secondary Malcolm document store',
                                choices=[
                                    (x, allowedDatabaseModes[x][1], x == args.opensearchSecondaryMode)
                                    for x in list(allowedDatabaseModes.keys())
                                ],
                                extraLabel=BACK_LABEL,
                            )
                        opensearchSecondaryMode = allowedDatabaseModes[databaseModeChoice][0]
                        opensearchSecondaryLabel = allowedDatabaseModes[databaseModeChoice][1]

                    if opensearchSecondaryMode in (DatabaseMode.OpenSearchRemote, DatabaseMode.ElasticsearchRemote):
                        loopBreaker = CountUntilException(
                            MaxAskForValueCount, f'Invalid {opensearchSecondaryLabel} URL'
                        )
                        opensearchSecondaryUrl = ''
                        while (len(opensearchSecondaryUrl) <= 1) and loopBreaker.increment():
                            opensearchSecondaryUrl = InstallerAskForString(
                                f'Enter secondary {opensearchSecondaryLabel} connection URL (e.g., https://192.168.1.123:9200)',
                                default=args.opensearchSecondaryUrl,
                                extraLabel=BACK_LABEL,
                            )
                        opensearchSecondarySslVerify = opensearchSecondaryUrl.lower().startswith(
                            'https'
                        ) and InstallerYesOrNo(
                            f'Require SSL certificate validation for communication with secondary {opensearchSecondaryLabel} instance?',
                            default=args.opensearchSecondarySslVerify,
                            extraLabel=BACK_LABEL,
                        )

                    if (opensearchPrimaryMode in (DatabaseMode.OpenSearchRemote, DatabaseMode.ElasticsearchRemote)) or (
                        opensearchSecondaryMode in (DatabaseMode.OpenSearchRemote, DatabaseMode.ElasticsearchRemote)
                    ):
                        InstallerDisplayMessage(
                            f'You must run auth_setup after {ScriptName} to store data store connection credentials.',
                        )

                ###################################################################################
                elif currentStep == ConfigOptions.ContainerResources:
                    if malcolmProfile == PROFILE_MALCOLM:
                        loopBreaker = CountUntilException(
                            MaxAskForValueCount,
                            f'Invalid {"OpenSearch/" if opensearchPrimaryMode == DatabaseMode.OpenSearchLocal else ""}Logstash memory setting(s)',
                        )
                        while (
                            not InstallerYesOrNo(
                                (
                                    f'Setting {osMemory} for OpenSearch and {lsMemory} for Logstash. Is this OK?'
                                    if opensearchPrimaryMode == DatabaseMode.OpenSearchLocal
                                    else f'Setting {lsMemory} for Logstash. Is this OK?'
                                ),
                                default=True,
                                extraLabel=BACK_LABEL,
                            )
                            and loopBreaker.increment()
                        ):
                            if opensearchPrimaryMode == DatabaseMode.OpenSearchLocal:
                                osMemory = InstallerAskForString(
                                    'Enter memory for OpenSearch (e.g., 16g, 9500m, etc.)',
                                    extraLabel=BACK_LABEL,
                                )
                            lsMemory = InstallerAskForString(
                                'Enter memory for Logstash (e.g., 3g, 4500m, etc.)',
                                extraLabel=BACK_LABEL,
                            )

                        loopBreaker = CountUntilException(MaxAskForValueCount, 'Invalid Logstash worker setting(s)')
                        while (
                            (not str(lsWorkers).isdigit())
                            or (
                                not InstallerYesOrNo(
                                    f'Setting {lsWorkers} workers for Logstash pipelines. Is this OK?',
                                    default=True,
                                    extraLabel=BACK_LABEL,
                                )
                            )
                        ) and loopBreaker.increment():
                            lsWorkers = InstallerAskForString(
                                'Enter number of Logstash workers (e.g., 4, 8, etc.)',
                                extraLabel=BACK_LABEL,
                            )

                ###################################################################################
                elif currentStep == ConfigOptions.RestartMode:
                    restartMode = None
                    allowedRestartModes = ('no', 'on-failure', 'always', 'unless-stopped')
                    if (self.orchMode is OrchestrationFramework.DOCKER_COMPOSE) and InstallerYesOrNo(
                        'Restart Malcolm upon system or container daemon restart?',
                        default=args.malcolmAutoRestart,
                        extraLabel=BACK_LABEL,
                    ):
                        loopBreaker = CountUntilException(MaxAskForValueCount, 'Invalid restart mode')
                        while restartMode not in allowedRestartModes and loopBreaker.increment():
                            restartMode = InstallerChooseOne(
                                'Select Malcolm restart behavior',
                                choices=[(x, '', x == 'unless-stopped') for x in allowedRestartModes],
                                extraLabel=BACK_LABEL,
                            )
                    else:
                        restartMode = 'no'

                ###################################################################################
                elif currentStep == ConfigOptions.RequireHTTPS:
                    if malcolmProfile == PROFILE_MALCOLM:
                        nginxSSL = InstallerYesOrNo(
                            'Require encrypted HTTPS connections?',
                            default=args.nginxSSL,
                            extraLabel=BACK_LABEL,
                        )
                        if (not nginxSSL) and (not args.acceptDefaultsNonInteractive):
                            nginxSSL = not InstallerYesOrNo(
                                'Unencrypted connections are NOT recommended. Are you sure?',
                                default=False,
                                extraLabel=BACK_LABEL,
                            )

                        nginxResolverChoices = []
                        allowedResolverChoices = {
                            'ipv4': [
                                DatabaseMode.OpenSearchLocal,
                                'IPv4',
                                args.nginxResolverIpv4,
                            ],
                            'ipv6': [
                                DatabaseMode.OpenSearchRemote,
                                'IPv6',
                                args.nginxResolverIpv6,
                            ],
                        }
                        loopBreaker = CountUntilException(MaxAskForValueCount, 'Both ')
                        while (not nginxResolverChoices) and loopBreaker.increment():
                            nginxResolverChoices = InstallerChooseMultiple(
                                'Which IP version does the network support? (IPv4, IPv6, or both)',
                                choices=[
                                    (x, allowedResolverChoices[x][1], allowedResolverChoices[x][2])
                                    for x in list(allowedResolverChoices.keys())
                                ],
                                extraLabel=BACK_LABEL,
                            )
                        nginxResolverIpv4Off = 'ipv4' not in nginxResolverChoices
                        nginxResolverIpv6Off = 'ipv6' not in nginxResolverChoices
                    else:
                        nginxSSL = True

                ###################################################################################
                elif currentStep == ConfigOptions.DockerNetworking:
                    behindReverseProxy = (self.orchMode is OrchestrationFramework.KUBERNETES) or (
                        (malcolmProfile == PROFILE_MALCOLM)
                        and InstallerYesOrNo(
                            'Will Malcolm be running behind another reverse proxy (Traefik, Caddy, etc.)?',
                            default=args.behindReverseProxy or (not nginxSSL),
                            extraLabel=BACK_LABEL,
                        )
                    )

                    traefikLabels = False
                    traefikHost = ""
                    traefikOpenSearchHost = ""
                    traefikEntrypoint = ""
                    traefikResolver = ""
                    if self.orchMode is OrchestrationFramework.DOCKER_COMPOSE:
                        if behindReverseProxy:
                            traefikLabels = InstallerYesOrNo(
                                'Configure labels for Traefik?',
                                default=bool(args.traefikHost),
                                extraLabel=BACK_LABEL,
                            )
                            if traefikLabels:
                                loopBreaker = CountUntilException(MaxAskForValueCount, 'Invalid Traefik request domain')
                                while (len(traefikHost) <= 1) and loopBreaker.increment():
                                    traefikHost = InstallerAskForString(
                                        'Enter request domain (host header value) for Malcolm interface Traefik router (e.g., malcolm.example.org)',
                                        default=args.traefikHost,
                                        extraLabel=BACK_LABEL,
                                    )
                                if opensearchPrimaryMode == DatabaseMode.OpenSearchLocal:
                                    loopBreaker = CountUntilException(
                                        MaxAskForValueCount, 'Invalid Traefik OpenSearch request domain'
                                    )
                                    while (
                                        (len(traefikOpenSearchHost) <= 1) or (traefikOpenSearchHost == traefikHost)
                                    ) and loopBreaker.increment():
                                        traefikOpenSearchHost = InstallerAskForString(
                                            f'Enter request domain (host header value) for OpenSearch Traefik router (e.g., opensearch.{traefikHost})',
                                            default=args.traefikOpenSearchHost,
                                            extraLabel=BACK_LABEL,
                                        )
                                loopBreaker = CountUntilException(
                                    MaxAskForValueCount, 'Invalid Traefik router entrypoint'
                                )
                                while (len(traefikEntrypoint) <= 1) and loopBreaker.increment():
                                    traefikEntrypoint = InstallerAskForString(
                                        'Enter Traefik router entrypoint (e.g., websecure)',
                                        default=args.traefikEntrypoint,
                                        extraLabel=BACK_LABEL,
                                    )
                                loopBreaker = CountUntilException(
                                    MaxAskForValueCount, 'Invalid Traefik router resolver'
                                )
                                while (len(traefikResolver) <= 1) and loopBreaker.increment():
                                    traefikResolver = InstallerAskForString(
                                        'Enter Traefik router resolver (e.g., myresolver)',
                                        default=args.traefikResolver,
                                        extraLabel=BACK_LABEL,
                                    )

                    dockerNetworkExternalName = InstallerAskForString(
                        'Specify external container network name (or leave blank for default networking)',
                        default=args.containerNetworkName,
                        extraLabel=BACK_LABEL,
                    )

                ###################################################################################
                elif currentStep == ConfigOptions.StorageLocations:
                    # directories for data volume mounts (PCAP storage, Zeek log storage, OpenSearch indexes, etc.)

                    # if the file .os-disk-config-defaults was created by the environment (os-disk-config.py)
                    #   we'll use those as defaults, otherwise base things underneath the malcolm_install_path
                    diskFormatInfo = {}
                    try:
                        diskFormatInfoFile = os.path.join(
                            os.path.realpath(os.path.join(ScriptPath, "..")), ".os-disk-config-defaults"
                        )
                        if os.path.isfile(diskFormatInfoFile):
                            with open(diskFormatInfoFile) as f:
                                diskFormatInfo = LoadFileIfJson(f)
                    except Exception:
                        pass
                    diskFormatInfo = {k: v for k, v in diskFormatInfo.items() if os.path.isdir(v)}

                    if MALCOLM_DB_DIR in diskFormatInfo:
                        for subDir in ['opensearch', 'opensearch-backup']:
                            pathlib.Path(os.path.join(diskFormatInfo[MALCOLM_DB_DIR], subDir)).mkdir(
                                parents=False, exist_ok=True
                            )
                    if MALCOLM_LOGS_DIR in diskFormatInfo:
                        for subDir in ['zeek-logs', 'suricata-logs']:
                            pathlib.Path(os.path.join(diskFormatInfo[MALCOLM_LOGS_DIR], subDir)).mkdir(
                                parents=False, exist_ok=True
                            )

                    if args.indexDir:
                        indexDirDefault = args.indexDir
                        indexDir = indexDirDefault
                    else:
                        indexDir = './opensearch'
                        if (MALCOLM_DB_DIR in diskFormatInfo) and os.path.isdir(
                            os.path.join(diskFormatInfo[MALCOLM_DB_DIR], indexDir)
                        ):
                            indexDirDefault = os.path.join(diskFormatInfo[MALCOLM_DB_DIR], indexDir)
                            indexDir = indexDirDefault
                        else:
                            indexDirDefault = os.path.join(malcolm_install_path, indexDir)
                    indexDirFull = os.path.realpath(indexDirDefault)

                    if args.indexSnapshotDir:
                        indexSnapshotDirDefault = args.indexSnapshotDir
                        indexSnapshotDir = indexSnapshotDirDefault
                    else:
                        indexSnapshotDir = './opensearch-backup'
                        if (MALCOLM_DB_DIR in diskFormatInfo) and os.path.isdir(
                            os.path.join(diskFormatInfo[MALCOLM_DB_DIR], indexSnapshotDir)
                        ):
                            indexSnapshotDirDefault = os.path.join(diskFormatInfo[MALCOLM_DB_DIR], indexSnapshotDir)
                            indexSnapshotDir = indexSnapshotDirDefault
                        else:
                            indexSnapshotDirDefault = os.path.join(malcolm_install_path, indexSnapshotDir)
                    indexSnapshotDirFull = os.path.realpath(indexSnapshotDirDefault)

                    if args.pcapDir:
                        pcapDirDefault = args.pcapDir
                        pcapDir = pcapDirDefault
                    else:
                        if MALCOLM_PCAP_DIR in diskFormatInfo:
                            pcapDirDefault = diskFormatInfo[MALCOLM_PCAP_DIR]
                            pcapDir = pcapDirDefault
                        else:
                            pcapDir = './pcap'
                            pcapDirDefault = os.path.join(malcolm_install_path, pcapDir)
                    pcapDirFull = os.path.realpath(pcapDirDefault)

                    if args.suricataLogDir:
                        suricataLogDirDefault = args.suricataLogDir
                        suricataLogDir = suricataLogDirDefault
                    else:
                        suricataLogDir = './suricata-logs'
                        if (MALCOLM_LOGS_DIR in diskFormatInfo) and os.path.isdir(
                            os.path.join(diskFormatInfo[MALCOLM_LOGS_DIR], suricataLogDir)
                        ):
                            suricataLogDirDefault = os.path.join(diskFormatInfo[MALCOLM_LOGS_DIR], suricataLogDir)
                            suricataLogDir = suricataLogDirDefault
                        else:
                            suricataLogDirDefault = os.path.join(malcolm_install_path, suricataLogDir)
                    suricataLogDirFull = os.path.realpath(suricataLogDirDefault)

                    if args.zeekLogDir:
                        zeekLogDirDefault = args.zeekLogDir
                        zeekLogDir = zeekLogDirDefault
                    else:
                        zeekLogDir = './zeek-logs'
                        if (MALCOLM_LOGS_DIR in diskFormatInfo) and os.path.isdir(
                            os.path.join(diskFormatInfo[MALCOLM_LOGS_DIR], zeekLogDir)
                        ):
                            zeekLogDirDefault = os.path.join(diskFormatInfo[MALCOLM_LOGS_DIR], zeekLogDir)
                            zeekLogDir = zeekLogDirDefault
                        else:
                            zeekLogDirDefault = os.path.join(malcolm_install_path, zeekLogDir)
                    zeekLogDirFull = os.path.realpath(zeekLogDirDefault)

                    if self.orchMode is OrchestrationFramework.DOCKER_COMPOSE:
                        if diskFormatInfo or not InstallerYesOrNo(
                            f'Store {"PCAP, log and index" if (malcolmProfile == PROFILE_MALCOLM) else "PCAP and log"} files in {malcolm_install_path}?',
                            default=not args.acceptDefaultsNonInteractive,
                            extraLabel=BACK_LABEL,
                        ):
                            # PCAP directory
                            if not InstallerYesOrNo(
                                'Store PCAP files in {}?'.format(pcapDirDefault),
                                default=not bool(args.pcapDir),
                                extraLabel=BACK_LABEL,
                            ):
                                loopBreaker = CountUntilException(MaxAskForValueCount, 'Invalid PCAP directory')
                                while loopBreaker.increment():
                                    pcapDir = InstallerAskForString(
                                        'Enter PCAP directory',
                                        default=pcapDirDefault,
                                        extraLabel=BACK_LABEL,
                                    )
                                    if (len(pcapDir) > 1) and os.path.isdir(pcapDir):
                                        pcapDirFull = os.path.realpath(pcapDir)
                                        pcapDir = (
                                            f"./{os.path.relpath(pcapDirDefault, malcolm_install_path)}"
                                            if same_file_or_dir(pcapDirDefault, pcapDirFull)
                                            else pcapDirFull
                                        )
                                        break

                            # Zeek log directory
                            if not InstallerYesOrNo(
                                'Store Zeek logs in {}?'.format(zeekLogDirDefault),
                                default=not bool(args.zeekLogDir),
                                extraLabel=BACK_LABEL,
                            ):
                                loopBreaker = CountUntilException(MaxAskForValueCount, 'Invalid Zeek directory')
                                while loopBreaker.increment():
                                    zeekLogDir = InstallerAskForString(
                                        'Enter Zeek log directory',
                                        default=zeekLogDirDefault,
                                        extraLabel=BACK_LABEL,
                                    )
                                    if (len(zeekLogDir) > 1) and os.path.isdir(zeekLogDir):
                                        zeekLogDirFull = os.path.realpath(zeekLogDir)
                                        zeekLogDir = (
                                            f"./{os.path.relpath(zeekLogDirDefault, malcolm_install_path)}"
                                            if same_file_or_dir(zeekLogDirDefault, zeekLogDirFull)
                                            else zeekLogDirFull
                                        )
                                        break

                            # Suricata log directory
                            if not InstallerYesOrNo(
                                'Store Suricata logs in {}?'.format(suricataLogDirDefault),
                                default=not bool(args.suricataLogDir),
                                extraLabel=BACK_LABEL,
                            ):
                                loopBreaker = CountUntilException(MaxAskForValueCount, 'Invalid Suricata directory')
                                while loopBreaker.increment():
                                    suricataLogDir = InstallerAskForString(
                                        'Enter Suricata log directory',
                                        default=suricataLogDirDefault,
                                        extraLabel=BACK_LABEL,
                                    )
                                    if (len(suricataLogDir) > 1) and os.path.isdir(suricataLogDir):
                                        suricataLogDirFull = os.path.realpath(suricataLogDir)
                                        suricataLogDir = (
                                            f"./{os.path.relpath(suricataLogDirDefault, malcolm_install_path)}"
                                            if same_file_or_dir(suricataLogDirDefault, suricataLogDirFull)
                                            else suricataLogDirFull
                                        )
                                        break

                            if (malcolmProfile == PROFILE_MALCOLM) and (
                                opensearchPrimaryMode == DatabaseMode.OpenSearchLocal
                            ):
                                # opensearch index directory
                                if not InstallerYesOrNo(
                                    'Store OpenSearch indices in {}?'.format(indexDirDefault),
                                    default=not bool(args.indexDir),
                                    extraLabel=BACK_LABEL,
                                ):
                                    loopBreaker = CountUntilException(
                                        MaxAskForValueCount, 'Invalid OpenSearch index directory'
                                    )
                                    while loopBreaker.increment():
                                        indexDir = InstallerAskForString(
                                            'Enter OpenSearch index directory',
                                            default=indexDirDefault,
                                            extraLabel=BACK_LABEL,
                                        )
                                        if (len(indexDir) > 1) and os.path.isdir(indexDir):
                                            indexDirFull = os.path.realpath(indexDir)
                                            indexDir = (
                                                f"./{os.path.relpath(indexDirDefault, malcolm_install_path)}"
                                                if same_file_or_dir(indexDirDefault, indexDirFull)
                                                else indexDirFull
                                            )
                                            break

                                # opensearch snapshot repository directory
                                if not InstallerYesOrNo(
                                    'Store OpenSearch index snapshots in {}?'.format(indexSnapshotDirDefault),
                                    default=not bool(args.indexSnapshotDir),
                                    extraLabel=BACK_LABEL,
                                ):
                                    loopBreaker = CountUntilException(
                                        MaxAskForValueCount, 'Invalid OpenSearch snapshots directory'
                                    )
                                    while loopBreaker.increment():
                                        indexSnapshotDir = InstallerAskForString(
                                            'Enter OpenSearch index snapshot directory',
                                            default=indexSnapshotDirDefault,
                                            extraLabel=BACK_LABEL,
                                        )
                                        if (len(indexSnapshotDir) > 1) and os.path.isdir(indexSnapshotDir):
                                            indexSnapshotDirFull = os.path.realpath(indexSnapshotDir)
                                            indexSnapshotDir = (
                                                f"./{os.path.relpath(indexSnapshotDirDefault, malcolm_install_path)}"
                                                if same_file_or_dir(indexSnapshotDirDefault, indexSnapshotDirFull)
                                                else indexSnapshotDirFull
                                            )
                                            break

                        # make sure paths specified (and their necessary children) exist
                        for pathToCreate in (
                            malcolm_install_path,
                            indexDirFull,
                            indexSnapshotDirFull,
                            os.path.join(pcapDirFull, 'arkime-live'),
                            os.path.join(pcapDirFull, 'processed'),
                            os.path.join(pcapDirFull, os.path.join('upload', os.path.join('tmp', 'spool'))),
                            os.path.join(pcapDirFull, os.path.join('upload', 'variants')),
                            os.path.join(suricataLogDirFull, 'live'),
                            os.path.join(zeekLogDirFull, 'current'),
                            os.path.join(zeekLogDirFull, 'live'),
                            os.path.join(zeekLogDirFull, 'upload'),
                            os.path.join(zeekLogDirFull, os.path.join('extract_files', 'preserved')),
                            os.path.join(zeekLogDirFull, os.path.join('extract_files', 'quarantine')),
                        ):
                            try:
                                logging.info(f"Creating {pathToCreate}")
                                pathlib.Path(pathToCreate).mkdir(parents=True, exist_ok=True)
                                if (
                                    ((self.platform == PLATFORM_LINUX) or (self.platform == PLATFORM_MAC))
                                    and (self.scriptUser == "root")
                                    and (getpwuid(os.stat(pathToCreate).st_uid).pw_name == self.scriptUser)
                                ):
                                    logging.info(f"Setting permissions of {pathToCreate} to {puid}:{pgid}")
                                    # change ownership of newly-created directory to match puid/pgid
                                    os.chown(pathToCreate, int(puid), int(pgid))
                            except Exception as e:
                                logging.error(f"Creating {pathToCreate} failed: {e}")

                ###################################################################################
                elif currentStep == ConfigOptions.ILMISM:
                    indexManagementPolicy = False
                    indexManagementHotWarm = False
                    indexManagementOptimizationTimePeriod = '30d'
                    indexManagementSpiDataRetention = '90d'
                    indexManagementReplicas = 0
                    indexManagementHistoryInWeeks = 13
                    indexManagementOptimizeSessionSegments = 1

                    loopBreaker = CountUntilException(
                        MaxAskForValueCount,
                        f'Invalid ILM/ISM setting(s)',
                    )
                    indexManagementPolicy = InstallerYesOrNo(
                        f'Enable index management policies (ILM/ISM) in Arkime?',
                        default=args.indexManagementPolicy,
                        extraLabel=BACK_LABEL,
                    )
                    if indexManagementPolicy:
                        while loopBreaker.increment():
                            # Set 'hot' for 'node.attr.molochtype' on new indices, warm on non sessions indices
                            indexManagementHotWarm = InstallerYesOrNo(
                                f'Should Arkime use a hot/warm design in which non-session data is stored in a warm index?',
                                default=args.indexManagementHotWarm,
                                extraLabel=BACK_LABEL,
                            )
                            if indexManagementHotWarm:
                                if opensearchPrimaryMode == DatabaseMode.ElasticsearchRemote:
                                    InstallerDisplayMessage(
                                        f'You must configure "hot" and "warm" nodes types in the remote Elasticsearch instance (https://arkime.com/faq#ilm)'
                                    )
                                else:
                                    InstallerDisplayMessage(
                                        f'You must configure "hot" and "warm" nodes types in the OpenSearch instance'
                                    )
                            # Time in hours/days before (moving Arkime indexes to warm) and force merge (number followed by h or d), default 30d
                            indexManagementOptimizationTimePeriod = InstallerAskForString(
                                "How long should Arkime keep an index in the hot node? (e.g. 25h, 5d, etc.)",
                                default=args.indexManagementOptimizationTimePeriod,
                                extraLabel=BACK_LABEL,
                            )
                            # Time in hours/days before deleting Arkime indexes (number followed by h or d), default 90d
                            indexManagementSpiDataRetention = InstallerAskForString(
                                "How long should Arkime retain SPI data before deleting it? (e.g. 25h, 90d, etc.)",
                                default=str(args.indexManagementSpiDataRetention),
                                extraLabel=BACK_LABEL,
                            )
                            # Number of segments to optimize sessions to in the ILM policy, default 1
                            indexManagementOptimizeSessionSegments = InstallerAskForString(
                                "How many segments should Arkime use to optimize?",
                                default=str(args.indexManagementOptimizeSessionSegments),
                                extraLabel=BACK_LABEL,
                            )
                            # Number of replicas for older sessions indices in the ILM policy, default 0
                            indexManagementReplicas = InstallerAskForString(
                                "How many replicas should Arkime maintain for older session indices?",
                                default=str(args.indexManagementReplicas),
                                extraLabel=BACK_LABEL,
                            )
                            # Number of weeks of history to keep, default 13
                            indexManagementHistoryInWeeks = InstallerAskForString(
                                "How many weeks of history should Arkime keep?",
                                default=str(args.indexManagementHistoryInWeeks),
                                extraLabel=BACK_LABEL,
                            )
                            if (
                                (re.match(r"\d+(h|d)", indexManagementOptimizationTimePeriod))
                                and (re.match(r"\d+(h|d)", indexManagementSpiDataRetention))
                                and str(indexManagementOptimizeSessionSegments).isdigit()
                                and str(indexManagementReplicas).isdigit()
                                and str(indexManagementHistoryInWeeks).isdigit()
                            ):
                                break

                ###################################################################################
                elif currentStep == ConfigOptions.StorageManagement:
                    # storage management (deleting oldest indices and/or PCAP files)
                    indexPruneSizeLimit = '0'
                    indexPruneNameSort = False
                    arkimeManagePCAP = False
                    arkimeFreeSpaceG = '10%'
                    extractedFileMaxSizeThreshold = '1TB'
                    extractedFileMaxPercentThreshold = 0

                    diskUsageManagementPrompt = InstallerYesOrNo(
                        (
                            'Should Malcolm delete the oldest database indices and capture artifacts based on available storage?'
                            if (malcolmProfile == PROFILE_MALCOLM)
                            else 'Should Malcolm delete the oldest capture artifacts based on available storage?'
                        ),
                        default=args.arkimeManagePCAP
                        or bool(args.indexPruneSizeLimit)
                        or bool(args.extractedFileMaxSizeThreshold)
                        or (args.extractedFileMaxPercentThreshold > 0),
                        extraLabel=BACK_LABEL,
                    )
                    if diskUsageManagementPrompt:

                        # delete oldest indexes based on index pattern size
                        if (malcolmProfile == PROFILE_MALCOLM) and InstallerYesOrNo(
                            'Delete the oldest indices when the database exceeds a certain size?',
                            default=bool(args.indexPruneSizeLimit),
                            extraLabel=BACK_LABEL,
                        ):
                            indexPruneSizeLimit = ''
                            loopBreaker = CountUntilException(MaxAskForValueCount, 'Invalid index threshold')
                            while (
                                (not re.match(r'^\d+(\.\d+)?\s*[kmgtp%]?b?$', indexPruneSizeLimit, flags=re.IGNORECASE))
                                and (indexPruneSizeLimit != '0')
                                and loopBreaker.increment()
                            ):
                                indexPruneSizeLimit = InstallerAskForString(
                                    'Enter index threshold (e.g., 250GB, 1TB, 60%, etc.)',
                                    default=args.indexPruneSizeLimit,
                                    extraLabel=BACK_LABEL,
                                )
                            indexPruneNameSort = InstallerYesOrNo(
                                'Determine oldest indices by name (instead of creation time)?',
                                default=False,
                                extraLabel=BACK_LABEL,
                            )

                        # let Arkime delete old PCAP files based on available storage
                        arkimeManagePCAP = (
                            (opensearchPrimaryMode != DatabaseMode.OpenSearchLocal)
                            or (malcolmProfile != PROFILE_MALCOLM)
                            or InstallerYesOrNo(
                                'Should Arkime delete uploaded PCAP files based on available storage (see https://arkime.com/faq#pcap-deletion)?',
                                default=args.arkimeManagePCAP,
                                extraLabel=BACK_LABEL,
                            )
                        )
                        if arkimeManagePCAP:
                            arkimeFreeSpaceGTmp = ''
                            loopBreaker = CountUntilException(MaxAskForValueCount, 'Invalid PCAP deletion threshold')
                            while (
                                not re.match(r'^\d+%?$', arkimeFreeSpaceGTmp, flags=re.IGNORECASE)
                            ) and loopBreaker.increment():
                                arkimeFreeSpaceGTmp = InstallerAskForString(
                                    'Enter PCAP deletion threshold in gigabytes or as a percentage (e.g., 500, 10%, etc.)',
                                    default=args.arkimeFreeSpaceG,
                                    extraLabel=BACK_LABEL,
                                )
                            if arkimeFreeSpaceGTmp:
                                arkimeFreeSpaceG = arkimeFreeSpaceGTmp
                ###################################################################################
                elif currentStep == ConfigOptions.AutoArkime:
                    autoArkime = InstallerYesOrNo(
                        'Automatically analyze all PCAP files with Arkime?',
                        default=args.autoArkime,
                        extraLabel=BACK_LABEL,
                    )
                ###################################################################################
                elif currentStep == ConfigOptions.AutoSuricata:
                    autoSuricata = InstallerYesOrNo(
                        'Automatically analyze all PCAP files with Suricata?',
                        default=args.autoSuricata,
                        extraLabel=BACK_LABEL,
                    )
                ###################################################################################
                elif currentStep == ConfigOptions.SuricataRuleUpdate:
                    suricataRuleUpdate = autoSuricata and InstallerYesOrNo(
                        'Download updated Suricata signatures periodically?',
                        default=args.suricataRuleUpdate,
                        extraLabel=BACK_LABEL,
                    )
                ###################################################################################
                elif currentStep == ConfigOptions.AutoZeek:
                    autoZeek = InstallerYesOrNo(
                        'Automatically analyze all PCAP files with Zeek?',
                        default=args.autoZeek,
                        extraLabel=BACK_LABEL,
                    )
                ###################################################################################
                elif currentStep == ConfigOptions.ICS:
                    malcolmIcs = InstallerYesOrNo(
                        'Is Malcolm being used to monitor an Operational Technology/Industrial Control Systems (OT/ICS) network?',
                        default=args.malcolmIcs,
                        extraLabel=BACK_LABEL,
                    )

                    zeekICSBestGuess = (
                        autoZeek
                        and malcolmIcs
                        and InstallerYesOrNo(
                            'Should Malcolm use "best guess" to identify potential OT/ICS traffic with Zeek?',
                            default=args.zeekICSBestGuess,
                            extraLabel=BACK_LABEL,
                        )
                    )

                ###################################################################################
                elif currentStep == ConfigOptions.Enrichment:
                    reverseDns = (malcolmProfile == PROFILE_MALCOLM) and InstallerYesOrNo(
                        'Perform reverse DNS lookup locally for source and destination IP addresses in logs?',
                        default=args.reverseDns,
                        extraLabel=BACK_LABEL,
                    )
                    autoOui = (malcolmProfile == PROFILE_MALCOLM) and InstallerYesOrNo(
                        'Perform hardware vendor OUI lookups for MAC addresses?',
                        default=args.autoOui,
                        extraLabel=BACK_LABEL,
                    )
                    autoFreq = (malcolmProfile == PROFILE_MALCOLM) and InstallerYesOrNo(
                        'Perform string randomness scoring on some fields?',
                        default=args.autoFreq,
                        extraLabel=BACK_LABEL,
                    )

                ###################################################################################
                elif currentStep == ConfigOptions.OpenPorts:
                    openPortsSelection = (
                        'c'
                        if (
                            args.exposeLogstash
                            or args.exposeOpenSearch
                            or args.exposeFilebeatTcp
                            or args.exposeSFTP
                            or args.syslogUdpPort
                            or args.syslogTcpPort
                        )
                        else 'unset'
                    )
                    if args.syslogTcpPort:
                        syslogPortDict['tcp'] = args.syslogTcpPort
                    if args.syslogUdpPort:
                        syslogPortDict['udp'] = args.syslogUdpPort
                    if self.orchMode is OrchestrationFramework.DOCKER_COMPOSE:
                        if malcolmProfile == PROFILE_MALCOLM:
                            openPortsOptions = ('no', 'yes', 'customize')
                            loopBreaker = CountUntilException(MaxAskForValueCount)
                            while (
                                openPortsSelection not in [x[0] for x in openPortsOptions] and loopBreaker.increment()
                            ):
                                openPortsSelection = InstallerChooseOne(
                                    'Should Malcolm accept logs and metrics from a Hedgehog Linux sensor or other forwarder?',
                                    choices=[(x, '', x == openPortsOptions[0]) for x in openPortsOptions],
                                    extraLabel=BACK_LABEL,
                                )[0]
                            if openPortsSelection == 'n':
                                opensearchOpen = False
                                logstashOpen = False
                                filebeatTcpOpen = False
                            elif openPortsSelection == 'y':
                                opensearchOpen = opensearchPrimaryMode == DatabaseMode.OpenSearchLocal
                                logstashOpen = True
                                filebeatTcpOpen = True
                            else:
                                openPortsSelection = 'c'
                                opensearchOpen = (
                                    opensearchPrimaryMode == DatabaseMode.OpenSearchLocal
                                ) and InstallerYesOrNo(
                                    'Expose OpenSearch port to external hosts?',
                                    default=args.exposeOpenSearch,
                                    extraLabel=BACK_LABEL,
                                )
                                logstashOpen = InstallerYesOrNo(
                                    'Expose Logstash port to external hosts?',
                                    default=args.exposeLogstash,
                                    extraLabel=BACK_LABEL,
                                )
                                filebeatTcpOpen = InstallerYesOrNo(
                                    'Expose Filebeat TCP port to external hosts?',
                                    default=args.exposeFilebeatTcp,
                                    extraLabel=BACK_LABEL,
                                )
                        else:
                            opensearchOpen = False
                            openPortsSelection = 'n'
                            logstashOpen = False
                            filebeatTcpOpen = False

                    else:
                        opensearchOpen = opensearchPrimaryMode == DatabaseMode.OpenSearchLocal
                        openPortsSelection = 'y'
                        logstashOpen = True
                        filebeatTcpOpen = True

                    filebeatTcpFormat = 'json'
                    filebeatTcpSourceField = 'message'
                    filebeatTcpTargetField = 'miscbeat'
                    filebeatTcpDropField = filebeatTcpSourceField
                    filebeatTcpTag = '_malcolm_beats'
                    if (
                        filebeatTcpOpen
                        and (openPortsSelection == 'c')
                        and not InstallerYesOrNo(
                            'Use default field values for Filebeat TCP listener?',
                            default=True,
                            extraLabel=BACK_LABEL,
                        )
                    ):
                        allowedFilebeatTcpFormats = ('json', 'raw')
                        filebeatTcpFormat = 'unset'
                        loopBreaker = CountUntilException(MaxAskForValueCount, f'Invalid log format')
                        while filebeatTcpFormat not in allowedFilebeatTcpFormats and loopBreaker.increment():
                            filebeatTcpFormat = InstallerChooseOne(
                                'Select log format for messages sent to Filebeat TCP listener',
                                choices=[(x, '', x == allowedFilebeatTcpFormats[0]) for x in allowedFilebeatTcpFormats],
                                extraLabel=BACK_LABEL,
                            )
                        if filebeatTcpFormat == 'json':
                            filebeatTcpSourceField = InstallerAskForString(
                                'Source field to parse for messages sent to Filebeat TCP listener',
                                default=filebeatTcpSourceField,
                                extraLabel=BACK_LABEL,
                            )
                            filebeatTcpTargetField = InstallerAskForString(
                                'Target field under which to store decoded JSON fields for messages sent to Filebeat TCP listener',
                                default=filebeatTcpTargetField,
                                extraLabel=BACK_LABEL,
                            )
                            filebeatTcpDropField = InstallerAskForString(
                                'Field to drop from events sent to Filebeat TCP listener',
                                default=filebeatTcpSourceField,
                                extraLabel=BACK_LABEL,
                            )
                        filebeatTcpTag = InstallerAskForString(
                            'Tag to apply to messages sent to Filebeat TCP listener',
                            default=filebeatTcpTag,
                            extraLabel=BACK_LABEL,
                        )

                    # Expose SFTP and/or Syslog servers?
                    if (
                        (self.orchMode is OrchestrationFramework.DOCKER_COMPOSE)
                        and (malcolmProfile == PROFILE_MALCOLM)
                        and (openPortsSelection == 'c')
                    ):
                        sftpOpen = InstallerYesOrNo(
                            'Expose SFTP server (for PCAP upload) to external hosts?',
                            default=args.exposeSFTP,
                            extraLabel=BACK_LABEL,
                        )
                        if InstallerYesOrNo(
                            'Accept standard syslog messages?',
                            default=any([x > 0 for x in [args.syslogUdpPort, args.syslogTcpPort]]),
                            extraLabel=BACK_LABEL,
                        ):
                            syslogTransports = ('tcp', 'udp')
                            for transport in syslogTransports:
                                loopBreaker = CountUntilException(
                                    MaxAskForValueCount, f'Invalid syslog over {transport.upper()} port'
                                )
                                syslogPortStr = ''
                                while (
                                    (not syslogPortStr.isdigit())
                                    or (int(syslogPortStr) < 0)
                                    or (int(syslogPortStr) > 65535)
                                    or (
                                        not InstallerYesOrNo(
                                            f'Setting port {syslogPortStr} for syslog over {transport.upper()}. Is this OK?',
                                            default=True,
                                            extraLabel=BACK_LABEL,
                                        )
                                    )
                                ) and loopBreaker.increment():
                                    syslogPortStr = InstallerAskForString(
                                        f'Enter port for syslog over {transport.upper()} (e.g., 514) or 0 to disable',
                                        extraLabel=BACK_LABEL,
                                        default=str(syslogPortDict[transport]),
                                    )
                                if (
                                    syslogPortStr.isdigit()
                                    and (int(syslogPortStr) > 0)
                                    and (int(syslogPortStr) <= 65535)
                                ):
                                    syslogPortDict[transport] = int(syslogPortStr)

                ###################################################################################
                elif currentStep == ConfigOptions.FileCarving:
                    # input file extraction parameters
                    allowedFileCarveModes = {
                        'none': 'No file extraction',
                        'known': 'Extract recognized MIME types',
                        'mapped': 'Extract MIME types for which file extensions are known',
                        'all': 'Extract all files',
                        'interesting': 'Extract MIME types of common attack vectors',
                        'notcommtxt': 'Extract all except common plain text files',
                    }
                    allowedFilePreserveModes = ('quarantined', 'all', 'none')

                    fileCarveMode = None
                    fileCarveModeDefault = args.fileCarveMode.lower() if args.fileCarveMode else None
                    filePreserveMode = None
                    filePreserveModeDefault = args.filePreserveMode.lower() if args.filePreserveMode else None
                    vtotApiKey = '0'
                    yaraScan = False
                    capaScan = False
                    clamAvScan = False
                    fileScanRuleUpdate = False
                    fileCarveHttpServer = False
                    fileCarveHttpServerZip = False
                    fileCarveHttpServeEncryptKey = ''

                    if InstallerYesOrNo(
                        'Enable file extraction with Zeek?', extraLabel=BACK_LABEL, default=bool(fileCarveModeDefault)
                    ):
                        loopBreaker = CountUntilException(MaxAskForValueCount, 'Invalid file extraction behavior')
                        while fileCarveMode not in allowedFileCarveModes.keys() and loopBreaker.increment():
                            fileCarveMode = InstallerChooseOne(
                                'Select file extraction behavior',
                                choices=[
                                    (
                                        x,
                                        allowedFileCarveModes[x],
                                        x == fileCarveModeDefault if fileCarveModeDefault else 'none',
                                    )
                                    for x in allowedFileCarveModes.keys()
                                ],
                                extraLabel=BACK_LABEL,
                            )
                        if fileCarveMode and (fileCarveMode != 'none'):

                            loopBreaker = CountUntilException(MaxAskForValueCount, 'Invalid file preservation behavior')
                            while filePreserveMode not in allowedFilePreserveModes and loopBreaker.increment():
                                filePreserveMode = InstallerChooseOne(
                                    'Select file preservation behavior',
                                    choices=[
                                        (
                                            x,
                                            '',
                                            (
                                                x == filePreserveModeDefault
                                                if filePreserveModeDefault
                                                else allowedFilePreserveModes[0]
                                            ),
                                        )
                                        for x in allowedFilePreserveModes
                                    ],
                                    extraLabel=BACK_LABEL,
                                )

                            if diskUsageManagementPrompt:
                                loopBreaker = CountUntilException(
                                    MaxAskForValueCount, 'Invalid Zeek extracted file prune threshold'
                                )
                                extractedFilePruneThresholdTemp = ''
                                while (
                                    not re.match(
                                        r'^\d+(\.\d+)?\s*[kmgtp%]?b?$',
                                        extractedFilePruneThresholdTemp,
                                        flags=re.IGNORECASE,
                                    )
                                ) and loopBreaker.increment():
                                    extractedFilePruneThresholdTemp = InstallerAskForString(
                                        'Enter maximum allowed space for Zeek-extracted files (e.g., 250GB) or file system fill threshold (e.g., 90%)',
                                        default=(
                                            args.extractedFileMaxPercentThreshold
                                            if args.extractedFileMaxPercentThreshold
                                            else args.extractedFileMaxSizeThreshold
                                        ),
                                        extraLabel=BACK_LABEL,
                                    )
                                if extractedFilePruneThresholdTemp:
                                    if '%' in extractedFilePruneThresholdTemp:
                                        extractedFileMaxPercentThreshold = str2percent(extractedFilePruneThresholdTemp)
                                        extractedFileMaxSizeThreshold = '0'
                                    else:
                                        extractedFileMaxPercentThreshold = 0
                                        extractedFileMaxSizeThreshold = extractedFilePruneThresholdTemp

                            fileCarveHttpServer = (malcolmProfile == PROFILE_MALCOLM) and InstallerYesOrNo(
                                'Expose web interface for downloading preserved files?',
                                default=args.fileCarveHttpServer,
                                extraLabel=BACK_LABEL,
                            )
                            if fileCarveHttpServer:
                                fileCarveHttpServerZip = InstallerYesOrNo(
                                    'ZIP downloaded preserved files?',
                                    default=args.fileCarveHttpServerZip,
                                    extraLabel=BACK_LABEL,
                                )
                                fileCarveHttpServeEncryptKey = InstallerAskForString(
                                    (
                                        'Enter ZIP archive password for downloaded preserved files (or leave blank for unprotected)'
                                        if fileCarveHttpServerZip
                                        else 'Enter AES-256-CBC encryption password for downloaded preserved files (or leave blank for unencrypted)'
                                    ),
                                    default=args.fileCarveHttpServeEncryptKey,
                                    extraLabel=BACK_LABEL,
                                )
                            if fileCarveMode is not None:
                                if InstallerYesOrNo(
                                    'Scan extracted files with ClamAV?',
                                    default=args.clamAvScan,
                                    extraLabel=BACK_LABEL,
                                ):
                                    clamAvScan = True
                                if InstallerYesOrNo(
                                    'Scan extracted files with Yara?',
                                    default=args.yaraScan,
                                    extraLabel=BACK_LABEL,
                                ):
                                    yaraScan = True
                                if InstallerYesOrNo(
                                    'Scan extracted PE files with Capa?',
                                    default=args.capaScan,
                                    extraLabel=BACK_LABEL,
                                ):
                                    capaScan = True
                                if InstallerYesOrNo(
                                    'Lookup extracted file hashes with VirusTotal?',
                                    default=(len(args.vtotApiKey) > 1),
                                    extraLabel=BACK_LABEL,
                                ):
                                    loopBreaker = CountUntilException(MaxAskForValueCount, 'Invalid VirusTotal API key')
                                    while (len(vtotApiKey) <= 1) and loopBreaker.increment():
                                        vtotApiKey = InstallerAskForString(
                                            'Enter VirusTotal API key',
                                            default=args.vtotApiKey,
                                            extraLabel=BACK_LABEL,
                                        )
                                fileScanRuleUpdate = InstallerYesOrNo(
                                    'Download updated file scanner signatures periodically?',
                                    default=args.fileScanRuleUpdate,
                                    extraLabel=BACK_LABEL,
                                )

                    if fileCarveMode not in allowedFileCarveModes.keys():
                        fileCarveMode = 'none'
                    if filePreserveMode not in allowedFilePreserveModes:
                        filePreserveMode = allowedFilePreserveModes[0]
                    if (vtotApiKey is None) or (len(vtotApiKey) <= 1):
                        vtotApiKey = '0'

                ###################################################################################
                elif currentStep == ConfigOptions.ZeekIntel:
                    if zeekIntelParamsProvided := InstallerYesOrNo(
                        'Configure pulling from threat intelligence feeds for Zeek intelligence framework?',
                        default=any(
                            [
                                x in raw_args
                                for x in [
                                    '--zeek-intel-on-startup',
                                    '--zeek-intel-feed-since',
                                    '--zeek-intel-cron-expression',
                                    '--zeek-intel-item-expiration',
                                ]
                            ]
                        ),
                        extraLabel=BACK_LABEL,
                    ):
                        zeekIntelOnStartup = InstallerYesOrNo(
                            'Pull from threat intelligence feeds on startup?',
                            default=args.zeekIntelOnStartup,
                            extraLabel=BACK_LABEL,
                        )

                        # https://stackoverflow.com/a/67419837
                        cronRegex = re.compile(
                            r"(^((\*\/)?([0-5]?[0-9])((\,|\-|\/)([0-5]?[0-9]))*|\*)\s+((\*\/)?((2[0-3]|1[0-9]|[0-9]|00))((\,|\-|\/)(2[0-3]|1[0-9]|[0-9]|00))*|\*)\s+((\*\/)?([1-9]|[12][0-9]|3[01])((\,|\-|\/)([1-9]|[12][0-9]|3[01]))*|\*)\s+((\*\/)?([1-9]|1[0-2])((\,|\-|\/)([1-9]|1[0-2]))*|\*|(jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|des))\s+((\*\/)?[0-6]((\,|\-|\/)[0-6])*|\*|00|(sun|mon|tue|wed|thu|fri|sat))\s*$)|@(annually|yearly|monthly|weekly|daily|hourly)"
                        )
                        zeekIntelCronExpression = '_invalid_'
                        loopBreaker = CountUntilException(MaxAskForValueCount, 'Invalid cron expression')
                        while loopBreaker.increment():
                            zeekIntelCronExpression = InstallerAskForString(
                                'Cron expression for scheduled pulls from threat intelligence feeds',
                                default=args.zeekIntelCronExpression,
                                extraLabel=BACK_LABEL,
                            )
                            if len(zeekIntelCronExpression) == 0:
                                if InstallerYesOrNo(
                                    'An empty cron expression will disable scheduled threat intelligence updates, are you sure?',
                                    default=False,
                                    extraLabel=BACK_LABEL,
                                ):
                                    break
                            elif cronRegex.match(zeekIntelCronExpression):
                                break

                        zeekIntelFeedSince = ''
                        loopBreaker = CountUntilException(MaxAskForValueCount, 'Invalid "since" period')
                        while (len(zeekIntelFeedSince) <= 0) and loopBreaker.increment():
                            zeekIntelFeedSince = InstallerAskForString(
                                'Threat indicator "since" period',
                                default=args.zeekIntelFeedSince,
                                extraLabel=BACK_LABEL,
                            )

                        zeekIntelItemExipration = ''
                        loopBreaker = CountUntilException(MaxAskForValueCount, 'Invalid Intel::item_expiration timeout')
                        while (len(zeekIntelItemExipration) <= 0) and loopBreaker.increment():
                            zeekIntelItemExipration = InstallerAskForString(
                                "Intel::item_expiration timeout for intelligence items (-1min to disable)",
                                default=args.zeekIntelItemExipration,
                                extraLabel=BACK_LABEL,
                            )

                        InstallerDisplayMessage(
                            f'Place feed definitions in\n\n  * TAXII - {os.path.join(malcolm_install_path, "zeek/intel/STIX/taxii.yaml")}\n  * MISP - {os.path.join(malcolm_install_path, "zeek/intel/MISP/misp.yaml")}\n  * Mandiant - {os.path.join(malcolm_install_path, "zeek/intel/Mandiant/mandiant.yaml")}\n\nSee Zeek Intelligence Framework in Malcolm documentation.',
                        )

                ###################################################################################
                elif currentStep == ConfigOptions.NetBox:
                    netboxOptions = (
                        ('disabled', 'disable NetBox'),
                        ('local', 'Run and maintain an embedded NetBox instance'),
                        ('remote', 'Use a remote NetBox instance'),
                    )
                    loopBreaker = CountUntilException(MaxAskForValueCount)
                    netboxMode = None
                    netboxUrl = ''
                    if malcolmProfile == PROFILE_MALCOLM:
                        while netboxMode not in [x[0] for x in netboxOptions] and loopBreaker.increment():
                            netboxMode = InstallerChooseOne(
                                'Should Malcolm utilize NetBox, an infrastructure resource modeling tool?',
                                choices=[
                                    (
                                        x[0],
                                        x[1],
                                        (
                                            (not args.netboxMode and x[0] == netboxOptions[0])
                                            or (x[0] == args.netboxMode)
                                        ),
                                    )
                                    for x in netboxOptions
                                ],
                                extraLabel=BACK_LABEL,
                            )
                    else:
                        netboxMode = 'disabled'
                    netboxEnabled = bool(netboxMode and (netboxMode != 'disabled'))
                    if netboxMode == 'remote':
                        loopBreaker = CountUntilException(MaxAskForValueCount, 'Invalid NetBox URL')
                        while (len(netboxUrl) <= 1) and loopBreaker.increment():
                            netboxUrl = InstallerAskForString(
                                'Enter NetBox connection URL (e.g., https://netbox.example.org)',
                                default=args.netboxUrl,
                                extraLabel=BACK_LABEL,
                            )
                        InstallerDisplayMessage(
                            f'You must run auth_setup after {ScriptName} to store NetBox API token.',
                        )

                    netboxLogstashEnrich = netboxEnabled and InstallerYesOrNo(
                        'Should Malcolm enrich network traffic using NetBox?',
                        default=args.netboxLogstashEnrich,
                        extraLabel=BACK_LABEL,
                    )
                    netboxAutoPopulate = netboxEnabled and InstallerYesOrNo(
                        'Should Malcolm automatically populate NetBox inventory based on observed network traffic?',
                        default=args.netboxAutoPopulate,
                        extraLabel=BACK_LABEL,
                    )
                    loopBreaker = CountUntilException(MaxAskForValueCount, 'Invalid NetBox IP autopopulation filter')
                    stripSpacePattern = re.compile(r'\s+')
                    while loopBreaker.increment():
                        netboxAutoPopulateSubnets = (
                            InstallerAskForString(
                                'Specify NetBox IP autopopulation filter',
                                default=args.netboxAutopopFilter,
                                extraLabel=BACK_LABEL,
                            )
                            if (netboxEnabled and netboxAutoPopulate)
                            else ''
                        )
                        if netboxAutoPopulateSubnets:
                            netboxAutoPopulateSubnets = ';'.join(
                                f"{k.strip()}:{stripSpacePattern.sub('', v)}"
                                for item in netboxAutoPopulateSubnets.split(';')
                                for k, v in [item.split(':', 1) if ':' in item else ('*', item)]
                            )
                        if ValidNetBoxSubnetFilter(netboxAutoPopulateSubnets):
                            break
                    netboxLogstashAutoSubnets = netboxLogstashEnrich and InstallerYesOrNo(
                        'Should Malcolm automatically create missing NetBox subnet prefixes based on observed network traffic?',
                        default=args.netboxLogstashAutoSubnets,
                        extraLabel=BACK_LABEL,
                    )
                    netboxSiteName = (
                        InstallerAskForString(
                            'Specify default NetBox site name',
                            default=args.netboxSiteName,
                            extraLabel=BACK_LABEL,
                        )
                        if netboxEnabled
                        else ''
                    )
                    if len(netboxSiteName) == 0:
                        netboxSiteName = 'Malcolm'

                ###################################################################################
                elif currentStep == ConfigOptions.Capture:
                    # input packet capture parameters
                    pcapNetSniff = False
                    pcapTcpDump = False
                    liveArkime = False
                    liveArkimeNodeHost = ''
                    liveZeek = False
                    liveSuricata = False
                    pcapIface = 'lo'
                    tweakIface = False
                    pcapFilter = ''
                    captureStats = False
                    captureSelection = (
                        'c'
                        if (
                            args.pcapNetSniff
                            or args.pcapTcpDump
                            or args.liveZeek
                            or args.liveSuricata
                            or (malcolmProfile == PROFILE_HEDGEHOG)
                        )
                        else 'unset'
                    )

                    captureOptions = ('no', 'yes', 'customize')
                    loopBreaker = CountUntilException(MaxAskForValueCount)
                    while captureSelection not in [x[0] for x in captureOptions] and loopBreaker.increment():
                        captureSelection = InstallerChooseOne(
                            'Should Malcolm capture live network traffic?',
                            choices=[(x, '', x == captureOptions[0]) for x in captureOptions],
                            extraLabel=BACK_LABEL,
                        )[0]
                    if captureSelection == 'y':
                        liveArkime = (malcolmProfile == PROFILE_HEDGEHOG) or (
                            opensearchPrimaryMode != DatabaseMode.OpenSearchLocal
                        )
                        pcapNetSniff = not liveArkime
                        liveSuricata = True
                        liveZeek = True
                        captureStats = True
                        tweakIface = True
                    elif captureSelection == 'c':
                        if InstallerYesOrNo(
                            'Should Malcolm capture live network traffic to PCAP files for analysis with Arkime?',
                            default=args.pcapNetSniff
                            or args.pcapTcpDump
                            or args.liveArkime
                            or (malcolmProfile == PROFILE_HEDGEHOG),
                            extraLabel=BACK_LABEL,
                        ):
                            liveArkime = (opensearchPrimaryMode != DatabaseMode.OpenSearchLocal) and (
                                (malcolmProfile == PROFILE_HEDGEHOG)
                                or InstallerYesOrNo(
                                    'Capture packets using Arkime capture?',
                                    default=args.liveArkime,
                                    extraLabel=BACK_LABEL,
                                )
                            )
                            pcapNetSniff = (not liveArkime) and InstallerYesOrNo(
                                'Capture packets using netsniff-ng?',
                                default=args.pcapNetSniff,
                                extraLabel=BACK_LABEL,
                            )
                            pcapTcpDump = (
                                (not liveArkime)
                                and (not pcapNetSniff)
                                and InstallerYesOrNo(
                                    'Capture packets using tcpdump?',
                                    default=args.pcapTcpDump,
                                    extraLabel=BACK_LABEL,
                                )
                            )
                        liveSuricata = InstallerYesOrNo(
                            'Should Malcolm analyze live network traffic with Suricata?',
                            default=args.liveSuricata,
                            extraLabel=BACK_LABEL,
                        )
                        liveZeek = InstallerYesOrNo(
                            'Should Malcolm analyze live network traffic with Zeek?',
                            default=args.liveZeek,
                            extraLabel=BACK_LABEL,
                        )
                        if pcapNetSniff or pcapTcpDump or liveArkime or liveZeek or liveSuricata:
                            pcapFilter = InstallerAskForString(
                                'Capture filter (tcpdump-like filter expression; leave blank to capture all traffic)',
                                default=args.pcapFilter,
                                extraLabel=BACK_LABEL,
                            )
                            # Arkime requires disabling NIC offloading: https://arkime.com/faq#arkime_requires_full_packet_captures_error
                            tweakIface = liveArkime or InstallerYesOrNo(
                                'Disable capture interface hardware offloading and adjust ring buffer sizes?',
                                default=args.tweakIface,
                                extraLabel=BACK_LABEL,
                            )
                        captureStats = (liveZeek or liveSuricata) and InstallerYesOrNo(
                            'Enable live packet capture statistics?',
                            default=args.captureStats,
                            extraLabel=BACK_LABEL,
                        )

                    if pcapNetSniff or pcapTcpDump or liveArkime or liveZeek or liveSuricata:
                        pcapIface = ''
                        loopBreaker = CountUntilException(MaxAskForValueCount, 'Invalid capture interface(s)')
                        while (len(pcapIface) <= 0) and loopBreaker.increment():
                            pcapIface = InstallerAskForString(
                                'Specify capture interface(s) (comma-separated)',
                                default=args.pcapIface,
                                extraLabel=BACK_LABEL,
                            )

                    if liveArkime:
                        liveArkimeNodeHost = InstallerAskForString(
                            f"Enter this node's hostname or IP to associate with network traffic metadata",
                            default=args.liveArkimeNodeHost,
                            extraLabel=BACK_LABEL,
                        )

                    if (
                        (malcolmProfile == PROFILE_HEDGEHOG)
                        and (not pcapNetSniff)
                        and (not pcapTcpDump)
                        and (not liveZeek)
                        and (not liveSuricata)
                        and (not liveArkime)
                    ):
                        InstallerDisplayMessage(
                            f'Warning: Running with the {malcolmProfile} profile but no capture methods are enabled.',
                        )

                ###################################################################################
                elif currentStep == ConfigOptions.DarkMode:
                    dashboardsDarkMode = (
                        (malcolmProfile == PROFILE_MALCOLM)
                        and (opensearchPrimaryMode != DatabaseMode.ElasticsearchRemote)
                        and InstallerYesOrNo(
                            'Enable dark mode for OpenSearch Dashboards?',
                            default=args.dashboardsDarkMode,
                            extraLabel=BACK_LABEL,
                        )
                    )

                ###################################################################################
                elif int(currentStep) >= int(ConfigOptions.PostConfig):
                    break

            except DialogBackException:
                if int(currentStep) >= 2:
                    currentStep = ConfigOptions(int(currentStep) - 2)
                else:
                    currentStep = ConfigOptions.Preconfig

            except DialogCanceledException:
                raise

        # modify values in .env files in args.configDir

        # if a specific *.env file doesn't exist, use the config/*.example.env files as defaults
        if os.path.isdir(examplesConfigDir := os.path.join(malcolm_install_path, 'config')):
            for envExampleFile in glob.glob(os.path.join(examplesConfigDir, '*.env.example')):
                envFile = os.path.join(args.configDir, os.path.basename(envExampleFile[: -len('.example')]))
                if not os.path.isfile(envFile):
                    logging.info(f"Creating {envFile} from {envExampleFile}")
                    shutil.copyfile(envExampleFile, envFile)

        EnvValues = [
            # Whether or not Arkime is allowed to delete uploaded/captured PCAP
            EnvValue(
                True,
                os.path.join(args.configDir, 'arkime.env'),
                'MANAGE_PCAP_FILES',
                TrueOrFalseNoQuote(arkimeManagePCAP),
            ),
            # Threshold for Arkime PCAP deletion
            EnvValue(
                True,
                os.path.join(args.configDir, 'arkime.env'),
                'ARKIME_FREESPACEG',
                arkimeFreeSpaceG,
            ),
            # live traffic analysis with Arkime capture (only available with remote opensearch or elasticsearch)
            EnvValue(
                True,
                os.path.join(args.configDir, 'arkime-live.env'),
                'ARKIME_LIVE_CAPTURE',
                TrueOrFalseNoQuote(liveArkime),
            ),
            # capture source "node host" for live Arkime capture
            EnvValue(
                True,
                os.path.join(args.configDir, 'arkime-live.env'),
                'ARKIME_LIVE_NODE_HOST',
                liveArkimeNodeHost,
            ),
            # rotated captured PCAP analysis with Arkime (not live capture)
            EnvValue(
                True,
                os.path.join(args.configDir, 'arkime-offline.env'),
                'ARKIME_ROTATED_PCAP',
                TrueOrFalseNoQuote(autoArkime and (not liveArkime)),
            ),
            # automatic uploaded pcap analysis with Arkime
            EnvValue(
                True,
                os.path.join(args.configDir, 'arkime-offline.env'),
                'ARKIME_AUTO_ANALYZE_PCAP_FILES',
                TrueOrFalseNoQuote(autoArkime),
            ),
            # Should Arkime use an ILM policy?
            EnvValue(
                True,
                os.path.join(args.configDir, 'arkime.env'),
                'INDEX_MANAGEMENT_ENABLED',
                TrueOrFalseNoQuote(indexManagementPolicy),
            ),
            # Should Arkime use a hot/warm design in which non-session data is stored in a warm index? (see https://https://arkime.com/faq#ilm)
            EnvValue(
                True,
                os.path.join(args.configDir, 'arkime.env'),
                'INDEX_MANAGEMENT_HOT_WARM_ENABLED',
                TrueOrFalseNoQuote(indexManagementHotWarm),
            ),
            # Time in hours/days before moving (Arkime indexes to warm) and force merge (number followed by h or d), default 30
            EnvValue(
                True,
                os.path.join(args.configDir, 'arkime.env'),
                'INDEX_MANAGEMENT_OPTIMIZATION_PERIOD',
                indexManagementOptimizationTimePeriod,
            ),
            # Time in hours/days before deleting Arkime indexes (number followed by h or d), default 90
            EnvValue(
                True,
                os.path.join(args.configDir, 'arkime.env'),
                'INDEX_MANAGEMENT_RETENTION_TIME',
                indexManagementSpiDataRetention,
            ),
            # Number of replicas for older sessions indices in the ILM policy, default 0
            EnvValue(
                True,
                os.path.join(args.configDir, 'arkime.env'),
                'INDEX_MANAGEMENT_OLDER_SESSION_REPLICAS',
                indexManagementReplicas,
            ),
            # Number of weeks of history to keep, default 13
            EnvValue(
                True,
                os.path.join(args.configDir, 'arkime.env'),
                'INDEX_MANAGEMENT_HISTORY_RETENTION_WEEKS',
                indexManagementHistoryInWeeks,
            ),
            # Number of segments to optimize sessions to in the ILM policy, default 1
            EnvValue(
                True,
                os.path.join(args.configDir, 'arkime.env'),
                'INDEX_MANAGEMENT_SEGMENTS',
                indexManagementOptimizeSessionSegments,
            ),
            # Logstash host and port
            EnvValue(
                True,
                os.path.join(args.configDir, 'beats-common.env'),
                'LOGSTASH_HOST',
                logstashHost,
            ),
            # OpenSearch Dashboards URL
            EnvValue(
                True,
                os.path.join(args.configDir, 'dashboards.env'),
                'DASHBOARDS_URL',
                dashboardsUrl,
            ),
            # turn on dark mode, or not
            EnvValue(
                True,
                os.path.join(args.configDir, 'dashboards-helper.env'),
                'DASHBOARDS_DARKMODE',
                TrueOrFalseNoQuote(dashboardsDarkMode),
            ),
            # delete based on index pattern size
            EnvValue(
                True,
                os.path.join(args.configDir, 'dashboards-helper.env'),
                'OPENSEARCH_INDEX_SIZE_PRUNE_LIMIT',
                indexPruneSizeLimit,
            ),
            # delete based on index pattern size (sorted by name vs. creation time)
            EnvValue(
                True,
                os.path.join(args.configDir, 'dashboards-helper.env'),
                'OPENSEARCH_INDEX_SIZE_PRUNE_NAME_SORT',
                TrueOrFalseNoQuote(indexPruneNameSort),
            ),
            # expose a filebeat TCP input listener
            EnvValue(
                True,
                os.path.join(args.configDir, 'filebeat.env'),
                'FILEBEAT_TCP_LISTEN',
                TrueOrFalseNoQuote(filebeatTcpOpen),
            ),
            # log format expected for events sent to the filebeat TCP input listener
            EnvValue(
                True,
                os.path.join(args.configDir, 'filebeat.env'),
                'FILEBEAT_TCP_LOG_FORMAT',
                filebeatTcpFormat,
            ),
            # source field name to parse for events sent to the filebeat TCP input listener
            EnvValue(
                True,
                os.path.join(args.configDir, 'filebeat.env'),
                'FILEBEAT_TCP_PARSE_SOURCE_FIELD',
                filebeatTcpSourceField,
            ),
            # target field name to store decoded JSON fields for events sent to the filebeat TCP input listener
            EnvValue(
                True,
                os.path.join(args.configDir, 'filebeat.env'),
                'FILEBEAT_TCP_PARSE_TARGET_FIELD',
                filebeatTcpTargetField,
            ),
            # field to drop in events sent to the filebeat TCP input listener
            EnvValue(
                True,
                os.path.join(args.configDir, 'filebeat.env'),
                'FILEBEAT_TCP_PARSE_DROP_FIELD',
                filebeatTcpDropField,
            ),
            # tag to append to events sent to the filebeat TCP input listener
            EnvValue(
                True,
                os.path.join(args.configDir, 'filebeat.env'),
                'FILEBEAT_TCP_TAG',
                filebeatTcpTag,
            ),
            # Syslog over TCP
            EnvValue(
                True,
                os.path.join(args.configDir, 'filebeat.env'),
                'FILEBEAT_SYSLOG_TCP_LISTEN',
                TrueOrFalseNoQuote(syslogPortDict['tcp'] > 0),
            ),
            EnvValue(
                True,
                os.path.join(args.configDir, 'filebeat.env'),
                'FILEBEAT_SYSLOG_TCP_PORT',
                syslogPortDict['tcp'],
            ),
            # Syslog over UDP
            EnvValue(
                True,
                os.path.join(args.configDir, 'filebeat.env'),
                'FILEBEAT_SYSLOG_UDP_LISTEN',
                TrueOrFalseNoQuote(syslogPortDict['udp'] > 0),
            ),
            EnvValue(
                True,
                os.path.join(args.configDir, 'filebeat.env'),
                'FILEBEAT_SYSLOG_UDP_PORT',
                syslogPortDict['udp'],
            ),
            # logstash memory allowance
            EnvValue(
                True,
                os.path.join(args.configDir, 'logstash.env'),
                'LS_JAVA_OPTS',
                re.sub(r'(-Xm[sx])(\w+)', fr'\g<1>{lsMemory}', LOGSTASH_JAVA_OPTS_DEFAULT),
            ),
            # automatic local reverse dns lookup
            EnvValue(
                True,
                os.path.join(args.configDir, 'logstash.env'),
                'LOGSTASH_REVERSE_DNS',
                TrueOrFalseNoQuote(reverseDns),
            ),
            # automatic MAC OUI lookup
            EnvValue(
                True,
                os.path.join(args.configDir, 'logstash.env'),
                'LOGSTASH_OUI_LOOKUP',
                TrueOrFalseNoQuote(autoOui),
            ),
            # logstash pipeline workers
            EnvValue(
                True,
                os.path.join(args.configDir, 'logstash.env'),
                'pipeline.workers',
                lsWorkers,
            ),
            # freq.py string randomness calculations
            EnvValue(
                True,
                os.path.join(args.configDir, 'lookup-common.env'),
                'FREQ_LOOKUP',
                TrueOrFalseNoQuote(autoFreq),
            ),
            # enrich network traffic metadata via NetBox API calls
            EnvValue(
                True,
                os.path.join(args.configDir, 'netbox-common.env'),
                'NETBOX_ENRICHMENT',
                TrueOrFalseNoQuote(netboxLogstashEnrich),
            ),
            # create missing NetBox subnet prefixes based on observed network traffic
            EnvValue(
                True,
                os.path.join(args.configDir, 'netbox-common.env'),
                'NETBOX_AUTO_CREATE_PREFIX',
                TrueOrFalseNoQuote(netboxLogstashAutoSubnets),
            ),
            # populate the NetBox inventory based on observed network traffic
            EnvValue(
                True,
                os.path.join(args.configDir, 'netbox-common.env'),
                'NETBOX_AUTO_POPULATE',
                TrueOrFalseNoQuote(netboxAutoPopulate),
            ),
            # NetBox IP autopopulation filter
            EnvValue(
                True,
                os.path.join(args.configDir, 'netbox-common.env'),
                'NETBOX_AUTO_POPULATE_SUBNETS',
                netboxAutoPopulateSubnets,
            ),
            # NetBox default site name
            EnvValue(
                True,
                os.path.join(args.configDir, 'netbox-common.env'),
                'NETBOX_DEFAULT_SITE',
                netboxSiteName,
            ),
            # netbox mode
            EnvValue(
                True,
                os.path.join(args.configDir, 'netbox-common.env'),
                'NETBOX_MODE',
                netboxMode,
            ),
            # remote netbox URL
            EnvValue(
                True,
                os.path.join(args.configDir, 'netbox-common.env'),
                'NETBOX_URL',
                netboxUrl if (netboxMode == 'remote') else '',
            ),
            # HTTPS (nginxSSL=True) vs unencrypted HTTP (nginxSSL=False)
            EnvValue(
                True,
                os.path.join(args.configDir, 'nginx.env'),
                'NGINX_SSL',
                TrueOrFalseNoQuote(nginxSSL),
            ),
            # "off" parameters for IPv4/IPv6 for NGINX resolver
            EnvValue(
                True,
                os.path.join(args.configDir, 'nginx.env'),
                'NGINX_RESOLVER_IPV4_OFF',
                TrueOrFalseNoQuote(nginxResolverIpv4Off),
            ),
            EnvValue(
                True,
                os.path.join(args.configDir, 'nginx.env'),
                'NGINX_RESOLVER_IPV6_OFF',
                TrueOrFalseNoQuote(nginxResolverIpv6Off),
            ),
            # OpenSearch primary instance is local vs. remote
            EnvValue(
                True,
                os.path.join(args.configDir, 'opensearch.env'),
                'OPENSEARCH_PRIMARY',
                DATABASE_MODE_LABELS[opensearchPrimaryMode],
            ),
            # OpenSearch primary instance URL
            EnvValue(
                True,
                os.path.join(args.configDir, 'opensearch.env'),
                'OPENSEARCH_URL',
                opensearchPrimaryUrl,
            ),
            # OpenSearch primary instance needs SSL verification
            EnvValue(
                True,
                os.path.join(args.configDir, 'opensearch.env'),
                'OPENSEARCH_SSL_CERTIFICATE_VERIFICATION',
                TrueOrFalseNoQuote(opensearchPrimarySslVerify),
            ),
            # OpenSearch secondary instance URL
            EnvValue(
                True,
                os.path.join(args.configDir, 'opensearch.env'),
                'OPENSEARCH_SECONDARY_URL',
                opensearchSecondaryUrl,
            ),
            # OpenSearch secondary instance needs SSL verification
            EnvValue(
                True,
                os.path.join(args.configDir, 'opensearch.env'),
                'OPENSEARCH_SECONDARY_SSL_CERTIFICATE_VERIFICATION',
                TrueOrFalseNoQuote(opensearchSecondarySslVerify),
            ),
            # OpenSearch secondary remote instance is enabled
            EnvValue(
                True,
                os.path.join(args.configDir, 'opensearch.env'),
                'OPENSEARCH_SECONDARY',
                DATABASE_MODE_LABELS[opensearchSecondaryMode],
            ),
            # OpenSearch memory allowance
            EnvValue(
                True,
                os.path.join(args.configDir, 'opensearch.env'),
                'OPENSEARCH_JAVA_OPTS',
                re.sub(r'(-Xm[sx])(\w+)', fr'\g<1>{osMemory}', OPENSEARCH_JAVA_OPTS_DEFAULT),
            ),
            # capture pcaps via netsniff-ng
            EnvValue(
                True,
                os.path.join(args.configDir, 'pcap-capture.env'),
                'PCAP_ENABLE_NETSNIFF',
                TrueOrFalseNoQuote(pcapNetSniff),
            ),
            # capture pcaps via tcpdump
            EnvValue(
                True,
                os.path.join(args.configDir, 'pcap-capture.env'),
                'PCAP_ENABLE_TCPDUMP',
                TrueOrFalseNoQuote(pcapTcpDump and (not pcapNetSniff)),
            ),
            # disable NIC hardware offloading features and adjust ring buffers
            EnvValue(
                True,
                os.path.join(args.configDir, 'pcap-capture.env'),
                'PCAP_IFACE_TWEAK',
                TrueOrFalseNoQuote(tweakIface),
            ),
            # capture interface(s)
            EnvValue(
                True,
                os.path.join(args.configDir, 'pcap-capture.env'),
                'PCAP_IFACE',
                pcapIface,
            ),
            # capture filter
            EnvValue(
                True,
                os.path.join(args.configDir, 'pcap-capture.env'),
                'PCAP_FILTER',
                pcapFilter,
            ),
            # process UID
            EnvValue(
                True,
                os.path.join(args.configDir, 'process.env'),
                'PUID',
                puid,
            ),
            # process GID
            EnvValue(
                True,
                os.path.join(args.configDir, 'process.env'),
                'PGID',
                pgid,
            ),
            # Container runtime engine (e.g., docker, podman)
            EnvValue(
                True,
                os.path.join(args.configDir, 'process.env'),
                CONTAINER_RUNTIME_KEY,
                'kubernetes' if (self.orchMode is OrchestrationFramework.KUBERNETES) else args.runtimeBin,
            ),
            # Malcolm run profile (malcolm vs. hedgehog)
            EnvValue(
                True,
                os.path.join(args.configDir, 'process.env'),
                PROFILE_KEY,
                malcolmProfile,
            ),
            # Suricata signature updates (via suricata-update)
            EnvValue(
                True,
                os.path.join(args.configDir, 'suricata.env'),
                'SURICATA_UPDATE_RULES',
                TrueOrFalseNoQuote(suricataRuleUpdate),
            ),
            # disable/enable ICS analyzers
            EnvValue(
                True,
                os.path.join(args.configDir, 'suricata.env'),
                'SURICATA_DISABLE_ICS_ALL',
                TrueOrFalseNoQuote(not malcolmIcs),
            ),
            # live traffic analysis with Suricata
            EnvValue(
                True,
                os.path.join(args.configDir, 'suricata-live.env'),
                'SURICATA_LIVE_CAPTURE',
                TrueOrFalseNoQuote(liveSuricata),
            ),
            # live capture statistics for Suricata
            EnvValue(
                True,
                os.path.join(args.configDir, 'suricata-live.env'),
                'SURICATA_STATS_ENABLED',
                TrueOrFalseNoQuote(captureStats),
            ),
            EnvValue(
                True,
                os.path.join(args.configDir, 'suricata-live.env'),
                'SURICATA_STATS_EVE_ENABLED',
                TrueOrFalseNoQuote(captureStats),
            ),
            # rotated captured PCAP analysis with Suricata (not live capture)
            EnvValue(
                True,
                os.path.join(args.configDir, 'suricata-offline.env'),
                'SURICATA_ROTATED_PCAP',
                TrueOrFalseNoQuote(autoSuricata and (not liveSuricata)),
            ),
            # automatic uploaded pcap analysis with suricata
            EnvValue(
                True,
                os.path.join(args.configDir, 'suricata-offline.env'),
                'SURICATA_AUTO_ANALYZE_PCAP_FILES',
                TrueOrFalseNoQuote(autoSuricata),
            ),
            # capture source "node name" for locally processed PCAP files
            EnvValue(
                True,
                os.path.join(args.configDir, 'upload-common.env'),
                'PCAP_NODE_NAME',
                pcapNodeName,
            ),
            # zeek file extraction mode
            EnvValue(
                True,
                os.path.join(args.configDir, 'zeek.env'),
                'ZEEK_EXTRACTOR_MODE',
                fileCarveMode,
            ),
            # zeek file preservation mode
            EnvValue(
                True,
                os.path.join(args.configDir, 'zeek.env'),
                'EXTRACTED_FILE_PRESERVATION',
                filePreserveMode,
            ),
            # total disk fill threshold for pruning zeek extracted files
            EnvValue(
                True,
                os.path.join(args.configDir, 'zeek.env'),
                'EXTRACTED_FILE_PRUNE_THRESHOLD_TOTAL_DISK_USAGE_PERCENT',
                extractedFileMaxPercentThreshold,
            ),
            # zeek extracted files maximum consumption threshold
            EnvValue(
                True,
                os.path.join(args.configDir, 'zeek.env'),
                'EXTRACTED_FILE_PRUNE_THRESHOLD_MAX_SIZE',
                extractedFileMaxSizeThreshold,
            ),
            # HTTP server for extracted files
            EnvValue(
                True,
                os.path.join(args.configDir, 'zeek.env'),
                'EXTRACTED_FILE_HTTP_SERVER_ENABLE',
                TrueOrFalseNoQuote(fileCarveHttpServer),
            ),
            # ZIP HTTP server for extracted files
            EnvValue(
                True,
                os.path.join(args.configDir, 'zeek.env'),
                'EXTRACTED_FILE_HTTP_SERVER_ZIP',
                TrueOrFalseNoQuote(fileCarveHttpServerZip),
            ),
            # key for encrypted HTTP-served extracted files (' -> '' for escaping in YAML)
            EnvValue(
                True,
                os.path.join(args.configDir, 'zeek-secret.env'),
                'EXTRACTED_FILE_HTTP_SERVER_KEY',
                fileCarveHttpServeEncryptKey,
            ),
            # virustotal API key
            EnvValue(
                True,
                os.path.join(args.configDir, 'zeek-secret.env'),
                'VTOT_API2_KEY',
                vtotApiKey,
            ),
            # file scanning via virustotal
            EnvValue(
                True,
                os.path.join(args.configDir, 'zeek.env'),
                'EXTRACTED_FILE_ENABLE_VTOT',
                TrueOrFalseNoQuote(len(vtotApiKey) > 1),
            ),
            # file scanning via yara
            EnvValue(
                True,
                os.path.join(args.configDir, 'zeek.env'),
                'EXTRACTED_FILE_ENABLE_YARA',
                TrueOrFalseNoQuote(yaraScan),
            ),
            # PE file scanning via capa
            EnvValue(
                True,
                os.path.join(args.configDir, 'zeek.env'),
                'EXTRACTED_FILE_ENABLE_CAPA',
                TrueOrFalseNoQuote(capaScan),
            ),
            # file scanning via clamav
            EnvValue(
                True,
                os.path.join(args.configDir, 'zeek.env'),
                'EXTRACTED_FILE_ENABLE_CLAMAV',
                TrueOrFalseNoQuote(clamAvScan),
            ),
            # rule updates (yara/capa via git, clamav via freshclam)
            EnvValue(
                True,
                os.path.join(args.configDir, 'zeek.env'),
                'EXTRACTED_FILE_UPDATE_RULES',
                TrueOrFalseNoQuote(fileScanRuleUpdate),
            ),
            # disable/enable ICS analyzers
            EnvValue(
                True,
                os.path.join(args.configDir, 'zeek.env'),
                'ZEEK_DISABLE_ICS_ALL',
                '' if malcolmIcs else TrueOrFalseNoQuote(not malcolmIcs),
            ),
            # disable/enable ICS best guess
            EnvValue(
                True,
                os.path.join(args.configDir, 'zeek.env'),
                'ZEEK_DISABLE_BEST_GUESS_ICS',
                '' if zeekICSBestGuess else TrueOrFalseNoQuote(not zeekICSBestGuess),
            ),
            # live traffic analysis with Zeek
            EnvValue(
                True,
                os.path.join(args.configDir, 'zeek-live.env'),
                'ZEEK_LIVE_CAPTURE',
                TrueOrFalseNoQuote(liveZeek),
            ),
            # live capture statistics for Zeek
            EnvValue(
                True,
                os.path.join(args.configDir, 'zeek-live.env'),
                'ZEEK_DISABLE_STATS',
                TrueOrFalseNoQuote(not captureStats),
            ),
            # rotated captured PCAP analysis with Zeek (not live capture)
            EnvValue(
                True,
                os.path.join(args.configDir, 'zeek-offline.env'),
                'ZEEK_ROTATED_PCAP',
                TrueOrFalseNoQuote(autoZeek and (not liveZeek)),
            ),
            # automatic uploaded pcap analysis with Zeek
            EnvValue(
                True,
                os.path.join(args.configDir, 'zeek-offline.env'),
                'ZEEK_AUTO_ANALYZE_PCAP_FILES',
                TrueOrFalseNoQuote(autoZeek),
            ),
            # Pull from threat intelligence feeds on container startup
            EnvValue(
                zeekIntelParamsProvided,
                os.path.join(args.configDir, 'zeek-offline.env'),
                'ZEEK_INTEL_REFRESH_ON_STARTUP',
                TrueOrFalseNoQuote(zeekIntelOnStartup),
            ),
            # Cron expression for scheduled pulls from threat intelligence feeds
            EnvValue(
                zeekIntelParamsProvided,
                os.path.join(args.configDir, 'zeek-offline.env'),
                'ZEEK_INTEL_REFRESH_CRON_EXPRESSION',
                zeekIntelCronExpression,
            ),
            # Threat indicator "since" period
            EnvValue(
                zeekIntelParamsProvided,
                os.path.join(args.configDir, 'zeek.env'),
                'ZEEK_INTEL_FEED_SINCE',
                zeekIntelFeedSince,
            ),
            # Intel::item_expiration timeout for intelligence items
            EnvValue(
                zeekIntelParamsProvided,
                os.path.join(args.configDir, 'zeek.env'),
                'ZEEK_INTEL_ITEM_EXPIRATION',
                zeekIntelItemExipration,
            ),
            # Use polling for file watching vs. native
            EnvValue(
                True,
                os.path.join(args.configDir, 'zeek.env'),
                'EXTRACTED_FILE_WATCHER_POLLING',
                TrueOrFalseNoQuote(self.orchMode is OrchestrationFramework.KUBERNETES),
            ),
            EnvValue(
                True,
                os.path.join(args.configDir, 'upload-common.env'),
                'PCAP_PIPELINE_POLLING',
                TrueOrFalseNoQuote(self.orchMode is OrchestrationFramework.KUBERNETES),
            ),
            EnvValue(
                True,
                os.path.join(args.configDir, 'filebeat.env'),
                'FILEBEAT_WATCHER_POLLING',
                TrueOrFalseNoQuote(self.orchMode is OrchestrationFramework.KUBERNETES),
            ),
        ]

        # now, go through and modify the provided values in the .env files
        UpdateEnvFiles(EnvValues)

        # if any arbitrary extra .env settings were specified, handle those last (e.g., foobar.env:VARIABLE_NAME=value)
        if args.extraSettings:
            extraVarRegex = re.compile(r"^([^:]+):([^=]+)=(.*)$")
            for extraSetting in args.extraSettings:
                if extraVarParts := extraVarRegex.match(extraSetting):
                    extraFile, extraVar, extraVal = [str(x).strip() for x in extraVarParts.groups()]
                    extraFile = os.path.join(args.configDir, os.path.basename(extraFile))

                    if not extraFile.endswith('.env'):
                        # only allow extra settings to modify .env files
                        logging.error(
                            f"Ignoring extra value ({extraVar}={extraVal}) in {os.path.basename(extraFile)} (not .env file)"
                        )

                    elif any(
                        [
                            x
                            for x in EnvValues
                            if (os.path.basename(x.envFile) == os.path.basename(extraFile)) and (x.key == extraVar)
                        ]
                    ):
                        # if this is one of the values that's settable through one of the
                        #   normal command-line arguments, don't allow it: force them
                        #   to use the appropriate command-line argument instead
                        logging.error(
                            f"Ignoring extra value ({extraVar}={extraVal}) in {os.path.basename(extraFile)} (use dedicated CLI argument)"
                        )

                    else:
                        extraValSuccess = UpdateEnvFiles(
                            [
                                EnvValue(
                                    True,
                                    extraFile,
                                    extraVar,
                                    extraVal,
                                ),
                            ]
                        )
                    logging.info(
                        f"Setting extra value ({extraVar}={extraVal}) in {os.path.basename(extraFile)} {'succeeded' if extraValSuccess else 'failed'}"
                    )

        # change ownership of .envs file to match puid/pgid
        if (
            ((self.platform == PLATFORM_LINUX) or (self.platform == PLATFORM_MAC))
            and (self.scriptUser == "root")
            and (getpwuid(os.stat(args.configDir).st_uid).pw_name == self.scriptUser)
        ):
            logging.info(f"Setting permissions of {args.configDir} to {puid}:{pgid}")
            os.chown(args.configDir, int(puid), int(pgid))
        envFiles = []
        for exts in ('*.env', '*.env.example'):
            envFiles.extend(glob.glob(os.path.join(args.configDir, exts)))
        for envFile in envFiles:
            if (
                ((self.platform == PLATFORM_LINUX) or (self.platform == PLATFORM_MAC))
                and (self.scriptUser == "root")
                and (getpwuid(os.stat(envFile).st_uid).pw_name == self.scriptUser)
            ):
                logging.info(f"Setting permissions of {envFile} to {puid}:{pgid}")
                os.chown(envFile, int(puid), int(pgid))

        if self.orchMode is OrchestrationFramework.DOCKER_COMPOSE:

            # modify docker-compose specific values (port mappings, volume bind mounts, etc.) in-place in docker-compose files
            for composeFile in configFiles:

                # save off owner of original files
                composeFileStat = os.stat(composeFile)
                origUid, origGuid = composeFileStat[4], composeFileStat[5]
                try:

                    # load the docker-compose file
                    data = LoadYaml(composeFile)

                    if 'services' in data:

                        ###################################
                        # stuff for all services
                        for service in data['services']:

                            # podman uses "userns_mode: keep-id"
                            deep_set(
                                data,
                                ['services', service, 'userns_mode'],
                                'keep-id' if args.runtimeBin.startswith('podman') else None,
                                deleteIfNone=True,
                            )

                            # podman and docker have different logging driver options
                            deep_set(
                                data,
                                ['services', service, 'logging', 'driver'],
                                'json-file' if args.runtimeBin.startswith('podman') else 'local',
                            )

                            # whether or not to restart services automatically (on boot, etc.)
                            deep_set(
                                data,
                                ['services', service, 'restart'],
                                restartMode,
                            )

                            # use architecture-specific images
                            image = deep_get(
                                data,
                                ['services', service, 'image'],
                            )
                            if image:
                                imageLineSpit = image.rstrip().split(":")
                                imageLineSpit[-1] = imageLineSpit[-1].split("-", 1)[0] + args.imageArch
                                deep_set(data, ['services', service, 'image'], ":".join(imageLineSpit))

                        ###################################
                        # stuff for specific services

                        ###################################
                        # for "large' storage locations (pcap, logs, opensearch, etc.) replace
                        #   bind mount sources with user-specified locations
                        boundPathsToAdjust = (
                            BoundPathReplacer("arkime", "/data/pcap", pcapDir),
                            BoundPathReplacer("arkime-live", "/data/pcap", pcapDir),
                            BoundPathReplacer("filebeat", "/suricata", suricataLogDir),
                            BoundPathReplacer("filebeat", "/zeek", zeekLogDir),
                            BoundPathReplacer(
                                "file-monitor", "/zeek/extract_files", os.path.join(zeekLogDir, 'extract_files')
                            ),
                            BoundPathReplacer("file-monitor", "/zeek/logs", os.path.join(zeekLogDir, 'current')),
                            BoundPathReplacer("opensearch", "/usr/share/opensearch/data", indexDir),
                            BoundPathReplacer("opensearch", "/opt/opensearch/backup", indexSnapshotDir),
                            BoundPathReplacer("pcap-capture", "/pcap", os.path.join(pcapDir, 'upload')),
                            BoundPathReplacer("pcap-monitor", "/pcap", pcapDir),
                            BoundPathReplacer("pcap-monitor", "/zeek", zeekLogDir),
                            BoundPathReplacer("suricata", "/data/pcap", pcapDir),
                            BoundPathReplacer("suricata", "/var/log/suricata", suricataLogDir),
                            BoundPathReplacer("suricata-live", "/var/log/suricata", suricataLogDir),
                            BoundPathReplacer(
                                "upload", "/var/www/upload/server/php/chroot/files", os.path.join(pcapDir, 'upload')
                            ),
                            BoundPathReplacer("zeek", "/pcap", pcapDir),
                            BoundPathReplacer("zeek", "/zeek/upload", os.path.join(zeekLogDir, 'upload')),
                            BoundPathReplacer("zeek", "/zeek/extract_files", os.path.join(zeekLogDir, 'extract_files')),
                            BoundPathReplacer("zeek-live", "/zeek/live", os.path.join(zeekLogDir, 'live')),
                            BoundPathReplacer(
                                "zeek-live", "/zeek/extract_files", os.path.join(zeekLogDir, 'extract_files')
                            ),
                        )
                        for boundPath in boundPathsToAdjust:
                            if (
                                (boundPath.service in data['services'])
                                and ('volumes' in data['services'][boundPath.service])
                                and os.path.isdir(boundPath.source)
                            ):
                                for volIdx, volVal in enumerate(data['services'][boundPath.service]['volumes']):
                                    if (
                                        isinstance(volVal, dict)
                                        and ('source' in volVal)
                                        and ('target' in volVal)
                                        and (volVal['target'] == boundPath.target)
                                    ):
                                        data['services'][boundPath.service]['volumes'][volIdx][
                                            'source'
                                        ] = boundPath.source
                                    elif isinstance(volVal, str) and re.match(
                                        fr'^.+:{boundPath.target}(:.+)?\s*$', volVal
                                    ):
                                        volumeParts = volVal.strip().split(':')
                                        volumeParts[0] = boundPath.source
                                        data['services'][boundPath.service]['volumes'][volIdx] = ':'.join(volumeParts)
                        ###################################

                        ###################################
                        # port bind IPs (0.0.0.0 vs. 127.0.0.1)
                        # set bind IPs based on whether services should be externally exposed or not

                        ufwManagerCmd = 'ufw_manager.sh'
                        if not which(ufwManagerCmd, debug=self.debug):
                            if os.path.isfile('/usr/local/bin/ufw_manager.sh'):
                                ufwManagerCmd = '/usr/local/bin/ufw_manager.sh'
                            else:
                                ufwManagerCmd = None

                        if ufwManagerCmd:
                            err, out = self.run_process(
                                [ufwManagerCmd, '-a', 'reset'],
                                privileged=True,
                            )
                            if err != 0:
                                logging.error(f"Resetting UFW firewall failed: {out}")

                        for service, portInfos in {
                            'filebeat': [
                                [filebeatTcpOpen, 5045, 5045, 'tcp'],
                                [syslogPortDict['tcp'] > 0, syslogPortDict['tcp'], syslogPortDict['tcp'], 'tcp'],
                                [syslogPortDict['udp'] > 0, syslogPortDict['udp'], syslogPortDict['udp'], 'udp'],
                            ],
                            'logstash': [
                                [logstashOpen, 5044, 5044, 'tcp'],
                            ],
                            'upload': [
                                [sftpOpen, 8022, 22, 'tcp'],
                            ],
                        }.items():
                            if service in data['services']:
                                if malcolmProfile == PROFILE_HEDGEHOG:
                                    data['services'][service].pop('ports', None)
                                else:
                                    data['services'][service]['ports'] = []
                                    for portInfo in portInfos:
                                        if all(x for x in portInfo):
                                            data['services'][service]['ports'].append(
                                                f"0.0.0.0:{portInfo[1]}:{portInfo[2]}/{portInfo[3]}"
                                            )
                                            if ufwManagerCmd:
                                                err, out = self.run_process(
                                                    [ufwManagerCmd, '-a', 'allow', f'{portInfo[1]}/{portInfo[3]}'],
                                                    privileged=True,
                                                )
                                                if err != 0:
                                                    logging.error(
                                                        f"Setting UFW 'allow {portInfo[1]}/{portInfo[3]}' failed: {out}"
                                                    )
                                    if not data['services'][service]['ports']:
                                        data['services'][service].pop('ports', None)
                        ###################################

                        ###################################
                        # nginx-proxy has got a lot going on
                        if 'nginx-proxy' in data['services']:

                            # set bind IPs and ports based on whether it should be externally exposed or not
                            if (malcolmProfile == PROFILE_HEDGEHOG) or (behindReverseProxy and traefikLabels):
                                data['services']['nginx-proxy'].pop('ports', None)
                            else:
                                data['services']['nginx-proxy']['ports'] = [
                                    f"{'0.0.0.0:443' if nginxSSL else '127.0.0.1:80'}:443/tcp",
                                ]
                                if (opensearchPrimaryMode == DatabaseMode.OpenSearchLocal) and opensearchOpen:
                                    data['services']['nginx-proxy']['ports'].append(
                                        f"0.0.0.0:{'9200' if nginxSSL else '9201'}:9200/tcp"
                                    )
                                    if ufwManagerCmd:
                                        err, out = self.run_process(
                                            [ufwManagerCmd, '-a', 'allow', f"{'9200' if nginxSSL else '9201'}/tcp"],
                                            privileged=True,
                                        )
                                        if err != 0:
                                            logging.error(
                                                f"Setting UFW 'allow {'9200' if nginxSSL else '9201'}/tcp' failed: {out}"
                                            )

                            # enable/disable/configure traefik labels if applicable
                            for label in (
                                'traefik.http.routers.osmalcolm.rule',
                                'traefik.http.routers.osmalcolm.entrypoints',
                                'traefik.http.routers.osmalcolm.tls.certresolver',
                                'traefik.http.routers.osmalcolm.service',
                                'traefik.http.services.osmalcolm.loadbalancer.server.port',
                                'traefik.http.routers.malcolm.rule',
                                'traefik.http.routers.malcolm.entrypoints',
                                'traefik.http.routers.malcolm.tls.certresolver',
                                'traefik.http.routers.malcolm.service',
                                'traefik.http.services.malcolm.loadbalancer.server.port',
                            ):
                                data['services']['nginx-proxy']['labels'].pop(label, None)

                            # Traefik enabled vs. disabled
                            data['services']['nginx-proxy']['labels']['traefik.enable'] = bool(traefikLabels)

                            if traefikLabels:
                                # general router enabled/disabled/host/etc values
                                data['services']['nginx-proxy']['labels'][
                                    'traefik.http.routers.malcolm.rule'
                                ] = f'Host(`{traefikHost}`)'
                                data['services']['nginx-proxy']['labels'][
                                    'traefik.http.routers.malcolm.entrypoints'
                                ] = traefikEntrypoint
                                data['services']['nginx-proxy']['labels'][
                                    'traefik.http.routers.malcolm.tls.certresolver'
                                ] = traefikResolver
                                data['services']['nginx-proxy']['labels'][
                                    'traefik.http.routers.malcolm.service'
                                ] = 'malcolm'
                                data['services']['nginx-proxy']['labels'][
                                    'traefik.http.services.malcolm.loadbalancer.server.port'
                                ] = '443'
                                if opensearchOpen:
                                    # OpenSearch router enabled/disabled/host/etc values
                                    data['services']['nginx-proxy']['labels'][
                                        'traefik.http.routers.osmalcolm.rule'
                                    ] = f'Host(`{traefikOpenSearchHost}`)'
                                    data['services']['nginx-proxy']['labels'][
                                        'traefik.http.routers.osmalcolm.entrypoints'
                                    ] = traefikEntrypoint
                                    data['services']['nginx-proxy']['labels'][
                                        'traefik.http.routers.osmalcolm.tls.certresolver'
                                    ] = traefikResolver
                                    data['services']['nginx-proxy']['labels'][
                                        'traefik.http.routers.osmalcolm.service'
                                    ] = 'osmalcolm'
                                    data['services']['nginx-proxy']['labels'][
                                        'traefik.http.services.osmalcolm.loadbalancer.server.port'
                                    ] = '9200'
                        ###################################

                    # re-write the network definition from scratch
                    if 'networks' in data:
                        del data['networks']
                    networkDef = {}
                    networkDef['external'] = bool(len(dockerNetworkExternalName) > 0)
                    if len(dockerNetworkExternalName) > 0:
                        networkDef['name'] = dockerNetworkExternalName
                    data['networks'] = {}
                    data['networks']['default'] = networkDef

                    # write the docker-compose file back out
                    DumpYaml(data, composeFile)

                finally:
                    # restore ownership
                    os.chown(composeFile, origUid, origGuid)

        try:
            touch(MalcolmCfgRunOnceFile)
            if ((self.platform == PLATFORM_LINUX) or (self.platform == PLATFORM_MAC)) and (self.scriptUser == "root"):
                os.chown(MalcolmCfgRunOnceFile, int(puid), int(pgid))
        except Exception:
            pass

        # if the Malcolm dir is owned by root, see if they want to reassign ownership to a non-root user
        if (
            ((self.platform == PLATFORM_LINUX) or (self.platform == PLATFORM_MAC))
            and (self.scriptUser == "root")
            and (getpwuid(os.stat(malcolm_install_path).st_uid).pw_name == self.scriptUser)
            and InstallerYesOrNo(
                f'Set ownership of {malcolm_install_path} to an account other than {self.scriptUser}?',
                default=True,
                forceInteraction=True,
            )
        ):
            tmpUser = ''
            while len(tmpUser) == 0:
                tmpUser = InstallerAskForString('Enter user account').strip()
            err, out = self.run_process(['id', '-g', '-n', tmpUser], stderr=True)
            if (err == 0) and (len(out) > 0) and (len(out[0]) > 0):
                tmpUser = f"{tmpUser}:{out[0]}"
            err, out = self.run_process(['chown', '-R', tmpUser, malcolm_install_path], stderr=True)
            if err == 0:
                logging.info(f"Changing ownership of {malcolm_install_path} to {tmpUser} succeeded")
            else:
                logging.error(f"Changing ownership of {malcolm_install_path} to {tmpUser} failed: {out}")


###################################################################################################
class LinuxInstaller(Installer):
    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    def __init__(self, orchMode, configOnly=False):
        super().__init__(orchMode, configOnly)

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
                    except Exception:
                        pass

            if ('NAME' in osInfo) and (len(osInfo['NAME']) > 0):
                self.distro = osInfo['NAME'].lower().split()[0]

            if ('VERSION_CODENAME' in osInfo) and (len(osInfo['VERSION_CODENAME']) > 0):
                self.codename = osInfo['VERSION_CODENAME'].lower().split()[0]

            if ('VERSION_ID' in osInfo) and (len(osInfo['VERSION_ID']) > 0):
                self.release = osInfo['VERSION_ID'].lower().split()[0]

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
            distroFile = next(
                (
                    path
                    for path in [
                        '/etc/rocky-release',
                        '/etc/almalinux-release',
                        '/etc/centos-release',
                        '/etc/redhat-release',
                        '/etc/issue',
                    ]
                    if os.path.isfile(path)
                ),
                None,
            )
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

        # determine packages required by Malcolm itself (not docker, those will be done later)
        if self.distro in (
            PLATFORM_LINUX_UBUNTU,
            PLATFORM_LINUX_DEBIAN,
        ):
            self.requiredPackages.extend(
                [
                    'apache2-utils',
                    'make',
                    'openssl',
                    'python3-dialog',
                    'python3-dotenv',
                    'python3-requests',
                    'python3-ruamel.yaml',
                    'xz-utils',
                ]
            )
        elif self.distro in (
            PLATFORM_LINUX_FEDORA,
            PLATFORM_LINUX_CENTOS,
        ):
            self.requiredPackages.extend(
                [
                    'httpd-tools',
                    'make',
                    'openssl',
                    'python3-dialog',
                    'python3-dotenv',
                    'python3-requests',
                    'python3-ruamel.yaml',
                    'xz',
                ]
            )
        elif self.distro in (
            PLATFORM_LINUX_ALMA,
            PLATFORM_LINUX_AMAZON,
            PLATFORM_LINUX_ROCKY,
        ):
            self.requiredPackages.extend(
                [
                    'httpd-tools',
                    'make',
                    'openssl',
                    'python3-requests',
                    'python3-ruamel-yaml',
                    'xz',
                ]
            )

        # on Linux this script requires root, or sudo, unless we're in local configuration-only mode
        if os.getuid() == 0:
            self.scriptUser = "root"
            self.sudoCmd = []
        else:
            self.sudoCmd = ["sudo", "-n"]
            err, out = self.run_process(['whoami'], privileged=True)
            if (
                ((err != 0) or (len(out) == 0) or (out[0] != 'root'))
                and (not self.configOnly)
                and (self.orchMode is OrchestrationFramework.DOCKER_COMPOSE)
            ):
                raise Exception(f'{ScriptName} must be run as root, or {self.sudoCmd} must be available')

        # determine command to use to query if a package is installed
        if which('dpkg', debug=self.debug):
            os.environ["DEBIAN_FRONTEND"] = "noninteractive"
            self.checkPackageCmds.append(['dpkg', '-s'])
        elif which('rpm', debug=self.debug):
            self.checkPackageCmds.append(['rpm', '-q'])
        elif which('dnf', debug=self.debug):
            self.checkPackageCmds.append(['dnf', 'list', 'installed'])
        elif which('yum', debug=self.debug):
            self.checkPackageCmds.append(['yum', 'list', 'installed'])

        # determine command to install a package from the distro's repos
        if which('apt-get', debug=self.debug):
            self.installPackageCmds.append(['apt-get', 'install', '-y', '-qq'])
        elif which('apt', debug=self.debug):
            self.installPackageCmds.append(['apt', 'install', '-y', '-qq'])
        elif which('dnf', debug=self.debug):
            self.installPackageCmds.append(['dnf', '-y', 'install', '--nobest'])
        elif which('yum', debug=self.debug):
            self.installPackageCmds.append(['yum', '-y', 'install'])

        # determine total system memory
        try:
            totalMemBytes = os.sysconf('SC_PAGE_SIZE') * os.sysconf('SC_PHYS_PAGES')
            self.totalMemoryGigs = math.ceil(totalMemBytes / (1024.0**3))
        except Exception:
            self.totalMemoryGigs = 0.0

        # determine total system memory a different way if the first way didn't work
        if self.totalMemoryGigs <= 0.0:
            err, out = self.run_process(['awk', '/MemTotal/ { printf "%.0f \\n", $2 }', '/proc/meminfo'])
            if (err == 0) and (len(out) > 0):
                totalMemKiloBytes = int(out[0])
                self.totalMemoryGigs = math.ceil(totalMemKiloBytes / (1024.0**2))

        # determine total system CPU cores
        try:
            self.totalCores = os.sysconf('SC_NPROCESSORS_ONLN')
        except Exception:
            self.totalCores = 0

        # determine total system CPU cores a different way if the first way didn't work
        if self.totalCores <= 0:
            err, out = self.run_process(['grep', '-c', '^processor', '/proc/cpuinfo'])
            if (err == 0) and (len(out) > 0):
                self.totalCores = int(out[0])

    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    def install_docker(self):
        global requests_imported

        result = False

        if self.orchMode is OrchestrationFramework.DOCKER_COMPOSE:
            # first see if docker is already installed and runnable
            err, out = self.run_process([args.runtimeBin, 'info'], privileged=True)

            if err == 0:
                result = True

            elif args.runtimeBin.startswith('docker') and InstallerYesOrNo(
                '"docker info" failed, attempt to install Docker?', default=True
            ):
                if InstallerYesOrNo('Attempt to install Docker using official repositories?', default=True):
                    # install required packages for repo-based install
                    if self.distro == PLATFORM_LINUX_UBUNTU:
                        requiredRepoPackages = [
                            'apt-transport-https',
                            'ca-certificates',
                            'curl',
                            'gnupg-agent',
                            'software-properties-common',
                        ]
                    elif self.distro == PLATFORM_LINUX_DEBIAN:
                        requiredRepoPackages = [
                            'apt-transport-https',
                            'ca-certificates',
                            'curl',
                            'gnupg2',
                            'software-properties-common',
                        ]
                    elif self.distro == PLATFORM_LINUX_FEDORA:
                        requiredRepoPackages = ['dnf-plugins-core']
                    elif self.distro == PLATFORM_LINUX_CENTOS:
                        requiredRepoPackages = ['yum-utils', 'device-mapper-persistent-data', 'lvm2']
                    elif self.distro in (
                        PLATFORM_LINUX_ALMA,
                        PLATFORM_LINUX_AMAZON,
                        PLATFORM_LINUX_ROCKY,
                    ):
                        requiredRepoPackages = ['dnf-utils']
                    else:
                        requiredRepoPackages = []

                    if len(requiredRepoPackages) > 0:
                        logging.info(f"Installing required packages: {requiredRepoPackages}")
                        self.install_package(requiredRepoPackages)

                    # install docker via repo if possible
                    dockerPackages = []
                    if (
                        (self.distro == PLATFORM_LINUX_UBUNTU) or (self.distro == PLATFORM_LINUX_DEBIAN)
                    ) and self.codename:
                        # for debian/ubuntu, add docker GPG key and check its fingerprint
                        logging.info("Requesting docker GPG key for package signing")
                        dockerGpgKey = requests_imported.get(
                            f'https://download.docker.com/linux/{self.distro}/gpg', allow_redirects=True
                        )
                        err, out = self.run_process(
                            ['apt-key', 'add'],
                            stdin=dockerGpgKey.content.decode(sys.getdefaultencoding()),
                            privileged=True,
                            stderr=False,
                        )
                        if err == 0:
                            err, out = self.run_process(
                                ['apt-key', 'fingerprint', DEB_GPG_KEY_FINGERPRINT], privileged=True, stderr=False
                            )

                        # add docker .deb repository
                        if err == 0:
                            logging.info("Adding docker repository")
                            err, out = self.run_process(
                                [
                                    'add-apt-repository',
                                    '-y',
                                    '-r',
                                    f'deb [arch=amd64] https://download.docker.com/linux/{self.distro} {self.codename} stable',
                                ],
                                privileged=True,
                            )
                            err, out = self.run_process(
                                [
                                    'add-apt-repository',
                                    '-y',
                                    '-u',
                                    f'deb [arch=amd64] https://download.docker.com/linux/{self.distro} {self.codename} stable',
                                ],
                                privileged=True,
                            )

                        # docker packages to install
                        if err == 0:
                            dockerPackages.extend(
                                ['docker-ce', 'docker-ce-cli', 'docker-compose-plugin', 'containerd.io']
                            )

                    elif self.distro == PLATFORM_LINUX_FEDORA:
                        # add docker fedora repository
                        logging.info("Adding docker repository")
                        err, out = self.run_process(
                            [
                                'dnf',
                                'config-manager',
                                '-y',
                                '--add-repo',
                                'https://download.docker.com/linux/fedora/docker-ce.repo',
                            ],
                            privileged=True,
                        )

                        # docker packages to install
                        if err == 0:
                            dockerPackages.extend(
                                ['docker-ce', 'docker-ce-cli', 'docker-compose-plugin', 'containerd.io']
                            )

                    elif self.distro == PLATFORM_LINUX_CENTOS:
                        # add docker centos repository
                        logging.info("Adding docker repository")
                        err, out = self.run_process(
                            [
                                'yum-config-manager',
                                '-y',
                                '--add-repo',
                                'https://download.docker.com/linux/centos/docker-ce.repo',
                            ],
                            privileged=True,
                        )

                        # docker packages to install
                        if err == 0:
                            dockerPackages.extend(
                                ['docker-ce', 'docker-ce-cli', 'docker-compose-plugin', 'containerd.io']
                            )

                    elif self.distro in (
                        PLATFORM_LINUX_ALMA,
                        PLATFORM_LINUX_ROCKY,
                    ):
                        # add docker rhel repository
                        logging.info("Adding docker repository")
                        err, out = self.run_process(
                            [
                                'dnf',
                                'config-manager',
                                '-y',
                                '--add-repo',
                                'https://download.docker.com/linux/centos/docker-ce.repo',
                            ],
                            privileged=True,
                        )

                        # docker packages to install
                        if err == 0:
                            dockerPackages.extend(
                                ['docker-ce', 'docker-ce-cli', 'docker-compose-plugin', 'containerd.io']
                            )

                    elif self.distro == PLATFORM_LINUX_AMAZON:
                        # docker packages to install
                        dockerPackages.extend(['docker'])

                    else:
                        err, out = None, None

                    if len(dockerPackages) > 0:
                        logging.info(f"Installing docker packages: {dockerPackages}")
                        if self.install_package(dockerPackages):
                            logging.info("Installation of docker packages apparently succeeded")
                            result = True
                        else:
                            logging.error("Installation of docker packages failed")

                # the user either chose not to use the official repos, the official repo installation failed, or there are not official repos available
                # see if we want to attempt using the convenience script at https://get.docker.com (see https://github.com/docker/docker-install)
                if not result and InstallerYesOrNo(
                    'Docker not installed via official repositories. Attempt to install Docker via convenience script (please read https://github.com/docker/docker-install)?',
                    default=False,
                ):
                    tempFileName = os.path.join(self.tempDirName, 'docker-install.sh')
                    if DownloadToFile("https://get.docker.com/", tempFileName, debug=self.debug):
                        os.chmod(tempFileName, 493)  # 493 = 0o755
                        err, out = self.run_process(([tempFileName]), privileged=True)
                        if err == 0:
                            logging.info("Installation of docker apparently succeeded")
                            result = True
                        else:
                            logging.error(f"Installation of docker failed: {out}")
                    else:
                        logging.error(f"Downloading https://get.docker.com/ to {tempFileName} failed")

            if (
                result
                and args.runtimeBin.startswith('docker')
                and (
                    self.distro
                    in (
                        PLATFORM_LINUX_ALMA,
                        PLATFORM_LINUX_AMAZON,
                        PLATFORM_LINUX_CENTOS,
                        PLATFORM_LINUX_FEDORA,
                        PLATFORM_LINUX_ROCKY,
                    )
                )
            ):
                # this platform doesn't automatically start/enable the daemon, so do so now
                err, out = self.run_process(['systemctl', 'start', 'docker'], privileged=True)
                if err == 0:
                    err, out = self.run_process(['systemctl', 'enable', 'docker'], privileged=True)
                    if err != 0:
                        logging.error(f"Enabling docker service failed: {out}")
                else:
                    logging.error(f"Starting docker service failed: {out}")

            # at this point we either have installed docker successfully or we have to give up, as we've tried all we could
            err, out = self.run_process([args.runtimeBin, 'info'], privileged=True, retry=6, retrySleepSec=5)
            if out and (err == 0):
                logging.info(f'"{args.runtimeBin} info" succeeded')

                if args.runtimeBin.startswith('docker'):
                    # add non-root user to docker group if required
                    usersToAdd = []
                    if self.scriptUser == 'root':
                        while InstallerYesOrNo(
                            f"Add {'a' if len(usersToAdd) == 0 else 'another'} non-root user to the \"docker\" group?"
                        ):
                            tmpUser = InstallerAskForString('Enter user account')
                            if len(tmpUser) > 0:
                                usersToAdd.append(tmpUser)
                    else:
                        usersToAdd.append(self.scriptUser)

                    for user in usersToAdd:
                        err, out = self.run_process(['usermod', '-a', '-G', 'docker', user], privileged=True)
                        if err == 0:
                            logging.info(f'Adding {user} to "docker" group succeeded')
                        else:
                            logging.error(f'Adding {user} to "docker" group failed')

            elif err != 0:
                result = False
                if args.runtimeBin.startswith('docker'):
                    raise Exception(
                        f'{ScriptName} requires {args.runtimeBin}, please see {DOCKER_INSTALL_URLS[self.distro]}'
                    )
                else:
                    raise Exception(
                        f"{ScriptName} requires {args.runtimeBin}, please consult your distribution's documentation"
                    )

        return result

    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    def install_docker_compose(self):
        result = False

        if self.orchMode is OrchestrationFramework.DOCKER_COMPOSE:
            # first see if docker compose/docker-compose is already installed and runnable
            #   (try non-root and root)
            tmpComposeCmd = (args.runtimeBin, 'compose')

            for priv in (False, True):
                err, out = self.run_process([tmpComposeCmd, 'version'], privileged=priv)
                if err == 0:
                    break
            if err != 0:
                tmpComposeCmd = f'{args.runtimeBin}-compose'
                if not which(tmpComposeCmd, debug=self.debug):
                    if os.path.isfile('/usr/libexec/docker/cli-plugins/docker-compose'):
                        tmpComposeCmd = '/usr/libexec/docker/cli-plugins/docker-compose'
                    elif os.path.isfile('/usr/local/bin/docker-compose'):
                        tmpComposeCmd = '/usr/local/bin/docker-compose'
                for priv in (False, True):
                    err, out = self.run_process([tmpComposeCmd, 'version'], privileged=priv)
                    if err == 0:
                        break

            if err == 0:
                self.dockerComposeCmd = tmpComposeCmd

            elif args.runtimeBin.startswith('docker') and InstallerYesOrNo(
                'docker compose failed, attempt to install docker compose?', default=True
            ):
                if InstallerYesOrNo('Install docker compose directly from docker github?', default=True):
                    # download docker-compose from github and put it in /usr/local/bin

                    # need to know some linux platform info
                    unames = []
                    err, out = self.run_process((['uname', '-s']))
                    if (err == 0) and (len(out) > 0):
                        unames.append(out[0].lower())
                    err, out = self.run_process((['uname', '-m']))
                    if (err == 0) and (len(out) > 0):
                        unames.append(out[0].lower())
                    if len(unames) == 2:
                        # download docker-compose from github and save it to a temporary file
                        tempFileName = os.path.join(self.tempDirName, tmpComposeCmd)
                        dockerComposeUrl = f"https://github.com/docker/compose/releases/download/v{DOCKER_COMPOSE_INSTALL_VERSION}/docker-compose-{unames[0]}-{unames[1]}"
                        if DownloadToFile(dockerComposeUrl, tempFileName, debug=self.debug):
                            os.chmod(tempFileName, 493)  # 493 = 0o755, mark as executable
                            # put docker-compose into /usr/local/bin
                            err, out = self.run_process(
                                (['cp', '-f', tempFileName, '/usr/local/bin/docker-compose']), privileged=True
                            )
                            if err == 0:
                                logging.info("Download and installation of docker-compose apparently succeeded")
                                tmpComposeCmd = '/usr/local/bin/docker-compose'
                            else:
                                raise Exception(f'Error copying {tempFileName} to /usr/local/bin: {out}')

                        else:
                            logging.error(f"Downloading {dockerComposeUrl} to {tempFileName} failed")

                elif InstallerYesOrNo('Install docker-compose via pip (privileged)?', default=False):
                    # install docker-compose via pip (as root)
                    err, out = self.run_process([self.pipCmd, 'install', 'docker-compose'], privileged=True)
                    if err == 0:
                        logging.info("Installation of docker-compose apparently succeeded")
                    else:
                        logging.error(f"Install docker-compose via pip failed with {err}, {out}")

                elif InstallerYesOrNo('Install docker-compose via pip (user)?', default=True):
                    # install docker-compose via pip (regular user)
                    err, out = self.run_process([self.pipCmd, 'install', 'docker-compose'], privileged=False)
                    if err == 0:
                        logging.info("Installation of docker-compose apparently succeeded")
                    else:
                        logging.error(f"Install docker-compose via pip failed with {err}, {out}")

            # see if docker-compose is now installed and runnable (try non-root and root)
            for priv in (False, True):
                err, out = self.run_process([tmpComposeCmd, 'version'], privileged=priv)
                if err == 0:
                    break

            if err == 0:
                self.dockerComposeCmd = tmpComposeCmd
                result = True
                logging.info(f'{args.runtimeBin} compose succeeded')

            else:
                if args.runtimeBin.startswith('docker'):
                    raise Exception(
                        f'{ScriptName} requires {args.runtimeBin} compose, please see {DOCKER_COMPOSE_INSTALL_URLS[self.platform]}'
                    )
                else:
                    raise Exception(
                        f"{ScriptName} requires {args.runtimeBin} compose, please consult your distribution's documentation"
                    )

        return result

    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    def tweak_system_files(self):
        # make some system configuration changes with permission

        tweakWithAbandon = InstallerYesOrNo(
            'Apply recommended system tweaks automatically without asking for confirmation?', default=True
        )

        ConfigLines = namedtuple("ConfigLines", ["distros", "filename", "prefix", "description", "lines"], rename=False)

        configLinesToAdd = [
            ConfigLines(
                [],
                '/etc/sysctl.d/99-sysctl-performance.conf' if os.path.isdir('/etc/sysctl.d') else '/etc/sysctl.conf',
                'fs.file-max=',
                'fs.file-max increases allowed maximum for file handles',
                ['# the maximum number of open file handles', 'fs.file-max=2097152'],
            ),
            ConfigLines(
                [],
                '/etc/sysctl.d/99-sysctl-performance.conf' if os.path.isdir('/etc/sysctl.d') else '/etc/sysctl.conf',
                'fs.inotify.max_user_watches=',
                'fs.inotify.max_user_watches increases allowed maximum for monitored files',
                ['# the maximum number of user inotify watches', 'fs.inotify.max_user_watches=131072'],
            ),
            ConfigLines(
                [],
                '/etc/sysctl.d/99-sysctl-performance.conf' if os.path.isdir('/etc/sysctl.d') else '/etc/sysctl.conf',
                'fs.inotify.max_queued_events=',
                'fs.inotify.max_queued_events increases queue size for monitored files',
                ['# the inotify event queue size', 'fs.inotify.max_queued_events=131072'],
            ),
            ConfigLines(
                [],
                '/etc/sysctl.d/99-sysctl-performance.conf' if os.path.isdir('/etc/sysctl.d') else '/etc/sysctl.conf',
                'fs.inotify.max_user_instances=',
                'fs.inotify.max_user_instances increases allowed maximum monitor file watchers',
                ['# the maximum number of user inotify monitors', 'fs.inotify.max_user_instances=512'],
            ),
            ConfigLines(
                [],
                '/etc/sysctl.d/99-sysctl-performance.conf' if os.path.isdir('/etc/sysctl.d') else '/etc/sysctl.conf',
                'vm.max_map_count=',
                'vm.max_map_count increases allowed maximum for memory segments',
                ['# the maximum number of memory map areas a process may have', 'vm.max_map_count=262144'],
            ),
            ConfigLines(
                [],
                '/etc/sysctl.d/99-sysctl-performance.conf' if os.path.isdir('/etc/sysctl.d') else '/etc/sysctl.conf',
                'net.core.somaxconn=',
                'net.core.somaxconn increases allowed maximum for socket connections',
                ['# the maximum number of incoming connections', 'net.core.somaxconn=65535'],
            ),
            ConfigLines(
                [],
                '/etc/sysctl.d/99-sysctl-performance.conf' if os.path.isdir('/etc/sysctl.d') else '/etc/sysctl.conf',
                'vm.swappiness=',
                'vm.swappiness adjusts the preference of the system to swap vs. drop runtime memory pages',
                ['# decrease "swappiness" (swapping out runtime memory vs. dropping pages)', 'vm.swappiness=1'],
            ),
            ConfigLines(
                [],
                '/etc/sysctl.d/99-sysctl-performance.conf' if os.path.isdir('/etc/sysctl.d') else '/etc/sysctl.conf',
                'vm.dirty_background_ratio=',
                'vm.dirty_background_ratio defines the percent of memory filled with dirty data before the system starts writing it to disk in the background',
                [
                    '# % of memory filled with dirty data before the system starts writing it to disk in the background',
                    'vm.dirty_background_ratio=40',
                ],
            ),
            ConfigLines(
                [],
                '/etc/sysctl.d/99-sysctl-performance.conf' if os.path.isdir('/etc/sysctl.d') else '/etc/sysctl.conf',
                'vm.dirty_ratio=',
                'vm.dirty_ratio defines the maximum percent of memory that can be dirty before all new writes are forced to flush to disk',
                [
                    '# maximum % of memory that can be dirty before all new writes are forced to flush to disk',
                    'vm.dirty_ratio=80',
                ],
            ),
            ConfigLines(
                [],
                '/etc/sysctl.d/99-sysctl-performance.conf' if os.path.isdir('/etc/sysctl.d') else '/etc/sysctl.conf',
                'net.ipv4.tcp_retries2=',
                'net.ipv4.tcp_retries2 defines the maximum number of TCP retransmissions',
                ['# maximum number of TCP retransmissions', 'net.ipv4.tcp_retries2=5'],
            ),
            ConfigLines(
                ['centos', 'core'],
                '/etc/systemd/system.conf.d/limits.conf',
                '',
                '/etc/systemd/system.conf.d/limits.conf increases the allowed maximums for file handles and memlocked segments',
                [
                    '[Manager]',
                    'DefaultLimitNOFILE=65535:65535',
                    'DefaultLimitMEMLOCK=infinity',
                ],
            ),
            ConfigLines(
                [
                    'bionic',
                    'trixie',
                    'bullseye',
                    'buster',
                    'cosmic',
                    'disco',
                    'eoan',
                    'focal',
                    'groovy',
                    'hirsute',
                    'impish',
                    'jammy',
                    'kinetic',
                    'lunar',
                    'mantic',
                    'noble',
                    'plucky',
                    'sid',
                    'stretch',
                    'trixie',
                    PLATFORM_LINUX_ALMA,
                    PLATFORM_LINUX_AMAZON,
                    PLATFORM_LINUX_FEDORA,
                    PLATFORM_LINUX_ROCKY,
                ],
                '/etc/security/limits.d/limits.conf',
                '',
                '/etc/security/limits.d/limits.conf increases the allowed maximums for file handles and memlocked segments',
                [
                    '* soft nofile 65535',
                    '* hard nofile 65535',
                    '* soft memlock unlimited',
                    '* hard memlock unlimited',
                    '* soft nproc 262144',
                    '* hard nproc 524288',
                ],
            ),
        ]

        for config in configLinesToAdd:
            if ((len(config.distros) == 0) or (self.codename in config.distros)) and (
                os.path.isfile(config.filename)
                or tweakWithAbandon
                or InstallerYesOrNo(
                    f'\n{config.description}\n{config.filename} does not exist, create it?', default=True
                )
            ):
                confFileLines = (
                    [line.rstrip('\n') for line in open(config.filename)] if os.path.isfile(config.filename) else []
                )

                if (
                    (len(confFileLines) == 0)
                    or (not os.path.isfile(config.filename) and (len(config.prefix) == 0))
                    or (
                        (len(list(filter(lambda x: x.startswith(config.prefix), confFileLines))) == 0)
                        and (
                            tweakWithAbandon
                            or InstallerYesOrNo(
                                f'\n{config.description}\n{config.prefix} appears to be missing from {config.filename}, append it?',
                                default=True,
                            )
                        )
                    )
                ):
                    echoNewLineJoin = '\\n'
                    err, out = self.run_process(
                        [
                            'bash',
                            '-c',
                            f"mkdir -p {os.path.dirname(config.filename)} && echo -n -e '{echoNewLineJoin}{echoNewLineJoin.join(config.lines)}{echoNewLineJoin}' >> '{config.filename}'",
                        ],
                        privileged=True,
                    )

        # tweak other kernel parameters

        # cgroup accounting in GRUB_CMDLINE_LINUX in /etc/default/grub
        if (
            (grubFileName := '/etc/default/grub')
            and os.path.isfile(grubFileName)
            and (not [line.rstrip('\n') for line in open(grubFileName) if 'cgroup' in line.lower()])
            and (
                tweakWithAbandon
                or InstallerYesOrNo(
                    f'\ncgroup parameters appear to be missing from {grubFileName}, set them?',
                    default=True,
                )
            )
        ):
            err, out = self.run_process(
                [
                    'bash',
                    '-c',
                    f'sed -i \'s/^GRUB_CMDLINE_LINUX="/&systemd.unified_cgroup_hierarchy=1 cgroup_enable=memory swapaccount=1 cgroup.memory=nokmem /\' {grubFileName}',
                ],
                privileged=True,
            )
            if err == 0:
                if which('update-grub', debug=self.debug):
                    err, out = self.run_process(['update-grub'], privileged=True)
                elif which('update-grub2', debug=self.debug):
                    err, out = self.run_process(['update-grub2'], privileged=True)
                elif which('grub2-mkconfig', debug=self.debug) and os.path.isfile('/boot/grub2/grub.cfg'):
                    err, out = self.run_process(['grub2-mkconfig', '-o', '/boot/grub2/grub.cfg'], privileged=True)
                else:
                    InstallerDisplayMessage(
                        f"{grubFileName} has been modified, consult your distribution's documentation generate new grub config file"
                    )


###################################################################################################
class MacInstaller(Installer):
    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    def __init__(self, orchMode, configOnly=False):
        super().__init__(orchMode, debug, configOnly)

        self.sudoCmd = []

        # first see if brew is already installed and runnable
        err, out = self.run_process(['brew', 'info'])
        brewInstalled = err == 0

        if brewInstalled and InstallerYesOrNo('Homebrew is installed: continue with Homebrew?', default=True):
            self.useBrew = True

        else:
            self.useBrew = False
            if (not brewInstalled) and (
                not InstallerYesOrNo('Homebrew is not installed: continue with manual installation?', default=False)
            ):
                raise Exception(
                    f'Follow the steps at {HOMEBREW_INSTALL_URLS[self.platform]} to install Homebrew, then re-run {ScriptName}'
                )

        if self.useBrew:
            # make sure we have brew cask
            err, out = self.run_process(['brew', 'info', 'cask'])
            if err != 0:
                self.install_package(['cask'])
                if err == 0:
                    logging.info('"brew install cask" succeeded')
                else:
                    logging.error(f'"brew install cask" failed with {err}, {out}')

            err, out = self.run_process(['brew', 'tap', 'homebrew/cask-versions'])
            if err == 0:
                logging.info('"brew tap homebrew/cask-versions" succeeded')
            else:
                logging.error(f'"brew tap homebrew/cask-versions" failed with {err}, {out}')

            self.checkPackageCmds.append(['brew', 'cask', 'ls', '--versions'])
            self.installPackageCmds.append(['brew', 'cask', 'install'])

        # determine total system memory
        try:
            totalMemBytes = os.sysconf('SC_PAGE_SIZE') * os.sysconf('SC_PHYS_PAGES')
            self.totalMemoryGigs = math.ceil(totalMemBytes / (1024.0**3))
        except Exception:
            self.totalMemoryGigs = 0.0

        # determine total system memory a different way if the first way didn't work
        if self.totalMemoryGigs <= 0.0:
            err, out = self.run_process(['sysctl', '-n', 'hw.memsize'])
            if (err == 0) and (len(out) > 0):
                totalMemBytes = int(out[0])
                self.totalMemoryGigs = math.ceil(totalMemBytes / (1024.0**3))

        # determine total system CPU cores
        try:
            self.totalCores = os.sysconf('SC_NPROCESSORS_ONLN')
        except Exception:
            self.totalCores = 0

        # determine total system CPU cores a different way if the first way didn't work
        if self.totalCores <= 0:
            err, out = self.run_process(['sysctl', '-n', 'hw.ncpu'])
            if (err == 0) and (len(out) > 0):
                self.totalCores = int(out[0])

    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    def install_docker(self):
        result = False

        if self.orchMode is OrchestrationFramework.DOCKER_COMPOSE:
            # first see if docker is already installed/runnable
            err, out = self.run_process([args.runtimeBin, 'info'])

            if (
                (err != 0)
                and self.useBrew
                and args.runtimeBin.startswith('docker')
                and self.package_is_installed(MAC_BREW_DOCKER_PACKAGE)
            ):
                # if docker is installed via brew, but not running, prompt them to start it
                logging.error(
                    f'{MAC_BREW_DOCKER_PACKAGE} appears to be installed via Homebrew, but "docker info" failed'
                )
                while True:
                    response = InstallerAskForString(
                        'Starting Docker the first time may require user interaction. Please find and start Docker in the Applications folder, then return here and type YES'
                    ).lower()
                    if response == 'yes':
                        break
                err, out = self.run_process(['docker', 'info'], retry=12, retrySleepSec=5)

            # did docker info work?
            if err == 0:
                result = True

            elif args.runtimeBin.startswith('docker') and InstallerYesOrNo(
                '"docker info" failed, attempt to install Docker?', default=True
            ):
                if self.useBrew:
                    # install docker via brew cask (requires user interaction)
                    dockerPackages = [MAC_BREW_DOCKER_PACKAGE, MAC_BREW_DOCKER_COMPOSE_PACKAGE]
                    logging.info(f"Installing docker packages: {dockerPackages}")
                    if self.install_package(dockerPackages):
                        logging.info("Installation of docker packages apparently succeeded")
                        while True:
                            response = InstallerAskForString(
                                'Starting Docker the first time may require user interaction. Please find and start Docker in the Applications folder, then return here and type YES'
                            ).lower()
                            if response == 'yes':
                                break
                    else:
                        logging.error("Installation of docker packages failed")

                else:
                    # install docker via downloaded dmg file (requires user interaction)
                    dlDirName = f'/Users/{self.scriptUser}/Downloads'
                    if os.path.isdir(dlDirName):
                        tempFileName = os.path.join(dlDirName, 'Docker.dmg')
                    else:
                        tempFileName = os.path.join(self.tempDirName, 'Docker.dmg')
                    if DownloadToFile(
                        'https://desktop.docker.com/mac/main/amd64/Docker.dmg', tempFileName, debug=self.debug
                    ):
                        while True:
                            response = InstallerAskForString(
                                f'Installing and starting Docker the first time may require user interaction. Please open Finder and install {tempFileName}, start Docker from the Applications folder, then return here and type YES'
                            ).lower()
                            if response == 'yes':
                                break

                # at this point we either have installed docker successfully or we have to give up, as we've tried all we could
                err, out = self.run_process([args.runtimeBin, 'info'], retry=12, retrySleepSec=5)
                if err == 0:
                    result = True
                    logging.info(f'"{args.runtimeBin} info" succeeded')

                elif err != 0:
                    raise Exception(
                        f'{ScriptName} requires {args.runtimeBin}, please see {DOCKER_INSTALL_URLS[self.platform]}'
                    )

            elif err != 0:
                if args.runtimeBin.startswith('docker'):
                    raise Exception(
                        f'{ScriptName} requires {args.runtimeBin}, please see {DOCKER_INSTALL_URLS[self.platform]}'
                    )
                else:
                    raise Exception(
                        f"{ScriptName} requires {args.runtimeBin}, please consult your platform's documentation"
                    )

            if args.runtimeBin.startswith('docker'):
                # tweak CPU/RAM usage for Docker in Mac
                settingsFile = MAC_BREW_DOCKER_SETTINGS.format(self.scriptUser)
                if (
                    result
                    and os.path.isfile(settingsFile)
                    and InstallerYesOrNo(f'Configure Docker resource usage in {settingsFile}?', default=True)
                ):
                    # adjust CPU and RAM based on system resources
                    if self.totalCores >= 16:
                        newCpus = 12
                    elif self.totalCores >= 12:
                        newCpus = 8
                    elif self.totalCores >= 8:
                        newCpus = 6
                    elif self.totalCores >= 4:
                        newCpus = 4
                    else:
                        newCpus = 2

                    if self.totalMemoryGigs >= 64.0:
                        newMemoryGiB = 32
                    elif self.totalMemoryGigs >= 32.0:
                        newMemoryGiB = 24
                    elif self.totalMemoryGigs >= 24.0:
                        newMemoryGiB = 16
                    elif self.totalMemoryGigs >= 16.0:
                        newMemoryGiB = 12
                    elif self.totalMemoryGigs >= 8.0:
                        newMemoryGiB = 8
                    elif self.totalMemoryGigs >= 4.0:
                        newMemoryGiB = 4
                    else:
                        newMemoryGiB = 2

                    while not InstallerYesOrNo(
                        f"Setting {newCpus if newCpus else '(unchanged)'} for CPU cores and {newMemoryGiB if newMemoryGiB else '(unchanged)'} GiB for RAM. Is this OK?",
                        default=True,
                    ):
                        newCpus = InstallerAskForString('Enter Docker CPU cores (e.g., 4, 8, 16)')
                        newMemoryGiB = InstallerAskForString('Enter Docker RAM MiB (e.g., 8, 16, etc.)')

                    if newCpus or newMemoryGiB:
                        with open(settingsFile, 'r+') as f:
                            data = json.load(f)
                            if newCpus:
                                data['cpus'] = int(newCpus)
                            if newMemoryGiB:
                                data['memoryMiB'] = int(newMemoryGiB) * 1024
                            f.seek(0)
                            json.dump(data, f, indent=2)
                            f.truncate()

                        # at this point we need to essentially update our system memory stats because we're running inside docker
                        # and don't have the whole banana at our disposal
                        self.totalMemoryGigs = newMemoryGiB

                        logging.info("Docker resource settings adjusted, attempting restart...")

                        err, out = self.run_process(['osascript', '-e', 'quit app "Docker"'])
                        if err == 0:
                            time.sleep(5)
                            err, out = self.run_process(['open', '-a', 'Docker'])

                        if err == 0:
                            err, out = self.run_process(['docker', 'info'], retry=12, retrySleepSec=5)
                            if err == 0:
                                logging.info('"docker info" succeeded')

                        else:
                            logging.error(f"Restarting Docker automatically failed: {out}")
                            while True:
                                response = InstallerAskForString(
                                    'Please restart Docker via the system taskbar, then return here and type YES'
                                ).lower()
                                if response == 'yes':
                                    break

        return result


###################################################################################################
# main
def main():
    global args
    global raw_args
    global requests_imported
    global kube_imported
    global yaml_imported
    global dotenv_imported

    # extract arguments from the command line
    # print (sys.argv[1:]);
    parser = argparse.ArgumentParser(
        description='Malcolm install script', add_help=True, usage=f'{ScriptName} <arguments>'
    )
    parser.add_argument(
        '--verbose',
        '-v',
        action='count',
        default=get_verbosity_env_var_count("VERBOSITY"),
        help='Increase verbosity (e.g., -v, -vv, etc.)',
    )
    parser.add_argument(
        '-d',
        '--defaults',
        dest='acceptDefaultsNonInteractive',
        type=str2bool,
        nargs='?',
        metavar="true|false",
        const=True,
        default=False,
        help="Accept defaults to prompts without user interaction",
    )
    parser.add_argument(
        '-c',
        '--configure',
        dest='configOnly',
        type=str2bool,
        metavar="true|false",
        nargs='?',
        const=True,
        default=False,
        help="Only do configuration (not installation)",
    )

    configDomainArgGroup = parser.add_argument_group('Configuration files')
    configDomainArgGroup.add_argument(
        '-f',
        '--configure-file',
        required=False,
        dest='configFile',
        metavar='<string>',
        type=str,
        default=os.getenv('MALCOLM_COMPOSE_FILE', ''),
        help='YAML file (docker-compose file to configure or kubeconfig file)',
    )
    configDomainArgGroup.add_argument(
        '-e',
        '--environment-dir',
        required=False,
        dest='configDir',
        metavar='<string>',
        type=str,
        default=os.getenv('MALCOLM_CONFIG_DIR', None),
        help="Directory containing Malcolm's .env files",
    )

    installFilesArgGroup = parser.add_argument_group('Installation files')
    installFilesArgGroup.add_argument(
        '-m',
        '--malcolm-file',
        required=False,
        dest='mfile',
        metavar='<string>',
        type=str,
        default='',
        help='Malcolm .tar.gz file for installation',
    )
    installFilesArgGroup.add_argument(
        '-i',
        '--image-file',
        required=False,
        dest='ifile',
        metavar='<string>',
        type=str,
        default='',
        help='Malcolm container images .tar.xz file for installation',
    )

    runtimeOptionsArgGroup = parser.add_argument_group('Runtime options')
    runtimeOptionsArgGroup.add_argument(
        '--runtime',
        required=False,
        dest='runtimeBin',
        metavar='<string>',
        type=str,
        default=os.getenv('MALCOLM_CONTAINER_RUNTIME', ''),
        help='Container runtime binary (e.g., docker, podman)',
    )
    runtimeOptionsArgGroup.add_argument(
        '--malcolm-profile',
        dest='malcolmProfile',
        type=str2bool,
        metavar="true|false",
        nargs='?',
        const=True,
        default=True,
        help="Run all Malcolm containers (true) vs. run capture-only containers (false)",
    )
    runtimeOptionsArgGroup.add_argument(
        '--dark-mode',
        dest='dashboardsDarkMode',
        type=str2bool,
        metavar="true|false",
        nargs='?',
        const=True,
        default=True,
        help="Enable dark mode for OpenSearch Dashboards",
    )
    runtimeOptionsArgGroup.add_argument(
        '--image-arch',
        dest='imageArch',
        required=False,
        metavar='<amd64|arm64>',
        type=str,
        default=None,
        help='Architecture for container image',
    )

    netOptionsArgGroup = parser.add_argument_group('Network connectivity options')
    netOptionsArgGroup.add_argument(
        '--https',
        dest='nginxSSL',
        type=str2bool,
        metavar="true|false",
        nargs='?',
        const=True,
        default=True,
        help="Require encrypted HTTPS connections",
    )
    netOptionsArgGroup.add_argument(
        '--nginx-resolver-ipv4',
        dest='nginxResolverIpv4',
        type=str2bool,
        metavar="true|false",
        nargs='?',
        const=True,
        default=True,
        help="Enable IPv4 for nginx resolver directive",
    )
    netOptionsArgGroup.add_argument(
        '--nginx-resolver-ipv6',
        dest='nginxResolverIpv6',
        type=str2bool,
        metavar="true|false",
        nargs='?',
        const=True,
        default=False,
        help="Enable IPv6 for nginx resolver directive",
    )

    dockerOptionsArgGroup = parser.add_argument_group('Container options')
    dockerOptionsArgGroup.add_argument(
        '-r',
        '--restart-malcolm',
        dest='malcolmAutoRestart',
        type=str2bool,
        metavar="true|false",
        nargs='?',
        const=True,
        default=False,
        help="Restart Malcolm on system restart (unless-stopped)",
    )
    dockerOptionsArgGroup.add_argument(
        '--reverse-proxied',
        dest='behindReverseProxy',
        type=str2bool,
        metavar="true|false",
        nargs='?',
        const=True,
        default=False,
        help="Malcolm will be running behind another reverse proxy (Traefik, Caddy, etc.)",
    )
    dockerOptionsArgGroup.add_argument(
        '--traefik-host',
        dest='traefikHost',
        required=False,
        metavar='<string>',
        type=str,
        default='',
        help='Request domain (host header value) for Malcolm interface Traefik router (e.g., malcolm.example.org)',
    )
    dockerOptionsArgGroup.add_argument(
        '--traefik-host-opensearch',
        dest='traefikOpenSearchHost',
        required=False,
        metavar='<string>',
        type=str,
        default='',
        help='Request domain (host header value) for OpenSearch Traefik router (e.g., opensearch.malcolm.example.org)',
    )
    dockerOptionsArgGroup.add_argument(
        '--traefik-entrypoint',
        dest='traefikEntrypoint',
        required=False,
        metavar='<string>',
        type=str,
        default='websecure',
        help='Traefik router entrypoint (e.g., websecure)',
    )
    dockerOptionsArgGroup.add_argument(
        '--traefik-resolver',
        dest='traefikResolver',
        required=False,
        metavar='<string>',
        type=str,
        default='myresolver',
        help='Traefik router resolver (e.g., myresolver)',
    )
    dockerOptionsArgGroup.add_argument(
        '--network-name',
        dest='containerNetworkName',
        required=False,
        metavar='<string>',
        type=str,
        default='',
        help='External container network name (or leave blank for default networking)',
    )

    opensearchArgGroup = parser.add_argument_group('OpenSearch options')
    opensearchArgGroup.add_argument(
        '--opensearch',
        dest='opensearchPrimaryMode',
        required=False,
        metavar='<string>',
        type=str,
        default=DATABASE_MODE_LABELS[DatabaseMode.OpenSearchLocal],
        help=f'Primary OpenSearch mode ({", ".join(list(DATABASE_MODE_ENUMS.keys()))})',
    )
    opensearchArgGroup.add_argument(
        '--opensearch-memory',
        dest='osMemory',
        required=False,
        metavar='<string>',
        type=str,
        default=None,
        help='Memory for OpenSearch (e.g., 16g, 9500m, etc.)',
    )
    opensearchArgGroup.add_argument(
        '--opensearch-url',
        dest='opensearchPrimaryUrl',
        required=False,
        metavar='<string>',
        type=str,
        default='',
        help='Primary remote OpenSearch connection URL',
    )
    opensearchArgGroup.add_argument(
        '--opensearch-ssl-verify',
        dest='opensearchPrimarySslVerify',
        type=str2bool,
        metavar="true|false",
        nargs='?',
        const=True,
        default=False,
        help="Require SSL certificate validation for communication with primary OpenSearch instance",
    )
    opensearchArgGroup.add_argument(
        '--opensearch-secondary',
        dest='opensearchSecondaryMode',
        required=False,
        metavar='<string>',
        type=str,
        default='',
        help=f'Secondary OpenSearch mode to forward Logstash logs to a remote OpenSearch instance',
    )
    opensearchArgGroup.add_argument(
        '--opensearch-secondary-url',
        dest='opensearchSecondaryUrl',
        required=False,
        metavar='<string>',
        type=str,
        default='',
        help='Secondary remote OpenSearch connection URL',
    )
    opensearchArgGroup.add_argument(
        '--opensearch-secondary-ssl-verify',
        dest='opensearchSecondarySslVerify',
        type=str2bool,
        metavar="true|false",
        nargs='?',
        const=True,
        default=False,
        help="Require SSL certificate validation for communication with secondary OpenSearch instance",
    )
    opensearchArgGroup.add_argument(
        '--dashboards-url',
        dest='dashboardsUrl',
        required=False,
        metavar='<string>',
        type=str,
        default='',
        help='Remote OpenSearch Dashboards connection URL',
    )

    logstashArgGroup = parser.add_argument_group('Logstash options')
    logstashArgGroup.add_argument(
        '--logstash-memory',
        dest='lsMemory',
        required=False,
        metavar='<string>',
        type=str,
        default=None,
        help='Memory for Logstash (e.g., 3g, 4500m, etc.)',
    )
    logstashArgGroup.add_argument(
        '--logstash-workers',
        dest='lsWorkers',
        required=False,
        metavar='<integer>',
        type=int,
        default=0,
        help='Number of Logstash workers (e.g., 4, 8, etc.)',
    )
    opensearchArgGroup.add_argument(
        '--logstash-host',
        dest='logstashHost',
        required=False,
        metavar='<string>',
        type=str,
        default='',
        help='Logstash host and port (for when running "capture-only" profile; e.g., 192.168.1.123:5044)',
    )

    openPortsArgGroup = parser.add_argument_group('Expose ports')
    openPortsArgGroup.add_argument(
        '--logstash-expose',
        dest='exposeLogstash',
        type=str2bool,
        metavar="true|false",
        nargs='?',
        const=True,
        default=False,
        help="Expose Logstash port to external hosts",
    )
    openPortsArgGroup.add_argument(
        '--opensearch-expose',
        dest='exposeOpenSearch',
        type=str2bool,
        metavar="true|false",
        nargs='?',
        const=True,
        default=False,
        help="Expose OpenSearch port to external hosts",
    )
    openPortsArgGroup.add_argument(
        '--filebeat-tcp-expose',
        dest='exposeFilebeatTcp',
        type=str2bool,
        metavar="true|false",
        nargs='?',
        const=True,
        default=False,
        help="Expose Filebeat TCP port to external hosts",
    )
    openPortsArgGroup.add_argument(
        '--sftp-expose',
        dest='exposeSFTP',
        type=str2bool,
        metavar="true|false",
        nargs='?',
        const=True,
        default=False,
        help="Expose SFTP server (for PCAP upload) to external hosts",
    )
    openPortsArgGroup.add_argument(
        '--syslog-tcp-port',
        dest='syslogTcpPort',
        required=False,
        metavar='<integer>',
        type=int,
        default=0,
        help='Listen for Syslog (TCP) on this port',
    )
    openPortsArgGroup.add_argument(
        '--syslog-udp-port',
        dest='syslogUdpPort',
        required=False,
        metavar='<integer>',
        type=int,
        default=0,
        help='Listen for Syslog (UDP) on this port',
    )

    storageArgGroup = parser.add_argument_group('Storage options')
    storageArgGroup.add_argument(
        '--pcap-path',
        dest='pcapDir',
        required=False,
        metavar='<string>',
        type=str,
        default='',
        help='PCAP storage directory',
    )
    storageArgGroup.add_argument(
        '--zeek-path',
        dest='zeekLogDir',
        required=False,
        metavar='<string>',
        type=str,
        default='',
        help='Zeek log storage directory',
    )
    storageArgGroup.add_argument(
        '--suricata-path',
        dest='suricataLogDir',
        required=False,
        metavar='<string>',
        type=str,
        default='',
        help='Suricata log storage directory',
    )
    storageArgGroup.add_argument(
        '--opensearch-path',
        dest='indexDir',
        required=False,
        metavar='<string>',
        type=str,
        default='',
        help='OpenSearch index directory',
    )
    storageArgGroup.add_argument(
        '--opensearch-snapshot-path',
        dest='indexSnapshotDir',
        required=False,
        metavar='<string>',
        type=str,
        default='',
        help='OpenSearch snapshot directory',
    )
    storageArgGroup.add_argument(
        '--delete-old-pcap',
        dest='arkimeManagePCAP',
        type=str2bool,
        metavar="true|false",
        nargs='?',
        const=True,
        default=False,
        help="Arkime should delete PCAP files based on available storage (see https://arkime.com/faq#pcap-deletion)",
    )
    storageArgGroup.add_argument(
        '--delete-pcap-threshold',
        dest='arkimeFreeSpaceG',
        required=False,
        metavar='<string>',
        type=str,
        default='',
        help=f'Threshold for Arkime PCAP deletion (see https://arkime.com/faq#pcap-deletion)',
    )
    storageArgGroup.add_argument(
        '--extracted-file-max-size-threshold',
        dest='extractedFileMaxSizeThreshold',
        required=False,
        metavar='<string>',
        type=str,
        default='',
        help=f'Delete zeek-extracted files when they consume this much disk space (e.g., 250GB, 1TB, etc.)',
    )
    storageArgGroup.add_argument(
        '--extracted-file-total-disk-usage-percent-threshold',
        dest='extractedFileMaxPercentThreshold',
        required=False,
        metavar='<string>',
        type=str2percent,
        default=0,
        help=f'Delete zeek-extracted files when the file system exceeds this percentage full (e.g., 90٪, etc.)',
    )
    storageArgGroup.add_argument(
        '--delete-index-threshold',
        dest='indexPruneSizeLimit',
        required=False,
        metavar='<string>',
        type=str,
        default='',
        help=f'Delete the oldest indices when the database exceeds this threshold (e.g., 250GB, 1TB, 60٪, etc.)',
    )
    storageArgGroup.add_argument(
        '--index-management-enable',
        dest='indexManagementPolicy',
        type=str2bool,
        metavar="true|false",
        nargs='?',
        const=True,
        default=False,
        help="Enable index management policies (ILM/ISM) in Arkime? (see https://https://arkime.com/faq#ilm)",
    )
    storageArgGroup.add_argument(
        '--index-management-hot-warm-enable',
        dest='indexManagementHotWarm',
        type=str2bool,
        metavar="true|false",
        nargs='?',
        const=True,
        default=False,
        help="Should Arkime use a hot/warm design in which non-session data is stored in a warm index?",
    )
    storageArgGroup.add_argument(
        '--index-management-optimization-time-period',
        dest='indexManagementOptimizationTimePeriod',
        required=False,
        metavar='<string>',
        type=str,
        default='30d',
        help=f'Time in hours/days before (moving Arkime indexes to warm) and force merge (number followed by h or d), default 30d',
    )
    storageArgGroup.add_argument(
        '--index-management-spi-data-retention',
        dest='indexManagementSpiDataRetention',
        required=False,
        metavar='<string>',
        type=str,
        default='90d',
        help=f'Time in hours/days before deleting Arkime indexes (number followed by h or d), default 90d',
    )
    storageArgGroup.add_argument(
        '--index-management-replicas',
        dest='indexManagementReplicas',
        required=False,
        metavar='<integer>',
        type=int,
        default=0,
        help='Number of replicas for older sessions indices in the ILM/ISM policy, default 0',
    )
    storageArgGroup.add_argument(
        '--index-management-weeks-of-history',
        dest='indexManagementHistoryInWeeks',
        required=False,
        metavar='<integer>',
        type=int,
        default=13,
        help='Number of weeks of history to keep, default 13',
    )
    storageArgGroup.add_argument(
        '--index-management-segments',
        dest='indexManagementOptimizeSessionSegments',
        required=False,
        metavar='<integer>',
        type=int,
        default=1,
        help='Number of segments to optimize sessions to in the ILM/ISM policy, default 1',
    )

    analysisArgGroup = parser.add_argument_group('Analysis options')
    analysisArgGroup.add_argument(
        '--auto-arkime',
        dest='autoArkime',
        type=str2bool,
        metavar="true|false",
        nargs='?',
        const=True,
        default=True,
        help="Automatically analyze all PCAP files with Arkime",
    )
    analysisArgGroup.add_argument(
        '--auto-suricata',
        dest='autoSuricata',
        type=str2bool,
        metavar="true|false",
        nargs='?',
        const=True,
        default=True,
        help="Automatically analyze all PCAP files with Suricata",
    )
    analysisArgGroup.add_argument(
        '--suricata-rule-update',
        dest='suricataRuleUpdate',
        type=str2bool,
        metavar="true|false",
        nargs='?',
        const=True,
        default=False,
        help="Automatically analyze all PCAP files with Suricata",
    )
    analysisArgGroup.add_argument(
        '--auto-zeek',
        dest='autoZeek',
        type=str2bool,
        metavar="true|false",
        nargs='?',
        const=True,
        default=True,
        help="Automatically analyze all PCAP files with Zeek",
    )
    analysisArgGroup.add_argument(
        '--zeek-ics',
        dest='malcolmIcs',
        type=str2bool,
        metavar="true|false",
        nargs='?',
        const=True,
        default=False,
        help="Malcolm is being used to monitor an Industrial Control Systems (ICS) or Operational Technology (OT) network",
    )
    analysisArgGroup.add_argument(
        '--zeek-ics-best-guess',
        dest='zeekICSBestGuess',
        type=str2bool,
        metavar="true|false",
        nargs='?',
        const=True,
        default=False,
        help='Use "best guess" to identify potential OT/ICS traffic with Zeek',
    )
    analysisArgGroup.add_argument(
        '--reverse-dns',
        dest='reverseDns',
        type=str2bool,
        metavar="true|false",
        nargs='?',
        const=True,
        default=False,
        help='Perform reverse DNS lookup locally for source and destination IP addresses in logs',
    )
    analysisArgGroup.add_argument(
        '--auto-oui',
        dest='autoOui',
        type=str2bool,
        metavar="true|false",
        nargs='?',
        const=True,
        default=True,
        help='Perform hardware vendor OUI lookups for MAC addresses',
    )
    analysisArgGroup.add_argument(
        '--auto-freq',
        dest='autoFreq',
        type=str2bool,
        metavar="true|false",
        nargs='?',
        const=True,
        default=True,
        help='Perform string randomness scoring on some fields',
    )

    zeekIntelGroup = parser.add_argument_group('Threat intelligence feed options')
    zeekIntelGroup.add_argument(
        '--zeek-intel-on-startup',
        dest='zeekIntelOnStartup',
        type=str2bool,
        metavar="true|false",
        nargs='?',
        const=True,
        default=True,
        help='Pull from threat intelligence feeds on container startup',
    )
    zeekIntelGroup.add_argument(
        '--zeek-intel-feed-since',
        dest='zeekIntelFeedSince',
        required=False,
        metavar='<string>',
        type=str,
        default='7 days ago',
        help=f"When pulling from threat intelligence feeds, only process indicators created or modified since the time represented by this value; either a fixed date (01/01/2021) or relative interval (7 days ago)",
    )
    zeekIntelGroup.add_argument(
        '--zeek-intel-cron-expression',
        dest='zeekIntelCronExpression',
        required=False,
        metavar='<string>',
        type=str,
        default='0 0 * * *',
        help=f'Cron expression for scheduled pulls from threat intelligence feeds',
    )
    zeekIntelGroup.add_argument(
        '--zeek-intel-item-expiration',
        dest='zeekIntelItemExipration',
        required=False,
        metavar='<string>',
        type=str,
        default='-1min',
        help=f"Specifies the value for Zeek's Intel::item_expiration timeout (-1min to disable)",
    )

    fileCarveArgGroup = parser.add_argument_group('File extraction options')
    fileCarveArgGroup.add_argument(
        '--file-extraction',
        dest='fileCarveMode',
        required=False,
        metavar='<none|known|mapped|all|interesting|notcommtxt>',
        type=str,
        default='none',
        help='Zeek file extraction behavior',
    )
    fileCarveArgGroup.add_argument(
        '--file-preservation',
        dest='filePreserveMode',
        required=False,
        metavar='<none|quarantined|all>',
        type=str,
        default='none',
        help='Zeek file preservation behavior',
    )
    fileCarveArgGroup.add_argument(
        '--extracted-file-server',
        dest='fileCarveHttpServer',
        type=str2bool,
        metavar="true|false",
        nargs='?',
        const=True,
        default=False,
        help='Expose web interface for downloading preserved files',
    )
    fileCarveArgGroup.add_argument(
        '--extracted-file-server-zip',
        dest='fileCarveHttpServerZip',
        type=str2bool,
        metavar="true|false",
        nargs='?',
        const=True,
        default=False,
        help='ZIP downloaded preserved files',
    )
    fileCarveArgGroup.add_argument(
        '--extracted-file-server-password',
        dest='fileCarveHttpServeEncryptKey',
        required=False,
        metavar='<string>',
        type=str,
        default='',
        help='ZIP archive or AES-256-CBC encryption password for downloaded preserved files (blank for unencrypted)',
    )
    fileCarveArgGroup.add_argument(
        '--extracted-file-clamav',
        dest='clamAvScan',
        type=str2bool,
        metavar="true|false",
        nargs='?',
        const=True,
        default=True,
        help='Scan extracted files with ClamAV',
    )
    fileCarveArgGroup.add_argument(
        '--extracted-file-yara',
        dest='yaraScan',
        type=str2bool,
        metavar="true|false",
        nargs='?',
        const=True,
        default=True,
        help='Scan extracted files with Yara',
    )
    fileCarveArgGroup.add_argument(
        '--extracted-file-capa',
        dest='capaScan',
        type=str2bool,
        metavar="true|false",
        nargs='?',
        const=True,
        default=True,
        help='Scan extracted files with Capa',
    )
    fileCarveArgGroup.add_argument(
        '--virustotal-api-key',
        dest='vtotApiKey',
        required=False,
        metavar='<string>',
        type=str,
        default='',
        help='VirusTotal API key to scan extracted files with VirusTotal',
    )
    fileCarveArgGroup.add_argument(
        '--file-scan-rule-update',
        dest='fileScanRuleUpdate',
        type=str2bool,
        metavar="true|false",
        nargs='?',
        const=True,
        default=False,
        help="Download updated file scanner signatures periodically",
    )

    netboxArgGroup = parser.add_argument_group('NetBox options')
    netboxArgGroup.add_argument(
        '--netbox',
        dest='netboxMode',
        required=False,
        metavar='<string>',
        type=str,
        default='disabled',
        help='NetBox mode (disabled, local, remote)',
    )
    netboxArgGroup.add_argument(
        '--netbox-url',
        dest='netboxUrl',
        required=False,
        metavar='<string>',
        type=str,
        default='',
        help='NetBox URL (used only if NetBox mode is \"remote\")',
    )
    netboxArgGroup.add_argument(
        '--netbox-enrich',
        dest='netboxLogstashEnrich',
        type=str2bool,
        metavar="true|false",
        nargs='?',
        const=True,
        default=True,
        help="Enrich network traffic using NetBox",
    )
    netboxArgGroup.add_argument(
        '--netbox-autopopulate',
        dest='netboxAutoPopulate',
        type=str2bool,
        metavar="true|false",
        nargs='?',
        const=True,
        default=False,
        help="Automatically populate NetBox inventory based on observed network traffic",
    )
    netboxArgGroup.add_argument(
        '--netbox-autopopulate-filter',
        dest='netboxAutopopFilter',
        required=False,
        metavar='<string>',
        type=str,
        default='',
        help='NetBox IP autopopulation filter',
    )
    netboxArgGroup.add_argument(
        '--netbox-auto-prefixes',
        dest='netboxLogstashAutoSubnets',
        type=str2bool,
        metavar="true|false",
        nargs='?',
        const=True,
        default=False,
        help="Automatically create missing NetBox subnet prefixes based on observed network traffic",
    )
    netboxArgGroup.add_argument(
        '--netbox-site-name',
        dest='netboxSiteName',
        required=False,
        metavar='<string>',
        type=str,
        default='',
        help='Default NetBox site name',
    )

    captureArgGroup = parser.add_argument_group('Live traffic capture options')
    captureArgGroup.add_argument(
        '--live-capture-iface',
        dest='pcapIface',
        required=False,
        metavar='<string>',
        type=str,
        default='',
        help='Capture interface(s) (comma-separated)',
    )
    captureArgGroup.add_argument(
        '--live-capture-filter',
        dest='pcapFilter',
        required=False,
        metavar='<string>',
        type=str,
        default='',
        help='Capture filter (tcpdump-like filter expression; leave blank to capture all traffic)',
    )
    captureArgGroup.add_argument(
        '--live-capture-iface-tweak',
        dest='tweakIface',
        type=str2bool,
        metavar="true|false",
        nargs='?',
        const=True,
        default=True,
        help="Disable capture interface hardware offloading and adjust ring buffer sizes",
    )
    captureArgGroup.add_argument(
        '--live-capture-stats',
        dest='captureStats',
        type=str2bool,
        metavar="true|false",
        nargs='?',
        const=True,
        default=False,
        help=f"Enable live packet capture statistics for Zeek and/or Suricata",
    )
    captureArgGroup.add_argument(
        '--live-capture-arkime',
        dest='liveArkime',
        type=str2bool,
        metavar="true|false",
        nargs='?',
        const=True,
        default=False,
        help=f"Capture live network traffic with Arkime capture (not available with --opensearch {DATABASE_MODE_LABELS[DatabaseMode.OpenSearchLocal]})",
    )
    captureArgGroup.add_argument(
        '--live-capture-arkime-node-host',
        dest='liveArkimeNodeHost',
        required=False,
        metavar='<string>',
        type=str,
        default='',
        help='The node hostname or IP address to associate with live network traffic observed by Arkime capture',
    )
    captureArgGroup.add_argument(
        '--live-capture-netsniff',
        dest='pcapNetSniff',
        type=str2bool,
        metavar="true|false",
        nargs='?',
        const=True,
        default=False,
        help="Capture live network traffic with netsniff-ng for Arkime",
    )
    captureArgGroup.add_argument(
        '--live-capture-tcpdump',
        dest='pcapTcpDump',
        type=str2bool,
        metavar="true|false",
        nargs='?',
        const=True,
        default=False,
        help="Capture live network traffic with tcpdump for Arkime",
    )
    captureArgGroup.add_argument(
        '--live-capture-zeek',
        dest='liveZeek',
        type=str2bool,
        metavar="true|false",
        nargs='?',
        const=True,
        default=False,
        help="Capture live network traffic with Zeek",
    )
    captureArgGroup.add_argument(
        '--live-capture-suricata',
        dest='liveSuricata',
        type=str2bool,
        metavar="true|false",
        nargs='?',
        const=True,
        default=False,
        help="Capture live network traffic with Suricata",
    )
    captureArgGroup.add_argument(
        '--node-name',
        dest='pcapNodeName',
        required=False,
        metavar='<string>',
        type=str,
        default=os.getenv('HOSTNAME', os.getenv('COMPUTERNAME', platform.node())).split('.')[0],
        help='The node name to associate with network traffic metadata',
    )

    extrasArgGroup = parser.add_argument_group('Additional configuration options')
    extrasArgGroup.add_argument(
        '--extra',
        dest='extraSettings',
        nargs='*',
        type=str,
        default=[],
        help="Extra environment variables to set (e.g., foobar.env:VARIABLE_NAME=value)",
    )

    try:
        raw_args = sys.argv[1:]
    except Exception:
        pass
    try:
        args = parser.parse_args()
    except SystemExit as e:
        if e.code == 2:
            parser.print_help()
        sys.exit(e.code)

    if os.path.islink(os.path.join(ScriptPath, ScriptName)) and ScriptName.startswith('configure'):
        args.configOnly = True

    args.verbose = set_logging(
        os.getenv("LOGLEVEL", ""),
        args.verbose,
        set_traceback_limit=True,
        logfmt='%(message)s',
    )
    logging.debug(os.path.join(ScriptPath, ScriptName))
    logging.debug(f"Arguments: {sys.argv[1:]}")
    logging.debug(f"Arguments: {args}")

    if args.imageArch is not None:
        args.imageArch = (
            '' if (args.imageArch.lower() == 'amd64') else ('-' + remove_suffix(args.imageArch.lower(), '-'))
        )
    else:
        args.imageArch = ''
        if rawPlatform := platform.machine().lower():
            if (rawPlatform == 'aarch64') or (rawPlatform == 'arm64'):
                args.imageArch = '-arm64'

    orchMode = OrchestrationFramework.UNKNOWN
    if args.configFile and os.path.isfile(args.configFile):
        if not (
            (orchMode := DetermineYamlFileFormat(args.configFile)) and (orchMode in OrchestrationFrameworksSupported)
        ):
            raise Exception(f'{args.configFile} must be a docker-compose or kubeconfig YAML file')
    else:
        orchMode = OrchestrationFramework.DOCKER_COMPOSE

    installPath = None

    installerPlatform = platform.system()
    if installerPlatform == PLATFORM_LINUX:
        installer = LinuxInstaller(orchMode, configOnly=args.configOnly)
    elif installerPlatform == PLATFORM_MAC:
        installer = MacInstaller(orchMode, configOnly=args.configOnly)
    elif installerPlatform == PLATFORM_WINDOWS:
        raise Exception(f'{ScriptName} is not yet supported on {installerPlatform}')
        # installer = WindowsInstaller(orchMode, configOnly=args.configOnly)

    if orchMode == OrchestrationFramework.DOCKER_COMPOSE:
        if GetPlatformOSRelease() == 'hedgehog-malcolm':
            args.runtimeBin = 'docker'
        else:
            runtimeOptions = ('docker', 'podman')
            loopBreaker = CountUntilException(MaxAskForValueCount)
            while (args.runtimeBin not in runtimeOptions) and loopBreaker.increment():
                args.runtimeBin = InstallerChooseOne(
                    'Select container runtime engine',
                    choices=[(x, '', x == runtimeOptions[0]) for x in runtimeOptions],
                )
        logging.info(f"Container engine: {args.runtimeBin}")

    if (not args.configOnly) and hasattr(installer, 'install_required_packages'):
        installer.install_required_packages()

    DialogInit()
    for pkgLoop in (1, 2):
        requests_imported = RequestsDynamic(
            debug=log_level_is_debug(args.verbose), forceInteraction=(not args.acceptDefaultsNonInteractive)
        )
        yaml_imported = YAMLDynamic(
            debug=log_level_is_debug(args.verbose), forceInteraction=(not args.acceptDefaultsNonInteractive)
        )
        dotenv_imported = DotEnvDynamic(
            debug=log_level_is_debug(args.verbose), forceInteraction=(not args.acceptDefaultsNonInteractive)
        )
        logging.info(f"Imported requests: {requests_imported}")
        logging.info(f"Imported yaml: {yaml_imported}")
        logging.info(f"Imported dotenv: {dotenv_imported}")
        if (not all((requests_imported, yaml_imported, dotenv_imported))) and (
            (pkgLoop != 1) or (not installer.ensure_pip(prompt_to_bootstrap=not args.acceptDefaultsNonInteractive))
        ):
            exit(2)

    # If Malcolm and images tarballs are provided, we will use them.
    # If they are not provided, look in the pwd first, then in the script directory, to see if we
    # can locate the most recent tarballs
    malcolmFile = None
    imageFile = None

    if args.mfile and os.path.isfile(args.mfile):
        malcolmFile = args.mfile
    else:
        # find the most recent non-image tarball, first checking in the pwd then in the script path
        files = list(filter(lambda x: "_images" not in x, glob.glob(os.path.join(origPath, '*.tar.gz'))))
        if len(files) == 0:
            files = list(filter(lambda x: "_images" not in x, glob.glob(os.path.join(ScriptPath, '*.tar.gz'))))
        files.sort(key=lambda x: os.path.getmtime(x), reverse=True)
        if len(files) > 0:
            malcolmFile = files[0]

    if args.ifile and os.path.isfile(args.ifile):
        imageFile = args.ifile

    if (malcolmFile and os.path.isfile(malcolmFile)) and (not imageFile or not os.path.isfile(imageFile)):
        # if we've figured out the malcolm tarball, the _images tarball should match it
        imageFile = malcolmFile.replace('.tar.gz', '_images.tar.xz')
        if not os.path.isfile(imageFile):
            imageFile = None

    if args.configOnly:
        logging.info("Only doing configuration, not installation")
    else:
        logging.info(f"Malcolm install file: {malcolmFile}")
        logging.info(f"Malcolm images file: {imageFile}")

    if not args.configOnly:
        if orchMode is OrchestrationFramework.DOCKER_COMPOSE:
            if hasattr(installer, 'install_docker'):
                installer.install_docker()
            if hasattr(installer, 'install_docker_compose'):
                installer.install_docker_compose()
            if hasattr(installer, 'tweak_system_files'):
                installer.tweak_system_files()
        if hasattr(installer, 'install_malcolm_files'):
            _, installPath = installer.install_malcolm_files(malcolmFile, args.configDir is None)

    # if .env directory is unspecified, use the default ./config directory
    if args.configDir is None:
        args.configDir = os.path.join(GetMalcolmPath(), 'config')
    try:
        os.makedirs(args.configDir)
    except OSError as exc:
        if (exc.errno == errno.EEXIST) and os.path.isdir(args.configDir):
            pass
        else:
            logging.error(f"Creating {args.configDir} failed: {exc}, attempting to continue anyway")
    except Exception as e:
        logging.error(f"Creating {args.configDir} failed: {e}, attempting to continue anyway")

    if orchMode is OrchestrationFramework.KUBERNETES:
        kube_imported = KubernetesDynamic(debug=log_level_is_debug(args.verbose))
        logging.info(f"Imported kubernetes: {kube_imported}")
        if kube_imported:
            kube_imported.config.load_kube_config(args.configFile)
        else:
            raise Exception(
                f'{ScriptName} requires the official Python client library for kubernetes for {orchMode} mode'
            )

    if ((not installPath) or (not os.path.isdir(installPath))) and (
        args.configOnly
        or (args.configFile and os.path.isfile(args.configFile))
        or (args.configDir and os.path.isdir(args.configDir))
    ):
        if args.configFile and os.path.isfile(args.configFile):
            installPath = os.path.dirname(os.path.realpath(args.configFile))

        elif args.configDir and os.path.isfile(args.configDir):
            installPath = os.path.dirname(os.path.realpath(args.configDir))

        else:
            for testPath in [origPath, ScriptPath, os.path.realpath(os.path.join(ScriptPath, ".."))]:
                if os.path.isfile(os.path.join(testPath, "docker-compose.yml")) or os.path.isdir(
                    os.path.join(testPath, "config")
                ):
                    installPath = testPath
                    break

        logging.info(f"Malcolm installation detected at {installPath}")

    if (installPath is not None) and os.path.isdir(installPath):
        if hasattr(installer, 'tweak_malcolm_runtime'):
            installer.tweak_malcolm_runtime(installPath)

        if (
            (not args.configOnly)
            and (orchMode is OrchestrationFramework.DOCKER_COMPOSE)
            and hasattr(installer, 'install_docker_images')
        ):
            installer.install_docker_images(imageFile, installPath)

        InstallerDisplayMessage(
            f"Malcolm has been installed to {installPath}. See README.md for more information.\nScripts for starting and stopping Malcolm and changing authentication-related settings can be found in {os.path.join(installPath, 'scripts')}."
        )


if __name__ == '__main__':
    main()
