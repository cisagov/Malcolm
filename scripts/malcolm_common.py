#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2023 Battelle Energy Alliance, LLC.  All rights reserved.

import getpass
import importlib
import json
import os
import platform
import re
import string
import sys

import malcolm_utils
from malcolm_utils import (
    deep_get,
    eprint,
    EscapeAnsi,
    LoadStrIfJson,
    remove_suffix,
    run_process,
    str2bool,
)

from collections import defaultdict, namedtuple
from enum import Flag, IntFlag, auto

try:
    from pwd import getpwuid
except ImportError:
    getpwuid = None

try:
    from dialog import Dialog

    MainDialog = Dialog(dialog='dialog', autowidgetsize=True)
except ImportError:
    Dialog = None
    MainDialog = None

try:
    from colorama import init as ColoramaInit, Fore, Back, Style

    ColoramaInit()
    coloramaImported = True
except Exception:
    coloramaImported = False

###################################################################################################
ScriptPath = os.path.dirname(os.path.realpath(__file__))
MalcolmPath = os.path.abspath(os.path.join(ScriptPath, os.pardir))
MalcolmTmpPath = os.path.join(MalcolmPath, '.tmp')
MalcolmCfgRunOnceFile = os.path.join(MalcolmPath, '.configured')

###################################################################################################
PLATFORM_WINDOWS = "Windows"
PLATFORM_MAC = "Darwin"
PLATFORM_LINUX = "Linux"
PLATFORM_LINUX_CENTOS = 'centos'
PLATFORM_LINUX_DEBIAN = 'debian'
PLATFORM_LINUX_FEDORA = 'fedora'
PLATFORM_LINUX_UBUNTU = 'ubuntu'


class UserInputDefaultsBehavior(IntFlag):
    DefaultsPrompt = auto()
    DefaultsAccept = auto()
    DefaultsNonInteractive = auto()


class UserInterfaceMode(IntFlag):
    InteractionDialog = auto()
    InteractionInput = auto()


BoundPath = namedtuple(
    "BoundPath",
    ["service", "container_dir", "files", "relative_dirs", "clean_empty_dirs"],
    rename=False,
)

# URLS for figuring things out if something goes wrong
DOCKER_INSTALL_URLS = defaultdict(lambda: 'https://docs.docker.com/install/')
DOCKER_INSTALL_URLS[PLATFORM_WINDOWS] = [
    'https://stefanscherer.github.io/how-to-install-docker-the-chocolatey-way/',
    'https://docs.docker.com/docker-for-windows/install/',
]
DOCKER_INSTALL_URLS[PLATFORM_LINUX_UBUNTU] = 'https://docs.docker.com/install/linux/docker-ce/ubuntu/'
DOCKER_INSTALL_URLS[PLATFORM_LINUX_DEBIAN] = 'https://docs.docker.com/install/linux/docker-ce/debian/'
DOCKER_INSTALL_URLS[PLATFORM_LINUX_CENTOS] = 'https://docs.docker.com/install/linux/docker-ce/centos/'
DOCKER_INSTALL_URLS[PLATFORM_LINUX_FEDORA] = 'https://docs.docker.com/install/linux/docker-ce/fedora/'
DOCKER_INSTALL_URLS[PLATFORM_MAC] = [
    'https://www.code2bits.com/how-to-install-docker-on-macos-using-homebrew/',
    'https://docs.docker.com/docker-for-mac/install/',
]
DOCKER_COMPOSE_INSTALL_URLS = defaultdict(lambda: 'https://docs.docker.com/compose/install/')
HOMEBREW_INSTALL_URLS = defaultdict(lambda: 'https://brew.sh/')


class OrchestrationFramework(Flag):
    UNKNOWN = auto()
    DOCKER_COMPOSE = auto()
    KUBERNETES = auto()


OrchestrationFrameworksSupported = OrchestrationFramework.DOCKER_COMPOSE | OrchestrationFramework.KUBERNETES


##################################################################################################
def ReplaceBindMountLocation(line, location, linePrefix):
    if os.path.isdir(location):
        volumeParts = line.strip().lstrip('-').lstrip().split(':')
        volumeParts[0] = location
        return "{}- {}".format(linePrefix, ':'.join(volumeParts))
    else:
        return line


##################################################################################################
def LocalPathForContainerBindMount(service, dockerComposeContents, containerPath, localBasePath=None):
    localPath = None
    if service and dockerComposeContents and containerPath:
        vols = deep_get(dockerComposeContents, ['services', service, 'volumes'])
        if (vols is not None) and (len(vols) > 0):
            for vol in vols:
                volSplit = vol.split(':')
                if (len(volSplit) >= 2) and (volSplit[1] == containerPath):
                    if localBasePath and not os.path.isabs(volSplit[0]):
                        localPath = os.path.realpath(os.path.join(localBasePath, volSplit[0]))
                    else:
                        localPath = volSplit[0]
                    break

    return localPath


##################################################################################################
def GetUidGidFromEnv(configDir=None):
    configDirToCheck = configDir if configDir and os.path.isdir(configDir) else os.path.join(MalcolmPath, 'config')
    uidGidDict = defaultdict(str)
    if dotEnvImported := DotEnvDynamic():
        pyPlatform = platform.system()
        uidGidDict['PUID'] = f'{os.getuid()}' if (pyPlatform != PLATFORM_WINDOWS) else '1000'
        uidGidDict['PGID'] = f'{os.getgid()}' if (pyPlatform != PLATFORM_WINDOWS) else '1000'
        envFileName = os.path.join(configDirToCheck, 'process.env')
        if os.path.isfile(envFileName):
            envValues = dotEnvImported.dotenv_values(envFileName)
            if 'PUID' in envValues:
                uidGidDict['PUID'] = envValues['PUID']
            if 'PGID' in envValues:
                uidGidDict['PGID'] = envValues['PGID']

    return uidGidDict


###################################################################################################
# attempt to clear the screen
def ClearScreen():
    try:
        os.system("clear" if platform.system() != PLATFORM_WINDOWS else "cls")
    except Exception:
        pass


###################################################################################################
# get interactive user response to Y/N question
def YesOrNo(
    question,
    default=None,
    defaultBehavior=UserInputDefaultsBehavior.DefaultsPrompt,
    uiMode=UserInterfaceMode.InteractionDialog | UserInterfaceMode.InteractionInput,
    clearScreen=False,
):
    if (default is not None) and (
        (defaultBehavior & UserInputDefaultsBehavior.DefaultsAccept)
        and (defaultBehavior & UserInputDefaultsBehavior.DefaultsNonInteractive)
    ):
        reply = ""

    elif (uiMode & UserInterfaceMode.InteractionDialog) and (MainDialog is not None):
        defaultYes = (default is not None) and str2bool(default)
        reply = MainDialog.yesno(
            question, yes_label='Yes' if defaultYes else 'No', no_label='no' if defaultYes else 'yes'
        )
        if defaultYes:
            reply = 'y' if (reply == Dialog.OK) else 'n'
        else:
            reply = 'n' if (reply == Dialog.OK) else 'y'

    elif uiMode & UserInterfaceMode.InteractionInput:
        if (default is not None) and defaultBehavior & UserInputDefaultsBehavior.DefaultsPrompt:
            if str2bool(default):
                questionStr = f"\n{question} (Y/n): "
            else:
                questionStr = f"\n{question} (y/N): "
        else:
            questionStr = f"\n{question}: "

        while True:
            reply = str(input(questionStr)).lower().strip()
            if len(reply) > 0:
                try:
                    str2bool(reply)
                    break
                except ValueError:
                    pass
            elif (defaultBehavior & UserInputDefaultsBehavior.DefaultsAccept) and (default is not None):
                break

    else:
        raise RuntimeError("No user interfaces available")

    if (len(reply) == 0) and (defaultBehavior & UserInputDefaultsBehavior.DefaultsAccept):
        reply = "y" if (default is not None) and str2bool(default) else "n"

    if clearScreen is True:
        ClearScreen()

    try:
        return str2bool(reply)
    except ValueError:
        return YesOrNo(
            question,
            default=default,
            uiMode=uiMode,
            defaultBehavior=defaultBehavior - UserInputDefaultsBehavior.DefaultsAccept,
            clearScreen=clearScreen,
        )


###################################################################################################
# get interactive user response
def AskForString(
    question,
    default=None,
    defaultBehavior=UserInputDefaultsBehavior.DefaultsPrompt,
    uiMode=UserInterfaceMode.InteractionDialog | UserInterfaceMode.InteractionInput,
    clearScreen=False,
):
    if (default is not None) and (
        (defaultBehavior & UserInputDefaultsBehavior.DefaultsAccept)
        and (defaultBehavior & UserInputDefaultsBehavior.DefaultsNonInteractive)
    ):
        reply = default

    elif (uiMode & UserInterfaceMode.InteractionDialog) and (MainDialog is not None):
        code, reply = MainDialog.inputbox(
            question,
            init=default
            if (default is not None) and (defaultBehavior & UserInputDefaultsBehavior.DefaultsPrompt)
            else "",
        )
        if (code == Dialog.CANCEL) or (code == Dialog.ESC):
            raise RuntimeError("Operation cancelled")
        else:
            reply = reply.strip()

    elif uiMode & UserInterfaceMode.InteractionInput:
        reply = str(
            input(
                f"\n{question}{f' ({default})' if (default is not None) and (defaultBehavior & UserInputDefaultsBehavior.DefaultsPrompt) else ''}: "
            )
        ).strip()
        if (len(reply) == 0) and (default is not None) and (defaultBehavior & UserInputDefaultsBehavior.DefaultsAccept):
            reply = default

    else:
        raise RuntimeError("No user interfaces available")

    if clearScreen is True:
        ClearScreen()

    return reply


###################################################################################################
# get interactive password (without echoing)
def AskForPassword(
    prompt,
    uiMode=UserInterfaceMode.InteractionDialog | UserInterfaceMode.InteractionInput,
    clearScreen=False,
):
    if (uiMode & UserInterfaceMode.InteractionDialog) and (MainDialog is not None):
        code, reply = MainDialog.passwordbox(prompt, insecure=True)
        if (code == Dialog.CANCEL) or (code == Dialog.ESC):
            raise RuntimeError("Operation cancelled")

    elif uiMode & UserInterfaceMode.InteractionInput:
        reply = getpass.getpass(prompt=f"{prompt}: ")

    else:
        raise RuntimeError("No user interfaces available")

    if clearScreen is True:
        ClearScreen()

    return reply


###################################################################################################
# Choose one of many.
# choices - an iterable of (tag, item, status) tuples where status specifies the initial
# selected/unselected state of each entry; can be True or False, 1 or 0, "on" or "off"
# (True, 1 and "on" meaning selected), or any case variation of these two strings.
# No more than one entry should be set to True.
def ChooseOne(
    prompt,
    choices=[],
    defaultBehavior=UserInputDefaultsBehavior.DefaultsPrompt,
    uiMode=UserInterfaceMode.InteractionDialog | UserInterfaceMode.InteractionInput,
    clearScreen=False,
):
    validChoices = [x for x in choices if len(x) == 3 and isinstance(x[0], str) and isinstance(x[2], bool)]
    defaulted = next(iter([x for x in validChoices if x[2] is True]), None)

    if (defaultBehavior & UserInputDefaultsBehavior.DefaultsAccept) and (
        defaultBehavior & UserInputDefaultsBehavior.DefaultsNonInteractive
    ):
        reply = defaulted[0] if defaulted is not None else ""

    elif (uiMode & UserInterfaceMode.InteractionDialog) and (MainDialog is not None):
        code, reply = MainDialog.radiolist(
            prompt,
            choices=validChoices,
        )
        if code == Dialog.CANCEL or code == Dialog.ESC:
            raise RuntimeError("Operation cancelled")

    elif uiMode & UserInterfaceMode.InteractionInput:
        index = 0
        for choice in validChoices:
            index = index + 1
            print(
                f"{index}: {choice[0]}{f' - {choice[1]}' if isinstance(choice[1], str) and len(choice[1]) > 0 else ''}"
            )
        while True:
            inputRaw = input(
                f"{prompt}{f' ({defaulted[0]})' if (defaulted is not None) and (defaultBehavior & UserInputDefaultsBehavior.DefaultsPrompt) else ''}: "
            ).strip()
            if (
                (len(inputRaw) == 0)
                and (defaulted is not None)
                and (defaultBehavior & UserInputDefaultsBehavior.DefaultsAccept)
            ):
                reply = defaulted[0]
                break
            elif (len(inputRaw) > 0) and inputRaw.isnumeric():
                inputIndex = int(inputRaw) - 1
                if inputIndex > -1 and inputIndex < len(validChoices):
                    reply = validChoices[inputIndex][0]
                    break

    else:
        raise RuntimeError("No user interfaces available")

    if clearScreen is True:
        ClearScreen()

    return reply


###################################################################################################
# Choose multiple of many
# choices - an iterable of (tag, item, status) tuples where status specifies the initial
# selected/unselected state of each entry; can be True or False, 1 or 0, "on" or "off"
# (True, 1 and "on" meaning selected), or any case variation of these two strings.
def ChooseMultiple(
    prompt,
    choices=[],
    defaultBehavior=UserInputDefaultsBehavior.DefaultsPrompt,
    uiMode=UserInterfaceMode.InteractionDialog | UserInterfaceMode.InteractionInput,
    clearScreen=False,
):
    validChoices = [x for x in choices if len(x) == 3 and isinstance(x[0], str) and isinstance(x[2], bool)]
    defaulted = [x[0] for x in validChoices if x[2] is True]

    if (defaultBehavior & UserInputDefaultsBehavior.DefaultsAccept) and (
        defaultBehavior & UserInputDefaultsBehavior.DefaultsNonInteractive
    ):
        reply = defaulted

    elif (uiMode & UserInterfaceMode.InteractionDialog) and (MainDialog is not None):
        code, reply = MainDialog.checklist(
            prompt,
            choices=validChoices,
        )
        if code == Dialog.CANCEL or code == Dialog.ESC:
            raise RuntimeError("Operation cancelled")

    elif uiMode & UserInterfaceMode.InteractionInput:
        allowedChars = set(string.digits + ',' + ' ')
        defaultValListStr = ",".join(defaulted)
        print("0: NONE")
        index = 0
        for choice in validChoices:
            index = index + 1
            print(
                f"{index}: {choice[0]}{f' - {choice[1]}' if isinstance(choice[1], str) and len(choice[1]) > 0 else ''}"
            )
        while True:
            inputRaw = input(
                f"{prompt}{f' ({defaultValListStr})' if (len(defaultValListStr) > 0) and (defaultBehavior & UserInputDefaultsBehavior.DefaultsPrompt) else ''}: "
            ).strip()
            if (
                (len(inputRaw) == 0)
                and (len(defaulted) > 0)
                and (defaultBehavior & UserInputDefaultsBehavior.DefaultsAccept)
            ):
                reply = defaulted
                break
            elif inputRaw == '0':
                reply = []
                break
            elif (len(inputRaw) > 0) and (set(inputRaw) <= allowedChars):
                reply = []
                selectedIndexes = list(set([int(x.strip()) - 1 for x in inputRaw.split(',') if (len(x.strip())) > 0]))
                for idx in selectedIndexes:
                    if idx > -1 and idx < len(validChoices):
                        reply.append(validChoices[idx][0])
                if len(reply) > 0:
                    break

    else:
        raise RuntimeError("No user interfaces available")

    if clearScreen is True:
        ClearScreen()

    return reply


###################################################################################################
# display a message to the user without feedback
def DisplayMessage(
    message,
    defaultBehavior=UserInputDefaultsBehavior.DefaultsPrompt,
    uiMode=UserInterfaceMode.InteractionDialog | UserInterfaceMode.InteractionInput,
    clearScreen=False,
):
    reply = False

    if (defaultBehavior & UserInputDefaultsBehavior.DefaultsAccept) and (
        defaultBehavior & UserInputDefaultsBehavior.DefaultsNonInteractive
    ):
        reply = True

    elif (uiMode & UserInterfaceMode.InteractionDialog) and (MainDialog is not None):
        code = MainDialog.msgbox(
            message,
        )
        if (code == Dialog.CANCEL) or (code == Dialog.ESC):
            raise RuntimeError("Operation cancelled")
        else:
            reply = True

    else:
        print(f"\n{message}")
        reply = True

    if clearScreen is True:
        ClearScreen()

    return reply


###################################################################################################
# display streaming content via Dialog.programbox
def DisplayProgramBox(
    filePath=None,
    fileFlags=0,
    fileDescriptor=None,
    text=None,
    clearScreen=False,
):
    reply = False

    if MainDialog is not None:
        code = MainDialog.programbox(
            file_path=filePath,
            file_flags=fileFlags,
            fd=fileDescriptor,
            text=text,
            width=78,
            height=20,
        )
        if (code == Dialog.CANCEL) or (code == Dialog.ESC):
            raise RuntimeError("Operation cancelled")
        else:
            reply = True

            if clearScreen is True:
                ClearScreen()

    return reply


###################################################################################################
# Dies if $value isn't positive. NoneType is also acceptable
def posInt(value):
    if value is None:
        return None

    ivalue = int(value)
    if ivalue <= 0:
        raise ValueError("{} is an invalid positive int value".format(value))

    return ivalue


###################################################################################################
# attempt dynamic imports, prompting for install via pip if possible
DynImports = defaultdict(lambda: None)


def DoDynamicImport(importName, pipPkgName, interactive=False, debug=False):
    global DynImports

    # see if we've already imported it
    if not DynImports[importName]:
        # if not, attempt the import
        try:
            tmpImport = importlib.import_module(importName)
            if tmpImport:
                DynImports[importName] = tmpImport
                return DynImports[importName]
        except ImportError:
            pass

        # see if we can help out by installing the module

        pyPlatform = platform.system()
        pyExec = sys.executable
        pipCmd = "pip3"
        if not malcolm_utils.which(pipCmd, debug=debug):
            pipCmd = "pip"

        eprint(f"The {pipPkgName} module is required under Python {platform.python_version()} ({pyExec})")

        if interactive and malcolm_utils.which(pipCmd, debug=debug):
            if YesOrNo(f"Importing the {pipPkgName} module failed. Attempt to install via {pipCmd}?"):
                installCmd = None

                if (pyPlatform == PLATFORM_LINUX) or (pyPlatform == PLATFORM_MAC):
                    # for linux/mac, we're going to try to figure out if this python is owned by root or the script user
                    if getpass.getuser() == getpwuid(os.stat(pyExec).st_uid).pw_name:
                        # we're running a user-owned python, regular pip should work
                        installCmd = [pipCmd, "install", pipPkgName]
                    else:
                        # python is owned by system, so make sure to pass the --user flag
                        installCmd = [pipCmd, "install", "--user", pipPkgName]
                else:
                    # on windows (or whatever other platform this is) I don't know any other way other than pip
                    installCmd = [pipCmd, "install", pipPkgName]

                err, out = run_process(installCmd, debug=debug)
                if err == 0:
                    eprint(f"Installation of {pipPkgName} module apparently succeeded")
                    try:
                        tmpImport = importlib.import_module(importName)
                        if tmpImport:
                            DynImports[importName] = tmpImport
                    except ImportError as e:
                        eprint(f"Importing the {importName} module still failed: {e}")
                else:
                    eprint(f"Installation of {importName} module failed: {out}")

    if not DynImports[importName]:
        eprint(
            "System-wide installation varies by platform and Python configuration. Please consult platform-specific documentation for installing Python modules."
        )

    return DynImports[importName]


def RequestsDynamic(debug=False, forceInteraction=False):
    return DoDynamicImport("requests", "requests", interactive=forceInteraction, debug=debug)


def YAMLDynamic(debug=False, forceInteraction=False):
    return DoDynamicImport("yaml", "pyyaml", interactive=forceInteraction, debug=debug)


def KubernetesDynamic(verifySsl=False, debug=False, forceInteraction=False):
    return DoDynamicImport("kubernetes", "kubernetes", interactive=forceInteraction, debug=debug)


def DotEnvDynamic(debug=False, forceInteraction=False):
    return DoDynamicImport("dotenv", "python-dotenv", interactive=forceInteraction, debug=debug)


###################################################################################################
# do the required auth files for Malcolm exist?
def MalcolmAuthFilesExist(configDir=None):
    configDirToCheck = (
        configDir if configDir is not None and os.path.isdir(configDir) else os.path.join(MalcolmPath, 'config')
    )
    return (
        os.path.isfile(os.path.join(MalcolmPath, os.path.join('nginx', 'htpasswd')))
        and os.path.isfile(os.path.join(MalcolmPath, os.path.join('nginx', 'nginx_ldap.conf')))
        and os.path.isfile(os.path.join(MalcolmPath, os.path.join('nginx', os.path.join('certs', 'cert.pem'))))
        and os.path.isfile(os.path.join(MalcolmPath, os.path.join('nginx', os.path.join('certs', 'key.pem'))))
        and os.path.isfile(os.path.join(MalcolmPath, os.path.join('htadmin', 'config.ini')))
        and os.path.isfile(os.path.join(configDirToCheck, 'netbox-secret.env'))
        and os.path.isfile(os.path.join(configDirToCheck, 'netbox-postgres.env'))
        and os.path.isfile(os.path.join(configDirToCheck, 'netbox-redis-cache.env'))
        and os.path.isfile(os.path.join(configDirToCheck, 'netbox-redis.env'))
        and os.path.isfile(os.path.join(configDirToCheck, 'auth.env'))
        and os.path.isfile(os.path.join(MalcolmPath, '.opensearch.primary.curlrc'))
    )


###################################################################################################
# determine if a YAML file looks like a docker-compose.yml file or a kubeconfig file
def DetermineYamlFileFormat(inputFileName):
    result = OrchestrationFramework.UNKNOWN

    if yamlImported := YAMLDynamic():
        try:
            with open(inputFileName, 'r') as cf:
                orchestrationYaml = yamlImported.safe_load(cf)

            if isinstance(orchestrationYaml, dict):
                if any(key in orchestrationYaml for key in ('apiVersion', 'clusters', 'contexts', 'kind')):
                    result = OrchestrationFramework.KUBERNETES
                elif 'services' in orchestrationYaml:
                    result = OrchestrationFramework.DOCKER_COMPOSE

        except Exception as e:
            eprint(f'Error deciphering {inputFileName}: {e}')

    return result


###################################################################################################
# download to file
def DownloadToFile(url, local_filename, debug=False):
    r = RequestsDynamic().get(url, stream=True, allow_redirects=True)
    with open(local_filename, 'wb') as f:
        for chunk in r.iter_content(chunk_size=1024):
            if chunk:
                f.write(chunk)
    fExists = os.path.isfile(local_filename)
    fSize = os.path.getsize(local_filename)
    if debug:
        eprint(
            f"Download of {url} to {local_filename} {'succeeded' if fExists else 'failed'} ({malcolm_utils.sizeof_fmt(fSize)})"
        )
    return fExists and (fSize > 0)


###################################################################################################
# process log line from containers' output

URL_USER_PASS_REGEX = re.compile(r'(\w+://[^/]+?:)[^/]+?(@[^/]+)')

# noisy logs (a lot of it is NGINX logs from health checks)
LOG_IGNORE_REGEX = re.compile(
    r"""
.+(
    deprecated
  | "GET\s+/\s+HTTP/1\.\d+"\s+200\s+-
  | \bGET.+\b302\s+30\b
  | (async|output)\.go.+(reset\s+by\s+peer|Connecting\s+to\s+backoff|backoff.+established$)
  | /(opensearch-dashboards|dashboards|kibana)/(api/ui_metric/report|internal/search/(es|opensearch))
  | (Error\s+during\s+file\s+comparison|File\s+was\s+renamed):\s+/zeek/live/logs/
  | /_ns_/nstest\.html
  | /proc/net/tcp6:\s+no\s+such\s+file\s+or\s+directory
  | /usr/share/logstash/x-pack/lib/filters/geoip/database_manager
  | \b(d|es)?stats\.json
  | \b1.+GET\s+/\s+.+401.+curl
  | _cat/indices
  | branding.*config\s+is\s+not\s+found\s+or\s+invalid
  | but\s+there\s+are\s+no\s+living\s+connections
  | Connecting\s+to\s+backoff
  | Cleaning\s+registries\s+for\s+queue:
  | curl.+localhost.+GET\s+/api/status\s+200
  | DEPRECATION
  | descheduling\s+job\s*id
  | (relation|SELECT)\s+"django_content_type"
  | eshealth
  | esindices/list
  | executing\s+attempt_(transition|set_replica_count)\s+for
  | failed\s+to\s+get\s+tcp6?\s+stats\s+from\s+/proc
  | GET\s+/(netbox/api|_cat/health|api/status|sessions2-|arkime_\w+).+HTTP/[\d\.].+\b200\b
  | GET\s+/\s+.+\b200\b.+ELB-HealthChecker
  | loaded\s+config\s+'/etc/netbox/config/
  | "netbox"\s+application\s+started
  | \[notice\].+app\s+process\s+\d+\s+exited\s+with\s+code\s+0\b
  | kube-probe/
  | POST\s+/(arkime_\w+)(/\w+)?/_(d?stat|doc|search).+HTTP/[\d\.].+\b20[01]\b
  | POST\s+/_bulk\s+HTTP/[\d\.].+\b20[01]\b
  | POST\s+/server/php/\s+HTTP/\d+\.\d+"\s+\d+\s+\d+.*:8443/
  | POST\s+HTTP/[\d\.].+\b200\b
  | reaped\s+unknown\s+pid
  | redis.*(changes.+seconds.+Saving|Background\s+saving\s+(started|terminated)|DB\s+saved\s+on\s+disk|Fork\s+CoW)
  | remov(ed|ing)\s+(old\s+file|dead\s+symlink|empty\s+directory)
  | retry\.go.+(send\s+unwait|done$)
  | running\s+full\s+sweep
  | saved_objects
  | scheduling\s+job\s*id.+opendistro-ism
  | SSL/TLS\s+verifications\s+disabled
  | Successfully\s+handled\s+GET\s+request\s+for\s+'/'
  | Test\s+run\s+complete.*:failed=>0,\s*:errored=>0\b
  | throttling\s+index
  | update_mapping
  | updating\s+number_of_replicas
  | use_field_mapping
  | Using\s+geoip\s+database
)
""",
    re.VERBOSE | re.IGNORECASE,
)

# logs we don't want to eliminate, but we don't want to repeat ad-nauseum
# TODO: not implemented yet
#   dupeRegEx = re.compile(
#       r"""
#   .+(
#       Maybe the destination pipeline is down or stopping
#   )
# """,
#       re.VERBOSE | re.IGNORECASE,
#   )

SERVICE_REGEX = re.compile(r'^(?P<service>.+?\|)\s*(?P<message>.*)$')

CONTAINER_REPL_REGEX = re.compile(r'([\w\.-]+)-container(\s*\|)')

ISO8601_TIME_REGEX = re.compile(
    r'^(-?(?:[1-9][0-9]*)?[0-9]{4})-(1[0-2]|0[1-9])-(3[01]|0[1-9]|[12][0-9])T(2[0-3]|[01][0-9]):([0-5][0-9]):([0-5][0-9])(\.[0-9]+)?(Z|[+-](?:2[0-3]|[01][0-9]):[0-5][0-9])?$'
)


def ProcessLogLine(line, debug=False):
    global ISO8601_TIME_REGEX
    global LOG_IGNORE_REGEX
    global SERVICE_REGEX
    global URL_USER_PASS_REGEX

    outputStr = CONTAINER_REPL_REGEX.sub(r"\1\2", URL_USER_PASS_REGEX.sub(r"\1xxxxxxxx\2", line.decode().strip()))
    outputStrEscaped = EscapeAnsi(outputStr)
    if LOG_IGNORE_REGEX.match(outputStrEscaped):
        return None
    else:
        serviceMatch = SERVICE_REGEX.search(outputStrEscaped)
        serviceMatchFmt = SERVICE_REGEX.search(outputStr) if coloramaImported else serviceMatch
        serviceStr = serviceMatchFmt.group('service').replace('-container', '') if (serviceMatchFmt is not None) else ''

        messageStr = serviceMatch.group('message') if (serviceMatch is not None) else ''
        messageStrSplit = messageStr.split(' ')
        messageTimeMatch = ISO8601_TIME_REGEX.match(messageStrSplit[0])
        if (messageTimeMatch is None) or (len(messageStrSplit) <= 1):
            messageStrToTestJson = messageStr
        else:
            messageStrToTestJson = messageStrSplit[1:].join(' ')

        outputJson = LoadStrIfJson(messageStrToTestJson)
        if isinstance(outputJson, dict):
            # if there's a timestamp, move it outside of the JSON to the beginning of the log string
            timeKey = None
            if 'time' in outputJson:
                timeKey = 'time'
            elif 'timestamp' in outputJson:
                timeKey = 'timestamp'
            elif '@timestamp' in outputJson:
                timeKey = '@timestamp'
            timeStr = ''
            if timeKey is not None:
                timeStr = f"{outputJson[timeKey]} "
                outputJson.pop(timeKey, None)
            elif messageTimeMatch is not None:
                timeStr = f"{messageTimeMatch[0]} "

            if ('job.schedule' in outputJson) and ('job.position' in outputJson) and ('job.command' in outputJson):
                # this is a status line line from supercronic, let's format and clean it up so it fits in better with the rest of the logs

                # remove some clutter for the display
                for noisyKey in ['level', 'channel', 'iteration', 'job.position', 'job.schedule']:
                    outputJson.pop(noisyKey, None)

                # if it's just command and message, format those NOT as JSON
                jobCmd = outputJson['job.command']
                jobStatus = outputJson['msg']
                if (len(outputJson.keys()) == 2) and ('job.command' in outputJson) and ('msg' in outputJson):
                    # if it's the most common status (starting or job succeeded) then don't print unless debug mode
                    if debug or ((jobStatus != 'starting') and (jobStatus != 'job succeeded')):
                        return (
                            f"{serviceStr}{Style.RESET_ALL if coloramaImported else ''} {timeStr} {jobCmd}: {jobStatus}"
                        )
                    else:
                        return None

                else:
                    # standardize and print the JSON line
                    return (
                        f"{serviceStr}{Style.RESET_ALL if coloramaImported else ''} {timeStr}{json.dumps(outputJson)}"
                    )

            elif 'dashboards' in serviceStr:
                # this is an line line from dashboards, let's clean it up a bit: remove some clutter for the display
                for noisyKey in ['type', 'tags', 'pid', 'method', 'prevState', 'prevMsg']:
                    outputJson.pop(noisyKey, None)

                # standardize and print the JSON line
                return f"{serviceStr}{Style.RESET_ALL if coloramaImported else ''} {timeStr}{json.dumps(outputJson)}"

            elif 'filebeat' in serviceStr:
                # this is an line line from filebeat, let's clean it up a bit: remove some clutter for the display
                for noisyKey in [
                    'ecs.version',
                    'harvester_id',
                    'input_id',
                    'log.level',
                    'log.logger',
                    'log.origin',
                    'os_id',
                    'service.name',
                    'state_id',
                ]:
                    outputJson.pop(noisyKey, None)

                # we'll fancify a couple of common things from filebeat
                if (
                    (len(outputJson.keys()) == 3)
                    and ('message' in outputJson)
                    and ('source_file' in outputJson)
                    and ('finished' in outputJson)
                ):
                    return f"{serviceStr}{Style.RESET_ALL if coloramaImported else ''} {timeStr}{outputJson['message'].rstrip('.')}: {outputJson['source_file']}"

                elif len(outputJson.keys()) == 1:
                    outputKey = next(iter(outputJson))
                    return f"{serviceStr}{Style.RESET_ALL if coloramaImported else ''} {timeStr}{outputKey + ': ' if outputKey != 'message' else ''}{outputJson[outputKey]}"

                else:
                    # standardize and print the JSON line
                    return (
                        f"{serviceStr}{Style.RESET_ALL if coloramaImported else ''} {timeStr}{json.dumps(outputJson)}"
                    )

            else:
                # standardize and print the JSON line
                return f"{serviceStr}{Style.RESET_ALL if coloramaImported else ''} {timeStr}{json.dumps(outputJson)}"

        else:
            # just a regular non-JSON string, print as-is
            return outputStr if coloramaImported else outputStrEscaped

    return None
