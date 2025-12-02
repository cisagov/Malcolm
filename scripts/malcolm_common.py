#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2025 Battelle Energy Alliance, LLC.  All rights reserved.

import getpass
import importlib
import importlib.util
import ipaddress
import json
import os
import math
import platform
import re
import site
import ssl
import string
import sys
import time
import types

from base64 import b64encode
from http.client import HTTPSConnection, HTTPConnection
from urllib.parse import urlparse

# Dynamically create a module named "scripts" which points to this directory
if "scripts" not in sys.modules:
    scripts_module = types.ModuleType("scripts")
    scripts_module.__path__ = [os.path.dirname(os.path.abspath(__file__))]
    sys.modules["scripts"] = scripts_module

from scripts.malcolm_utils import (
    deep_get,
    eprint,
    get_main_script_path,
    EscapeAnsi,
    LoadStrIfJson,
    remove_suffix,
    run_process,
    sizeof_fmt,
    touch,
    which,
)

from collections import defaultdict, namedtuple
from enum import IntEnum, Flag, IntFlag, auto
from typing import Tuple, List, Optional
from pathlib import Path

from scripts.malcolm_constants import (
    DEFAULT_INDEX_DIR,
    DEFAULT_INDEX_SNAPSHOT_DIR,
    DEFAULT_PCAP_DIR,
    DEFAULT_SURICATA_LOG_DIR,
    DEFAULT_ZEEK_LOG_DIR,
    FILE_MONITOR_ZEEK_LOGS_CONTAINER_PATH,
    FILEBEAT_SURICATA_LOG_CONTAINER_PATH,
    FILEBEAT_ZEEK_LOG_CONTAINER_PATH,
    ImageArchitecture,
    MALCOLM_VERSION,
    OPENSEARCH_BACKUP_CONTAINER_PATH,
    OPENSEARCH_DATA_CONTAINER_PATH,
    OrchestrationFramework,
    OrchestrationFrameworksSupported,
    PCAP_CAPTURE_CONTAINER_PATH,
    PCAP_DATA_CONTAINER_PATH,
    PGID_DEFAULT,
    PLATFORM_LINUX,
    PLATFORM_LINUX_CENTOS,
    PLATFORM_LINUX_DEBIAN,
    PLATFORM_LINUX_FEDORA,
    PLATFORM_LINUX_UBUNTU,
    PLATFORM_MAC,
    PLATFORM_WINDOWS,
    PROFILE_HEDGEHOG,
    PROFILE_MALCOLM,
    PUID_DEFAULT,
    SettingsFileFormat,
    SURICATA_LOG_CONTAINER_PATH,
    UPLOAD_ARTIFACT_CONTAINER_PATH,
    YAML_VERSION,
    ZEEK_EXTRACT_FILES_CONTAINER_PATH,
    ZEEK_LIVE_LOG_CONTAINER_PATH,
    ZEEK_LOG_UPLOAD_CONTAINER_PATH,
)

try:
    from pwd import getpwuid
except ImportError:
    getpwuid = None

Dialog = None
MainDialog = None

# Reasonable dialog bounds; used to reduce awkward wrapping in python-dialog
_DIALOG_MIN_WIDTH = 50
_DIALOG_MAX_WIDTH = 140
_DIALOG_MIN_HEIGHT = 7
_DIALOG_MAX_HEIGHT = 30


def _dialog_size_for(text: str) -> tuple[int, int]:
    """Compute a suitable (height, width) for a dialog widget.

    - Width fits the longest line with a small padding.
    - Height accounts for the number of text lines plus button area.
    """
    try:
        if not isinstance(text, str):
            text = str(text)
        lines = text.splitlines() or [""]
        max_line = max((len(line) for line in lines), default=_DIALOG_MIN_WIDTH)
        width = max(_DIALOG_MIN_WIDTH, min(max_line + 4, _DIALOG_MAX_WIDTH))
        # base height for buttons + borders; add per text line beyond the first
        height = _DIALOG_MIN_HEIGHT + max(0, len(lines) - 1)
        height = max(_DIALOG_MIN_HEIGHT, min(height, _DIALOG_MAX_HEIGHT))
        return height, width
    except Exception:
        return (_DIALOG_MIN_HEIGHT, _DIALOG_MIN_WIDTH)


def _dialog_menu_width_for(choices) -> int:
    """Compute a suitable dialog width based on menu choices.

    Looks at the lengths of tag and item columns to avoid overlap/truncation
    in radiolist/checklist widgets.
    """
    try:
        max_tag = 0
        max_item = 0
        for ch in choices or []:
            if not (isinstance(ch, (list, tuple)) and len(ch) == 3):
                continue
            tag = str(ch[0])
            item = str(ch[1]) if ch[1] is not None else ""
            max_tag = max(max_tag, len(tag))
            max_item = max(max_item, len(item))
        # approximate spacing between tag and item columns used by dialog
        # add an explicit buffer so value column doesn't butt against tag text
        buffer_spaces = 6
        width = max_tag + 2 + max_item + 8 + buffer_spaces
        return max(_DIALOG_MIN_WIDTH, min(width, _DIALOG_MAX_WIDTH))
    except Exception:
        return _DIALOG_MIN_WIDTH


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
MalcolmISOOsInfoFile = os.path.join(MalcolmPath, '.os-info')

# Utility helpers for referring to the root of the Malcolm repository from
# other helper scripts.


def GetMalcolmPath():
    """Return the absolute path to the root of the Malcolm repository."""
    return MalcolmPath


def SetMalcolmPath(val):
    global MalcolmPath
    MalcolmPath = val
    return MalcolmPath


class NullRepresenter:
    def __call__(self, repr, data):
        ret_val = repr.represent_scalar(u'tag:yaml.org,2002:null', u'')
        return ret_val


def DialogInit():
    global Dialog
    global MainDialog
    try:
        if not Dialog:
            from dialog import Dialog

        if not MainDialog:
            MainDialog = Dialog(dialog='dialog', autowidgetsize=True)
    except ImportError:
        Dialog = None
        MainDialog = None


DialogInit()


class UserInputDefaultsBehavior(IntFlag):
    DefaultsPrompt = auto()
    DefaultsAccept = auto()
    DefaultsNonInteractive = auto()


class UserInterfaceMode(IntFlag):
    InteractionDialog = auto()
    InteractionInput = auto()


class DialogBackException(Exception):
    pass


class DialogCanceledException(Exception):
    pass


class BoolOrExtra(IntEnum):
    FALSE = 0
    TRUE = 1
    EXTRA = 2


BoundPath = namedtuple(
    "BoundPath",
    ["service", "target", "files", "relative_dirs", "clean_empty_dirs"],
    rename=False,
)

BoundPathReplacer = namedtuple(
    "BoundPathReplacer",
    ["service", "target", "source"],
    rename=False,
)

# define environment variables to be set in .env files
EnvValue = namedtuple("EnvValue", ["provided", "envFile", "key", "value"], rename=False)

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
    'https://formulae.brew.sh/formula/docker',
    'https://formulae.brew.sh/formula/docker-compose',
]
DOCKER_COMPOSE_INSTALL_URLS = defaultdict(lambda: 'https://docs.docker.com/compose/install/')
HOMEBREW_INSTALL_URLS = defaultdict(lambda: 'https://brew.sh/')

##################################################################################################


##################################################################################################
def LocalPathForContainerBindMount(
    service,
    docker_compose_contents,
    container_path,
    local_base_path=None,
):
    local_path = None
    if service and docker_compose_contents and container_path:
        vols = deep_get(docker_compose_contents, ['services', service, 'volumes'])
        if (vols is not None) and (len(vols) > 0):
            for vol in vols:
                if (
                    isinstance(vol, dict)
                    and ('source' in vol)
                    and ('target' in vol)
                    and (vol['target'] == container_path)
                ):
                    if local_base_path and not os.path.isabs(vol['source']):
                        local_path = os.path.realpath(os.path.join(local_base_path, vol['source']))
                    else:
                        local_path = vol['source']
                    break
                elif isinstance(vol, str):
                    volSplit = vol.split(':')
                    if (len(volSplit) >= 2) and (volSplit[1] == container_path):
                        if local_base_path and not os.path.isabs(volSplit[0]):
                            local_path = os.path.realpath(os.path.join(local_base_path, volSplit[0]))
                        else:
                            local_path = volSplit[0]
                        break
    return local_path


def GetExposedPorts(docker_compose_contents, exclude_ports=None):
    exclude_ports = exclude_ports or set()
    host_ports = set()

    for svc in docker_compose_contents.get("services", {}).values():
        for port_str in svc.get("ports", []):
            parts = port_str.split(":")
            if len(parts) == 3:
                ip, host_port, _ = parts
                if ip in ("", "0.0.0.0") and host_port not in exclude_ports:
                    host_ports.add(host_port)
            elif len(parts) == 2:
                host_port, _ = parts
                if host_port not in exclude_ports:
                    host_ports.add(host_port)

    return sorted(host_ports, key=int)


def BuildBoundPathReplacers(
    pcap_dir=DEFAULT_PCAP_DIR,
    suricata_log_dir=DEFAULT_SURICATA_LOG_DIR,
    zeek_log_dir=DEFAULT_ZEEK_LOG_DIR,
    index_dir=DEFAULT_INDEX_DIR,
    index_snapshot_dir=DEFAULT_INDEX_SNAPSHOT_DIR,
):
    return (
        BoundPathReplacer("arkime", PCAP_DATA_CONTAINER_PATH, pcap_dir),
        BoundPathReplacer("arkime-live", PCAP_DATA_CONTAINER_PATH, pcap_dir),
        BoundPathReplacer("filebeat", FILEBEAT_SURICATA_LOG_CONTAINER_PATH, suricata_log_dir),
        BoundPathReplacer("filebeat", FILEBEAT_ZEEK_LOG_CONTAINER_PATH, zeek_log_dir),
        BoundPathReplacer(
            "file-monitor", ZEEK_EXTRACT_FILES_CONTAINER_PATH, os.path.join(zeek_log_dir, 'extract_files')
        ),
        BoundPathReplacer("file-monitor", FILE_MONITOR_ZEEK_LOGS_CONTAINER_PATH, os.path.join(zeek_log_dir, 'current')),
        BoundPathReplacer("opensearch", OPENSEARCH_DATA_CONTAINER_PATH, index_dir),
        BoundPathReplacer("opensearch", OPENSEARCH_BACKUP_CONTAINER_PATH, index_snapshot_dir),
        BoundPathReplacer("pcap-capture", PCAP_CAPTURE_CONTAINER_PATH, os.path.join(pcap_dir, 'upload')),
        BoundPathReplacer("pcap-monitor", PCAP_CAPTURE_CONTAINER_PATH, pcap_dir),
        BoundPathReplacer("pcap-monitor", FILEBEAT_ZEEK_LOG_CONTAINER_PATH, zeek_log_dir),
        BoundPathReplacer("suricata", PCAP_DATA_CONTAINER_PATH, pcap_dir),
        BoundPathReplacer("suricata", SURICATA_LOG_CONTAINER_PATH, suricata_log_dir),
        BoundPathReplacer("suricata-live", SURICATA_LOG_CONTAINER_PATH, suricata_log_dir),
        BoundPathReplacer("upload", UPLOAD_ARTIFACT_CONTAINER_PATH, os.path.join(pcap_dir, 'upload')),
        BoundPathReplacer("zeek", PCAP_CAPTURE_CONTAINER_PATH, pcap_dir),
        BoundPathReplacer("zeek", ZEEK_LOG_UPLOAD_CONTAINER_PATH, os.path.join(zeek_log_dir, 'upload')),
        BoundPathReplacer("zeek", ZEEK_EXTRACT_FILES_CONTAINER_PATH, os.path.join(zeek_log_dir, 'extract_files')),
        BoundPathReplacer("zeek-live", ZEEK_LIVE_LOG_CONTAINER_PATH, os.path.join(zeek_log_dir, 'live')),
        BoundPathReplacer("zeek-live", ZEEK_EXTRACT_FILES_CONTAINER_PATH, os.path.join(zeek_log_dir, 'extract_files')),
    )


def RemapBoundPaths(docker_compose_contents: dict, replacements: Tuple[BoundPathReplacer]) -> int:
    remap_count = 0
    for replacer in replacements:
        if (replacer.service in docker_compose_contents['services']) and (
            'volumes' in docker_compose_contents['services'][replacer.service]
        ):
            for vol_idx, vol_val in enumerate(docker_compose_contents['services'][replacer.service]['volumes']):
                if (
                    isinstance(vol_val, dict)
                    and ('source' in vol_val)
                    and ('target' in vol_val)
                    and (vol_val['target'] == replacer.target)
                ):
                    docker_compose_contents['services'][replacer.service]['volumes'][vol_idx][
                        'source'
                    ] = replacer.source
                    remap_count += 1
                elif isinstance(vol_val, str) and re.match(fr'^.+:{replacer.target}(:.+)?\s*$', vol_val):
                    volume_parts = vol_val.strip().split(':')
                    volume_parts[0] = replacer.source
                    docker_compose_contents['services'][replacer.service]['volumes'][vol_idx] = ':'.join(volume_parts)
                    remap_count += 1

    return remap_count


##################################################################################################
def GetMemMegabytesFromJavaOptsLine(val):
    resultStr = None
    resultMB = 0
    for opt in ('Xmx', 'Xms'):
        if resultStr is not None:
            break
        if match := re.search(fr'-{opt}(\d+[kmg])', val, re.IGNORECASE):
            resultStr = match.group(1)
    if resultStr is not None:
        value = int(resultStr[:-1])
        unit = resultStr[-1].lower()
        if unit == 'g':
            resultMB = value * 1024
        elif unit == 'm':
            resultMB = value
        elif unit == 'k':
            resultMB = math.ceil(value / 1024)
        else:
            resultMB = 0
        if resultMB < 1:
            resultMB = 0
    return resultMB


##################################################################################################
def ParseK8sMemoryToMib(val):
    val = str(val).strip()
    units = {'Ki': 1 / 1024, 'Mi': 1, 'Gi': 1024, 'Ti': 1024 * 1024}

    for unit in units:
        if val.endswith(unit):
            value = float(val.replace(unit, ''))
            return int(value * units[unit])

    return 0


##################################################################################################
def GetUidGidFromEnv(configDir=None):
    uidGidDict = {}
    # default to the IDs for the calling user ...
    pyPlatform = platform.system()
    uidGidDict['PUID'] = f'{os.getuid()}' if (pyPlatform != PLATFORM_WINDOWS) else str(PUID_DEFAULT)
    uidGidDict['PGID'] = f'{os.getgid()}' if (pyPlatform != PLATFORM_WINDOWS) else str(PGID_DEFAULT)
    if dotEnvImported := DotEnvDynamic():
        # ... but prefer the values in process.env
        configDirToCheck = configDir if configDir and os.path.isdir(configDir) else os.path.join(MalcolmPath, 'config')
        envFileName = os.path.join(configDirToCheck, 'process.env')
        if os.path.isfile(envFileName):
            envValues = dotEnvImported.dotenv_values(envFileName)
            if 'PUID' in envValues:
                uidGidDict['PUID'] = envValues['PUID']
            if 'PGID' in envValues:
                uidGidDict['PGID'] = envValues['PGID']

    return uidGidDict


##################################################################################################
def GetNonRootUidGid(
    reference_path=None,
    script_user=getpass.getuser(),
    script_platform=platform.system(),
    fallback_uid=PUID_DEFAULT,
    fallback_gid=PGID_DEFAULT,
):
    default_uid = str(fallback_uid)
    default_gid = str(fallback_gid)

    if (
        ((script_platform == PLATFORM_LINUX) or (script_platform == PLATFORM_MAC))
        and (script_user == "root")
        and reference_path
        and os.path.exists(reference_path)
    ):
        if path_uid := os.stat(reference_path).st_uid:
            default_uid = str(path_uid)
        if path_gid := os.stat(reference_path).st_gid:
            default_gid = str(path_gid)

    uid = default_uid
    gid = default_gid
    try:
        if (script_platform == PLATFORM_LINUX) or (script_platform == PLATFORM_MAC):
            uid = str(os.getuid())
            gid = str(os.getgid())
            if (uid == "0") or (gid == "0"):
                raise
    except Exception:
        uid = default_uid
        gid = default_gid

    return {
        'PUID': uid,
        'PGID': gid,
    }


##################################################################################################
def GetNonRootMalcolmUserNames():

    def safe_getpwuid_name(val):
        try:
            return getpwuid(val).pw_name if getpwuid else None
        except Exception:
            return None

    return list(
        set(
            [
                user
                for user in {
                    getpass.getuser(),
                    safe_getpwuid_name(int(GetNonRootUidGid(reference_path=MalcolmPath).get('PUID'))),
                    os.environ.get("USER"),
                    os.environ.get("LOGNAME"),
                }
                if user and user not in {"root", "0"}
            ]
        )
    )


##################################################################################################
# takes an array of EnvValue namedtuple (see above) and updates the values in the specified .env files
def UpdateEnvFiles(envValues, chmodFlag=None):
    result = False
    if dotEnvImported := DotEnvDynamic():
        result = True
        for val in [v for v in envValues if v.provided]:
            try:
                touch(val.envFile)
            except Exception:
                pass

            try:
                oldDotEnvVersion = False
                try:
                    dotEnvImported.set_key(
                        val.envFile,
                        val.key,
                        str(val.value),
                        quote_mode='never',
                        encoding='utf-8',
                    )
                except TypeError:
                    oldDotEnvVersion = True

                if oldDotEnvVersion:
                    dotEnvImported.set_key(
                        val.envFile,
                        val.key,
                        str(val.value),
                        quote_mode='never',
                    )

            except Exception as e:
                eprint(f"Setting value for {val.key} in {val.envFile} module failed ({type(e).__name__}): {e}")
                result = False

            if chmodFlag is not None:
                try:
                    os.chmod(val.envFile, chmodFlag)
                except Exception:
                    pass

    return result


###################################################################################################
# attempt to clear the screen
def ClearScreen():
    try:
        os.system("clear" if platform.system() != PLATFORM_WINDOWS else "cls")
    except Exception:
        pass


###################################################################################################
def str2boolorextra(v):
    if isinstance(v, bool):
        return BoolOrExtra.TRUE if v else BoolOrExtra.FALSE
    elif isinstance(v, str):
        if v.lower() in ("yes", "true", "t", "y", "1"):
            return BoolOrExtra.TRUE
        elif v.lower() in ("no", "false", "f", "n", "0"):
            return BoolOrExtra.FALSE
        elif v.lower() in ("b", "back", "p", "previous", "e", "extra"):
            return BoolOrExtra.EXTRA
        else:
            raise ValueError("BoolOrExtra value expected")
    else:
        raise ValueError("BoolOrExtra value expected")


###################################################################################################
# get interactive user response to Y/N question
def YesOrNo(
    question,
    default=None,
    defaultBehavior=UserInputDefaultsBehavior.DefaultsPrompt,
    uiMode=UserInterfaceMode.InteractionDialog | UserInterfaceMode.InteractionInput,
    clearScreen=False,
    yesLabel='Yes',
    noLabel='No',
    extraLabel=None,
):
    global Dialog
    global MainDialog
    result = None

    if (default is not None) and (
        (defaultBehavior & UserInputDefaultsBehavior.DefaultsAccept)
        and (defaultBehavior & UserInputDefaultsBehavior.DefaultsNonInteractive)
    ):
        reply = ""

    elif (uiMode & UserInterfaceMode.InteractionDialog) and (MainDialog is not None):
        defaultYes = (default is not None) and str2boolorextra(default)
        # by default the "extra" button is between "Yes" and "No" which looks janky, IMO.
        #   so we're going to switch things around a bit.
        yesLabelTmp = yesLabel.capitalize() if defaultYes else noLabel.capitalize()
        noLabelTmp = noLabel.capitalize() if defaultYes else yesLabel.capitalize()
        replyMap = {}
        if hasExtraLabel := (extraLabel is not None):
            replyMap[Dialog.EXTRA] = Dialog.CANCEL
            replyMap[Dialog.CANCEL] = Dialog.EXTRA
        _h, _w = _dialog_size_for(str(question))
        kwargs = {
            "yes_label": str(yesLabelTmp),
            "no_label": (str(extraLabel) if hasExtraLabel else str(noLabelTmp)),
            "extra_button": hasExtraLabel,
            "extra_label": (str(noLabelTmp) if hasExtraLabel else ""),
            "height": _h,
            "width": _w,
        }
        reply = MainDialog.yesno(str(question), **kwargs)
        reply = replyMap.get(reply, reply)
        if defaultYes:
            reply = 'y' if (reply == Dialog.OK) else ('e' if (reply == Dialog.EXTRA) else 'n')
        else:
            reply = 'n' if (reply == Dialog.OK) else ('e' if (reply == Dialog.EXTRA) else 'y')

    elif uiMode & UserInterfaceMode.InteractionInput:
        if (default is not None) and defaultBehavior & UserInputDefaultsBehavior.DefaultsPrompt:
            if str2boolorextra(default):
                questionStr = f"\n{question} (Y{'' if yesLabel == 'Yes' else ' (' + yesLabel + ')'} / n{'' if noLabel == 'No' else ' (' + noLabel + ')'}): "
            else:
                questionStr = f"\n{question} (y{'' if yesLabel == 'Yes' else ' (' + yesLabel + ')'} / N{'' if noLabel == 'No' else ' (' + noLabel + ')'}): "
        else:
            questionStr = f"\n{question} (Y{'' if yesLabel == 'Yes' else ' (' + yesLabel + ')'} / N{'' if noLabel == 'No' else ' (' + noLabel + ')'}): "

        while True:
            reply = str(input(questionStr)).lower().strip()
            if len(reply) > 0:
                try:
                    str2boolorextra(reply)
                    break
                except ValueError:
                    pass
            elif (defaultBehavior & UserInputDefaultsBehavior.DefaultsAccept) and (default is not None):
                break

    else:
        raise RuntimeError("No user interfaces available")

    if (len(reply) == 0) and (defaultBehavior & UserInputDefaultsBehavior.DefaultsAccept):
        reply = "y" if (default is not None) and str2boolorextra(default) else "n"

    if clearScreen is True:
        ClearScreen()

    try:
        result = str2boolorextra(reply)
    except ValueError:
        result = YesOrNo(
            question,
            default=default,
            uiMode=uiMode,
            defaultBehavior=defaultBehavior - UserInputDefaultsBehavior.DefaultsAccept,
            clearScreen=clearScreen,
            yesLabel=yesLabel,
            noLabel=noLabel,
            extraLabel=extraLabel,
        )

    if result == BoolOrExtra.EXTRA:
        raise DialogBackException(question)

    return bool(result)


###################################################################################################
# get interactive user response
def AskForString(
    question,
    default=None,
    defaultBehavior=UserInputDefaultsBehavior.DefaultsPrompt,
    uiMode=UserInterfaceMode.InteractionDialog | UserInterfaceMode.InteractionInput,
    clearScreen=False,
    extraLabel=None,
):
    global Dialog
    global MainDialog

    if (default is not None) and (
        (defaultBehavior & UserInputDefaultsBehavior.DefaultsAccept)
        and (defaultBehavior & UserInputDefaultsBehavior.DefaultsNonInteractive)
    ):
        reply = default

    elif (uiMode & UserInterfaceMode.InteractionDialog) and (MainDialog is not None):
        _h, _w = _dialog_size_for(str(question))
        kwargs = {
            "init": (
                default
                if (default is not None) and (defaultBehavior & UserInputDefaultsBehavior.DefaultsPrompt)
                else ""
            ),
            "extra_button": (extraLabel is not None),
            "extra_label": (str(extraLabel) if (extraLabel is not None) else ""),
            "height": _h,
            "width": _w,
        }
        code, reply = MainDialog.inputbox(str(question), **kwargs)
        if (code == Dialog.CANCEL) or (code == Dialog.ESC):
            raise DialogCanceledException(question)
        elif code == Dialog.EXTRA:
            raise DialogBackException(question)
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


def AskForStrings(
    prompt,
    labels,
    defaults=None,
    defaultBehavior=UserInputDefaultsBehavior.DefaultsPrompt,
    uiMode=UserInterfaceMode.InteractionDialog | UserInterfaceMode.InteractionInput,
    clearScreen=False,
    extraLabel=None,
    visibleInputLength=40,
    maxInputLength=1024,
    maxFormHeight=15,
):
    global Dialog
    global MainDialog

    if (defaults is not None) and (
        (defaultBehavior & UserInputDefaultsBehavior.DefaultsAccept)
        and (defaultBehavior & UserInputDefaultsBehavior.DefaultsNonInteractive)
    ):
        reply = defaults

    elif (uiMode & UserInterfaceMode.InteractionDialog) and (MainDialog is not None):
        # Compute label alignment
        label_width = max(len(label) for label in labels) if labels else 0
        label_col = 1
        field_col = label_col + label_width + 2  # 2 spaces between label and field

        # Define field sizing
        field_length = visibleInputLength
        input_length = maxInputLength

        # Build the form elements
        elements = [
            (
                # label text
                label,
                # label position (row, col)
                i + 1,
                label_col,
                # default value or ""
                (
                    defaults[i]
                    if (
                        defaults
                        and (defaults[i] is not None)
                        and (defaultBehavior & UserInputDefaultsBehavior.DefaultsPrompt)
                    )
                    else ""
                ),
                # field position (row, col)
                i + 1,
                field_col,
                # field length (visible width)
                visibleInputLength,
                # input length (max chars)
                maxInputLength,
            )
            for i, label in enumerate(labels)
        ]

        # Compute dialog width and height dynamically
        width = field_col + field_length + 5  # padding at the end for borders and breathing room
        height = len(elements) + 6  # room for prompt and spacing
        form_height = len(elements)  # show all fields at once (or tweak if too tall)

        kwargs = {
            "extra_button": (extraLabel is not None),
            "extra_label": (str(extraLabel) if (extraLabel is not None) else ""),
            "height": height,
            "width": width,
            "form_height": min(form_height, maxFormHeight),
        }

        code, reply = MainDialog.form(prompt, elements, **kwargs)
        if (code == Dialog.CANCEL) or (code == Dialog.ESC):
            raise DialogCanceledException(prompt)
        elif code == Dialog.EXTRA:
            raise DialogBackException(prompt)
        else:
            reply = [x.strip() for x in reply]

    elif uiMode & UserInterfaceMode.InteractionInput:
        print(f"\n{prompt}")

        reply = []
        for i, label in enumerate(labels):
            default = (
                defaults[i]
                if (
                    defaults
                    and (defaults[i] is not None)
                    and (defaultBehavior & UserInputDefaultsBehavior.DefaultsPrompt)
                )
                else None
            )
            value = str(input(f"\n{label}{f' ({default})' if default  else ''}: ")).strip()
            if (
                (len(value) == 0)
                and (default is not None)
                and (defaultBehavior & UserInputDefaultsBehavior.DefaultsAccept)
            ):
                reply.append(default)
            else:
                reply.append(value)

    else:
        raise RuntimeError("No user interfaces available")

    if clearScreen is True:
        ClearScreen()

    return reply


###################################################################################################
# get interactive password (without echoing)
def AskForPassword(
    prompt,
    default=None,
    defaultBehavior=UserInputDefaultsBehavior.DefaultsPrompt,
    uiMode=UserInterfaceMode.InteractionDialog | UserInterfaceMode.InteractionInput,
    clearScreen=False,
    extraLabel=None,
):
    global Dialog
    global MainDialog

    if (default is not None) and (
        (defaultBehavior & UserInputDefaultsBehavior.DefaultsAccept)
        and (defaultBehavior & UserInputDefaultsBehavior.DefaultsNonInteractive)
    ):
        reply = default

    elif (uiMode & UserInterfaceMode.InteractionDialog) and (MainDialog is not None):
        _h, _w = _dialog_size_for(str(prompt))
        kwargs = {
            "insecure": True,
            "extra_button": (extraLabel is not None),
            "extra_label": (str(extraLabel) if (extraLabel is not None) else ""),
            "height": _h,
            "width": _w,
        }
        code, reply = MainDialog.passwordbox(str(prompt), **kwargs)
        if (code == Dialog.CANCEL) or (code == Dialog.ESC):
            raise DialogCanceledException(prompt)
        elif code == Dialog.EXTRA:
            raise DialogBackException(prompt)

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
    extraLabel=None,
):
    global Dialog
    global MainDialog

    validChoices = [x for x in choices if len(x) == 3 and isinstance(x[0], str) and isinstance(x[2], bool)]
    defaulted = next(iter([x for x in validChoices if x[2] is True]), None)

    if (defaultBehavior & UserInputDefaultsBehavior.DefaultsAccept) and (
        defaultBehavior & UserInputDefaultsBehavior.DefaultsNonInteractive
    ):
        reply = defaulted[0] if defaulted is not None else ""

    elif (uiMode & UserInterfaceMode.InteractionDialog) and (MainDialog is not None):
        _h, _w = _dialog_size_for(str(prompt))
        _menu_w = _dialog_menu_width_for(validChoices)
        _w = max(_w, _menu_w)
        kwargs = {
            "choices": validChoices,
            "extra_button": (extraLabel is not None),
            "extra_label": (str(extraLabel) if (extraLabel is not None) else ""),
            "height": max(_h, 12),
            "width": _w,
        }
        code, reply = MainDialog.radiolist(str(prompt), **kwargs)
        if code == Dialog.CANCEL or code == Dialog.ESC:
            raise DialogCanceledException(prompt)
        elif code == Dialog.EXTRA:
            raise DialogBackException(prompt)

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
    extraLabel=None,
):
    global Dialog
    global MainDialog

    validChoices = [x for x in choices if len(x) == 3 and isinstance(x[0], str) and isinstance(x[2], bool)]
    defaulted = [x[0] for x in validChoices if x[2] is True]

    if (defaultBehavior & UserInputDefaultsBehavior.DefaultsAccept) and (
        defaultBehavior & UserInputDefaultsBehavior.DefaultsNonInteractive
    ):
        reply = defaulted

    elif (uiMode & UserInterfaceMode.InteractionDialog) and (MainDialog is not None):
        _h, _w = _dialog_size_for(str(prompt))
        _menu_w = _dialog_menu_width_for(validChoices)
        _w = max(_w, _menu_w)
        kwargs = {
            "choices": validChoices,
            "extra_button": (extraLabel is not None),
            "extra_label": (str(extraLabel) if (extraLabel is not None) else ""),
            "height": max(_h, 12),
            "width": _w,
        }
        code, reply = MainDialog.checklist(str(prompt), **kwargs)
        if code == Dialog.CANCEL or code == Dialog.ESC:
            raise DialogCanceledException(prompt)
        elif code == Dialog.EXTRA:
            raise DialogBackException(prompt)

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
    extraLabel=None,
):
    global Dialog
    global MainDialog

    reply = False

    if (defaultBehavior & UserInputDefaultsBehavior.DefaultsAccept) and (
        defaultBehavior & UserInputDefaultsBehavior.DefaultsNonInteractive
    ):
        reply = True

    elif (uiMode & UserInterfaceMode.InteractionDialog) and (MainDialog is not None):
        _h, _w = _dialog_size_for(str(message))
        kwargs = {
            "extra_button": (extraLabel is not None),
            "extra_label": (str(extraLabel) if (extraLabel is not None) else ""),
            "height": _h,
            "width": _w,
            "no_collapse": True,
        }
        code = MainDialog.msgbox(str(message), **kwargs)
        if (code == Dialog.CANCEL) or (code == Dialog.ESC):
            raise DialogCanceledException(message)
        elif code == Dialog.EXTRA:
            raise DialogBackException(message)
        else:
            reply = True

    else:
        print(f"{message}")
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
    extraLabel=None,
):
    global Dialog
    global MainDialog

    reply = False

    if MainDialog is not None:
        kwargs = {
            "file_path": filePath,
            "file_flags": fileFlags,
            "fd": fileDescriptor,
            "text": text,
            "width": 78,
            "height": 20,
            "extra_button": (extraLabel is not None),
            "extra_label": (str(extraLabel) if (extraLabel is not None) else ""),
        }
        code = MainDialog.programbox(**kwargs)
        if (code == Dialog.CANCEL) or (code == Dialog.ESC):
            raise DialogCanceledException()
        elif code == Dialog.EXTRA:
            raise DialogBackException()
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
def FormatNetBoxSubnetFilter(value):
    if (not value) or (not isinstance(value, str)) or (not value.strip()):
        return ""

    stripSpacePattern = re.compile(r'\s+')
    return ';'.join(
        f"{k.strip()}:{stripSpacePattern.sub('', v)}"
        for item in value.split(';')
        for k, v in [item.split(':', 1) if ':' in item else ('*', item)]
    )


###################################################################################################
def ValidNetBoxSubnetFilter(value):
    if not value.strip():
        return True

    site_entries = [entry.strip() for entry in value.split(';') if entry.strip()]
    cidr_pattern = re.compile(r'^!?([0-9a-fA-F:.]+/\d+)$')

    for entry in site_entries:
        if ':' in entry:
            site_key, cidr_list = entry.split(':', 1)
            site_key = site_key.strip()
        else:
            site_key = '*'
            cidr_list = entry

        if not site_key:  # site name can be '*', any string, or omitted (becomes '*')
            return False

        cidr_entries = [cidr.strip() for cidr in cidr_list.split(',') if cidr.strip()]
        for cidr_entry in cidr_entries:
            match = cidr_pattern.match(cidr_entry)
            if not match:
                return False

            cidr = match.group(1)
            try:
                ipaddress.ip_network(cidr, strict=False)
            except ValueError:
                return False

    return True


###################################################################################################
# attempt dynamic imports, prompting for install via pip if possible
DynImports = defaultdict(lambda: None)


def DoDynamicImport(
    importName,
    pipPkgName,
    interactive=False,
    debug=False,
    silent=True,
):
    global DynImports

    debug = debug and not silent

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
        if not which(pipCmd, debug=debug):
            err, out = run_process([sys.executable, '-m', 'pip', '--version'], debug=debug)
            if out and (err == 0):
                pipCmd = [sys.executable, '-m', 'pip']

        if not silent:
            eprint(f"The {pipPkgName} module is required under Python {platform.python_version()} ({pyExec})")

        if interactive and which(pipCmd, debug=debug):
            if YesOrNo(f"Importing the {pipPkgName} module failed. Attempt to install via {pipCmd}?"):
                installCmd = None

                if (pyPlatform == PLATFORM_LINUX) or (pyPlatform == PLATFORM_MAC):
                    # for linux/mac, we're going to try to figure out if this python is owned by root or the script user
                    if getpwuid and (getpass.getuser() == getpwuid(os.stat(pyExec).st_uid).pw_name):
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
                    if not silent:
                        eprint(f"Installation of {pipPkgName} module apparently succeeded")
                    importlib.reload(site)
                    importlib.invalidate_caches()
                    try:
                        tmpImport = importlib.import_module(importName)
                        if tmpImport:
                            DynImports[importName] = tmpImport
                    except ImportError as e:
                        if not silent:
                            eprint(f"Importing the {importName} module still failed: {e}")
                elif not silent:
                    eprint(f"Installation of {importName} module failed: {out}")

    if not DynImports[importName] and not silent:
        eprint(
            "System-wide installation varies by platform and Python configuration. Please consult platform-specific documentation for installing Python modules."
        )

    return DynImports[importName]


def RequestsDynamic(
    debug=False,
    forceInteraction=False,
    silent=True,
):
    return DoDynamicImport(
        "requests",
        "requests",
        interactive=forceInteraction,
        debug=debug,
        silent=silent,
    )


def YAMLDynamic(
    debug=False,
    forceInteraction=False,
    silent=True,
):
    return DoDynamicImport(
        "ruamel.yaml",
        "ruamel.yaml",
        interactive=forceInteraction,
        debug=debug,
        silent=silent,
    )


def KubernetesDynamic(
    verifySsl=False,
    debug=False,
    forceInteraction=False,
    silent=True,
):
    return DoDynamicImport(
        "kubernetes",
        "kubernetes",
        interactive=forceInteraction,
        debug=debug,
        silent=silent,
    )


def DotEnvDynamic(
    debug=False,
    forceInteraction=False,
    silent=True,
):
    return DoDynamicImport(
        "dotenv",
        "python-dotenv",
        interactive=forceInteraction,
        debug=debug,
        silent=silent,
    )


def get_malcolm_dir():
    """
    Get the absolute path to the Malcolm installation directory.

    This function is designed to work robustly whether run:
    - directly from the Malcolm directory
    - from another directory
    - with sudo or other elevated privileges

    Returns:
        str: The absolute path to the Malcolm directory
    """
    # First, try using the location of this script
    try:
        # Start with the directory containing this script (malcolm_common.py)
        current_dir = os.path.dirname(os.path.abspath(__file__))

        # Go up one level to the Malcolm root directory if in scripts/
        if os.path.basename(current_dir) == "scripts":
            malcolm_dir = os.path.dirname(current_dir)
        else:
            malcolm_dir = current_dir

        # Verify this is indeed the Malcolm directory by checking for key files/directories
        if (
            os.path.isdir(os.path.join(malcolm_dir, "scripts"))
            and os.path.isdir(os.path.join(malcolm_dir, "config"))
            and os.path.isfile(os.path.join(malcolm_dir, "docker-compose.yml"))
        ):
            return malcolm_dir
    except Exception:
        pass

    # If that didn't work, try using the current working directory
    try:
        cwd = os.getcwd()
        if (
            os.path.isdir(os.path.join(cwd, "scripts"))
            and os.path.isdir(os.path.join(cwd, "config"))
            and os.path.isfile(os.path.join(cwd, "docker-compose.yml"))
        ):
            return cwd
    except Exception:
        pass

    # If we're running the script directly, try using its location
    try:
        script_path = os.path.abspath(sys.argv[0])
        script_dir = os.path.dirname(script_path)

        # Check if we're running from the scripts directory
        if os.path.basename(script_dir) == "scripts":
            possible_malcolm_dir = os.path.dirname(script_dir)
            if os.path.isdir(os.path.join(possible_malcolm_dir, "config")) and os.path.isfile(
                os.path.join(possible_malcolm_dir, "docker-compose.yml")
            ):
                return possible_malcolm_dir
    except Exception:
        pass

    # If all else fails, check if there's an environment variable set
    if "MALCOLM_DIR" in os.environ:
        malcolm_dir = os.environ["MALCOLM_DIR"]
        if (
            os.path.isdir(malcolm_dir)
            and os.path.isdir(os.path.join(malcolm_dir, "scripts"))
            and os.path.isdir(os.path.join(malcolm_dir, "config"))
        ):
            return malcolm_dir

    # If we still can't find it, raise an exception
    raise FileNotFoundError(
        "Could not locate the Malcolm directory. Please run this script from within "
        "the Malcolm directory or set the MALCOLM_DIR environment variable."
    )


def get_default_config_dir():
    """Get the default config directory."""
    try:
        return os.path.join(get_malcolm_dir(), "config")
    except FileNotFoundError:
        return os.path.join(os.getcwd(), "config")


def get_malcolm_version():
    """Get the Malcolm version from docker-compose.yml, fall back to MALCOLM_VERSION if not found

    Returns:
        str: The Malcolm version string, or MALCOLM_VERSION if not found
    """

    def parse_calver(tag):
        try:
            return tuple(int(p) for p in tag.split("-", 1)[0].split("+", 1)[0].split(".")[:3])
        except ValueError:
            return None

    def get_highest_calver(tags):
        parsed = [parse_calver(tag) for tag in tags]
        valid = [p for p in parsed if p is not None]
        if not valid:
            return None
        highest = max(valid)
        return ".".join(str(x) for x in highest)

    result = MALCOLM_VERSION

    if yamlImported := YAMLDynamic():
        try:
            try:
                compose_file_name = os.path.join(get_malcolm_dir(), "docker-compose.yml")
            except FileNotFoundError:
                compose_file_name = os.path.join(os.getcwd(), "docker-compose.yml")
            if os.path.isfile(compose_file_name):
                with open(compose_file_name, 'r') as f:
                    compose_data = yamlImported.YAML(typ='safe', pure=True).load(f)
                    image_tags = []
                    for service_name, service_def in compose_data.get("services", {}).items():
                        image = service_def.get("image")
                        if image and ":" in image:
                            image_tags.append(image.rsplit(":", 1)[1])
                    result = get_highest_calver(image_tags)
        except Exception as e:
            eprint(f'Error deciphering docker-compose.yml: {e}')

    return result


###################################################################################################
# do the required auth files for Malcolm exist?
def AuthFileCheck(fileName, allowEmpty=False):
    try:
        return os.path.isfile(fileName) and (allowEmpty or (os.path.getsize(fileName) > 0))
    except Exception as e:
        return False


def MalcolmAuthFilesExist(configDir=None, run_profile=PROFILE_MALCOLM):
    configDirToCheck = (
        configDir if configDir is not None and os.path.isdir(configDir) else os.path.join(MalcolmPath, 'config')
    )
    return (
        (
            (run_profile == PROFILE_HEDGEHOG)
            or (
                AuthFileCheck(os.path.join(MalcolmPath, os.path.join('nginx', 'htpasswd')))
                and AuthFileCheck(os.path.join(MalcolmPath, os.path.join('nginx', 'nginx_ldap.conf')), allowEmpty=True)
                and AuthFileCheck(
                    os.path.join(MalcolmPath, os.path.join('nginx', os.path.join('certs', 'cert.pem'))), allowEmpty=True
                )
                and AuthFileCheck(
                    os.path.join(MalcolmPath, os.path.join('nginx', os.path.join('certs', 'key.pem'))), allowEmpty=True
                )
                and AuthFileCheck(os.path.join(configDirToCheck, 'netbox-secret.env'))
                and AuthFileCheck(os.path.join(configDirToCheck, 'postgres.env'))
                and AuthFileCheck(os.path.join(configDirToCheck, 'auth.env'))
            )
        )
        and AuthFileCheck(os.path.join(configDirToCheck, 'redis.env'))
        and AuthFileCheck(os.path.join(MalcolmPath, '.opensearch.primary.curlrc'))
    )


###################################################################################################
# determine if a YAML file looks like a docker-compose.yml file or a kubeconfig file
def DetermineYamlFileFormat(inputFileName):
    result = OrchestrationFramework.UNKNOWN

    if yamlImported := YAMLDynamic():
        try:
            with open(inputFileName, 'r') as cf:
                orchestrationYaml = yamlImported.YAML(typ='safe', pure=True).load(cf)

            if isinstance(orchestrationYaml, dict):
                if any(key in orchestrationYaml for key in ('apiVersion', 'clusters', 'contexts', 'kind')):
                    result = OrchestrationFramework.KUBERNETES
                elif 'services' in orchestrationYaml:
                    result = OrchestrationFramework.DOCKER_COMPOSE

        except Exception as e:
            eprint(f'Error deciphering {inputFileName}: {e}')

    return result


###################################################################################################
def LoadYaml(inputFileName):
    result = None
    if inputFileName and os.path.isfile(inputFileName):
        if yamlImported := YAMLDynamic():
            with open(inputFileName, 'r') as f:
                inYaml = yamlImported.YAML(typ='rt')
                inYaml.boolean_representation = ['false', 'true']
                inYaml.emitter.alt_null = None
                inYaml.preserve_quotes = True
                inYaml.representer.ignore_aliases = lambda *args: True
                inYaml.width = sys.maxsize
                result = inYaml.load(f)
    return result


###################################################################################################
def LoadYamlOrJson(inputFileName):
    result = None
    fmt = SettingsFileFormat.UNKNOWN

    if inputFileName and os.path.isfile(inputFileName):
        extension = Path(inputFileName).suffix.lower()
        if extension in [".yml", ".yaml"]:
            if result := LoadYaml(inputFileName):
                fmt = SettingsFileFormat.YAML
        elif extension == ".json":
            with open(inputFileName, "r") as f:
                if result := json.load(f):
                    fmt = SettingsFileFormat.JSON
        else:
            # try to auto-detect by parsing content
            with open(inputFileName, "r") as f:
                content = f.read().strip()
                if content.startswith("{"):
                    if result := json.loads(content):
                        fmt = SettingsFileFormat.JSON
            if not result:
                if result := LoadYaml(inputFileName):
                    fmt = SettingsFileFormat.YAML

    return result or {}, fmt


###################################################################################################
def PopLine(fileName, count=1):
    result = []
    with open(fileName, 'r+') as f:
        for i in range(0, count):
            result.append(f.readline())
        data = f.read()
        f.seek(0)
        f.write(data)
        f.truncate()
    return result if (len(result) != 1) else result[0]


###################################################################################################
def DumpYaml(data, outputFileName):
    if data is not None:
        if yamlImported := YAMLDynamic():
            with open(outputFileName, 'w') as outfile:
                outYaml = yamlImported.YAML(typ='rt')
                outYaml.boolean_representation = ['false', 'true']
                outYaml.preserve_quotes = False
                outYaml.representer.ignore_aliases = lambda *args: True
                outYaml.representer.add_representer(type(None), NullRepresenter())
                outYaml.version = YAML_VERSION
                outYaml.width = sys.maxsize
                outYaml.dump(data, outfile)
            # ruamel puts the YAML version header (2 lines) at the top, which docker-compose
            #   doesn't like, so we need to remove it
            PopLine(outputFileName, 2)


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
        eprint(f"Download of {url} to {local_filename} {'succeeded' if fExists else 'failed'} ({sizeof_fmt(fSize)})")
    return fExists and (fSize > 0)


###################################################################################################
# test a connection to an HTTP/HTTPS server
def test_http_connection(
    protocol=None,
    host=None,
    port=None,
    uri=None,
    url=None,
    username=None,
    password=None,
    ssl_verify="full",
    user_agent="malcolm",
):
    status = 400
    message = "Connection error"

    # If URL is provided, parse it and override host/port/protocol/uri
    if url:
        parsed = urlparse(url)
        protocol = parsed.scheme
        host = parsed.hostname
        port = parsed.port
        uri = parsed.path.lstrip("/")
        if port is None:
            port = 443 if protocol == "https" else 80

    # Set up the connection
    c = None
    if protocol.lower() == "https":
        if (isinstance(ssl_verify, bool) and ssl_verify) or (
            isinstance(ssl_verify, str) and (ssl_verify.lower() == "full")
        ):
            c = HTTPSConnection(host, port=port)
        else:
            c = HTTPSConnection(host, port=port, context=ssl._create_unverified_context())
    elif protocol.lower() == "http":
        c = HTTPConnection(host, port=port)

    if c:
        try:
            headers = {'User-agent': user_agent}
            if username and password:
                headers['Authorization'] = 'Basic %s' % b64encode(f"{username}:{password}".encode()).decode("ascii")
            c.request('GET', f'/{str(uri)}', headers=headers)
            res = c.getresponse()
            status = res.status
            message = res.reason
        except Exception as e:
            message = f"Error: {e}"

    return status, message


###################################################################################################
# process log line from containers' output

URL_USER_PASS_REGEX = re.compile(r'(\w+://[^/]+?:)[^/]+?(@[^/]+)')

# noisy logs (a lot of it is NGINX logs from health checks)
LOG_IGNORE_REGEX = re.compile(
    r"""
.+(
    deprecated
  | "GET\s+/\s+HTTP/1\.\d+"\s+200\s+-
  | "netbox"\s+application\s+started
  | (async|output)\.go.+(reset\s+by\s+peer|Connecting\s+to\s+backoff|backoff.+established$)
  | (Error\s+during\s+file\s+comparison|File\s+was\s+renamed):\s+/zeek/live/logs/
  | (GET|POST)\s+/(fields|get|valueActions|views|fieldActions)\b.+bytes\s+[\d\.]+\s+ms
  | (GET|POST|PATCH|DELETE)\s+/netbox/.+HTTP/[\d\.]+.+\b20[\d]\b
  | (relation|SELECT)\s+"django_content_type"
  | /(opensearch-dashboards|dashboards|kibana)/(api/ui_metric/report|internal/search/(es|opensearch))
  | /_ns_/nstest\.html
  | /proc/net/tcp6:\s+no\s+such\s+file\s+or\s+directory
  | /usr/share/logstash/x-pack/lib/filters/geoip/database_manager
  | \[notice\].+app\s+process\s+\d+\s+exited\s+with\s+code\s+0\b
  | \b(d|es)?stats\.json
  | \b1.+GET\s+/\s+.+401.+curl
  | \bGET.+\b302\s+30\b
  | \d+\s+changes\s+in\s+\d+\s+seconds\.\s+Saving
  | _cat/indices
  | Background\s+saving\s+started
  | Background\s+saving\s+terminated\s+with\s+success
  | branding.*config\s+is\s+not\s+found\s+or\s+invalid
  | but\s+there\s+are\s+no\s+living\s+connections
  | Cleaning\s+registries\s+for\s+queue:
  | Closing\s+because\s+(close_renamed|close_eof|close_inactive)
  | Connecting\s+to\s+backoff
  | Could\s+not\s+assign\s+group.+to\s+remotely-authenticated\s+user.+Group\s+not\s+found
  | curl.+localhost.+GET\s+/api/status\s+200
  | DB\s+saved\s+on\s+disk
  | DEPRECATION
  | descheduling\s+job\s*id
  | DON'T\s+DO\s+IT.*bad\s+idea
  | Error\s+during\s+file\s+comparison:.*no\s+such\s+file
  | eshealth
  | esindices/list
  | executing\s+attempt_(transition|set_replica_count)\s+for
  | failed\s+to\s+get\s+tcp6?\s+stats\s+from\s+/proc
  | Failure\s+no\s+such\s+index\s+\[\.opendistro_security\]
  | Falling\s+back\s+to\s+single\s+shard\s+assignment
  | Fork\s+CoW\s+for\s+RDB
  | GET\s+/(_cat/health|api/status|sessions2-|arkime_\w+).+HTTP/[\d\.].+\b200\b
  | GET\s+/\s+.+\b200\b.+ELB-HealthChecker
  | GET\s+/wise/+stats
  | i:\s+pcap:\s+read\s+\d+\s+file
  | Info:\s+checksum:\s+No\s+packets\s+with\s+invalid\s+checksum,\s+assuming\s+checksum\s+offloading\s+is\s+NOT\s+used
  | Info:\s+logopenfile:\s+eve-log\s+output\s+device\s+\(regular\)\s+initialized:\s+eve\.json
  | Info:\s+pcap:\s+(Starting\s+file\s+run|pcap\s+file)
  | Info:\s+unix-socket:
  | kube-probe/
  | loaded\s+config\s+'/etc/netbox/config/
  | LOG:\s+checkpoint\s+(complete|starting)\
  | No\s+active\s+configuration\s+revision\s+found\s+-\s+falling\s+back\s+to\s+most\s+recent
  | Notice:\s+pcap:\s+read\s+(\d+)\s+file
  | opensearch.*has\s+insecure\s+file\s+permissions
  | (POST|PUT)\s+/(arkime_\w+)(/\w+)?/_(d?stat|doc|search).+HTTP/[\d\.].+\b20[01]\b
  | POST\s+/_bulk\s+HTTP/[\d\.].+\b20[01]\b
  | POST\s+/server/php/\s+HTTP/\d+\.\d+"\s+\d+\s+\d+.*:8443/
  | POST\s+/wise/+get.+\b200\b
  | POST\s+HTTP/[\d\.].+\b200\b
  | reaped\s+unknown\s+pid
  | redis.*(changes.+seconds.+Saving|Background\s+saving\s+(started|terminated)|DB\s+saved\s+on\s+disk|Fork\s+CoW)
  | remov(ed|ing)\s+(old\s+file|dead\s+symlink|empty\s+directory)
  | retry\.go.+(send\s+unwait|done$)
  | running\s+full\s+sweep
  | running\s+without\s+any\s+HTTP\s+authentication\s+checking
  | saved_objects
  | scheduling\s+job\s*id.+opendistro-ism
  | SSL/TLS\s+verifications\s+disabled
  | Successfully\s+handled\s+GET\s+request\s+for\s+'/'
  | Test\s+run\s+complete.*:failed=>0,\s*:errored=>0\b
  | throttling\s+index
  | unix-socket:.*(pcap-file\.tenant-id\s+not\s+set|Marking\s+current\s+task\s+as\s+done|Resetting\s+engine\s+state)
  | update_mapping
  | updating\s+number_of_replicas
  | use_field_mapping
  | Using\s+geoip\s+database
  | Warning:\s+app-layer-
  | you\s+may\s+need\s+to\s+run\s+securityadmin
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


##################################################################################################
def InstallerDisplayMessage(
    message,
    defaultBehavior=UserInputDefaultsBehavior.DefaultsPrompt | UserInputDefaultsBehavior.DefaultsAccept,
    uiMode=UserInterfaceMode.InteractionInput | UserInterfaceMode.InteractionDialog,
    extraLabel=None,
):
    """
    Wrapper around DisplayMessage for installation-specific use cases.
    This provides consistent behavior across TUI and GUI installers.
    """
    return DisplayMessage(
        message,
        defaultBehavior=defaultBehavior,
        uiMode=uiMode,
        extraLabel=extraLabel,
    )


# Add these installer wrapper functions near existing similar functions
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
    """
    Wrapper around YesOrNo for installation-specific use cases.
    This provides consistent behavior across TUI and GUI installers.
    """
    return YesOrNo(
        question,
        default=default,
        defaultBehavior=defaultBehavior,
        uiMode=uiMode,
        yesLabel=yesLabel,
        noLabel=noLabel,
        extraLabel=extraLabel,
    )


def InstallerAskForString(
    question,
    default=None,
    forceInteraction=False,
    defaultBehavior=UserInputDefaultsBehavior.DefaultsPrompt | UserInputDefaultsBehavior.DefaultsAccept,
    uiMode=UserInterfaceMode.InteractionInput | UserInterfaceMode.InteractionDialog,
    extraLabel=None,
):
    """
    Wrapper around AskForString for installation-specific use cases.
    This provides consistent behavior across TUI and GUI installers.
    """
    return AskForString(
        question,
        default=default,
        defaultBehavior=defaultBehavior,
        uiMode=uiMode,
        extraLabel=extraLabel,
    )


def InstallerAskForPassword(
    question,
    default=None,
    forceInteraction=False,
    defaultBehavior=UserInputDefaultsBehavior.DefaultsPrompt | UserInputDefaultsBehavior.DefaultsAccept,
    uiMode=UserInterfaceMode.InteractionInput | UserInterfaceMode.InteractionDialog,
    extraLabel=None,
):
    """
    Wrapper for password input, ensuring masked entry.
    Consistent behavior for TUI (passwordbox) and GUI (passwordbox).
    """
    return AskForPassword(
        question,
        default=default,
        defaultBehavior=defaultBehavior,
        uiMode=uiMode,
        extraLabel=extraLabel,
    )


def InstallerChooseOne(
    prompt,
    choices=[],
    forceInteraction=False,
    defaultBehavior=UserInputDefaultsBehavior.DefaultsPrompt | UserInputDefaultsBehavior.DefaultsAccept,
    uiMode=UserInterfaceMode.InteractionInput | UserInterfaceMode.InteractionDialog,
    extraLabel=None,
):
    """
    Wrapper around ChooseOne for installation-specific use cases.
    This provides consistent behavior across TUI and GUI installers.
    """
    return ChooseOne(
        prompt,
        choices=choices,
        defaultBehavior=defaultBehavior,
        uiMode=uiMode,
        extraLabel=extraLabel,
    )


def InstallerChooseMultiple(
    prompt,
    choices=[],
    forceInteraction=False,
    defaultBehavior=UserInputDefaultsBehavior.DefaultsPrompt | UserInputDefaultsBehavior.DefaultsAccept,
    uiMode=UserInterfaceMode.InteractionInput | UserInterfaceMode.InteractionDialog,
    extraLabel=None,
):
    """
    Wrapper around ChooseMultiple for installation-specific use cases.
    This provides consistent behavior across TUI and GUI installers.
    """
    return ChooseMultiple(
        prompt,
        choices=choices,
        defaultBehavior=defaultBehavior,
        uiMode=uiMode,
        extraLabel=extraLabel,
    )


###################################################################################################
# System-information helpers (used by installer logic)


def _total_memory_bytes() -> int:
    """Return total physical memory in bytes (Linux/BSD/Darwin portable)."""
    result = 0  # unknown
    try:
        if plat := sys.platform:
            if plat.startswith('linux'):
                with open("/proc/meminfo", "r", encoding="utf-8") as meminfo:
                    for line in meminfo:
                        if line.startswith("MemTotal:"):
                            # value is in kB
                            result = int(line.split()[1]) * 1024
            elif plat.startswith('darwin') and which('sysctl'):
                err, out = run_process(['sysctl', '-n', 'hw.memsize'], stderr=False)
                if (err == 0) and (len(out) > 0):
                    result = int(out[0].strip())
    except Exception:
        pass

    # Fallback that works on many *nix via sysconf
    if not result and hasattr(os, "sysconf"):
        try:
            result = int(os.sysconf('SC_PAGE_SIZE')) * int(os.sysconf('SC_PHYS_PAGES'))
        except Exception:
            pass

    return result


def total_memory_gb() -> int:
    """Return total memory in whole GiB (rounded down)."""
    return max(1, _total_memory_bytes() // (1024**3))


def cpu_cores() -> int:
    """Return logical CPU count, falling back to 1."""
    cpu_count = os.cpu_count() or 0

    if (not cpu_count) and hasattr(os, "sysconf"):
        try:
            cpu_count = int(os.sysconf('SC_NPROCESSORS_ONLN'))
        except:
            cpu_count = 0

    if (not cpu_count) and (plat := sys.platform):
        try:
            if plat.startswith('linux'):
                with open('/proc/cpuinfo') as f:
                    cpu_count = sum(1 for line in f if line.startswith('processor'))

            elif plat.startswith('darwin') and which('sysctl'):
                err, out = self.run_process(['sysctl', '-n', 'hw.ncpu'], stderr=False)
                if (err == 0) and (len(out) > 0):
                    cpu_count = int(out[0].strip())
        except:
            cpu_count = 0

    return max(1, cpu_count or 1)


def disk_free_bytes(path: str = "/") -> int:
    """Return free bytes on the filesystem that contains *path*."""
    try:
        return shutil.disk_usage(path).free
    except (OSError, FileNotFoundError):
        return 0


# ------------------------------------------------------------------
# Heuristic defaults the legacy installer used
# ------------------------------------------------------------------


def suggest_os_memory(total_gb: Optional[int] = None) -> str:
    """Return OpenSearch heap suggestion (e.g., "24g")."""
    if total_gb is None:
        total_gb = total_memory_gb()
    # Rough rule: half of RAM, capped at 31 GiB, min 4 GiB
    heap_gb = max(4, min(31, total_gb // 2))
    return f"{heap_gb}g"


def suggest_ls_memory(total_gb: Optional[int] = None) -> str:
    """Return Logstash heap suggestion (e.g., "3g")."""
    if total_gb is None:
        total_gb = total_memory_gb()
    # Rough rule: 1/8th of RAM, capped at 8 GiB, min 1 GiB, rounded.
    heap_gb = max(1, min(8, max(1, total_gb // 8)))
    return f"{heap_gb}g"


def suggest_ls_workers(cores: Optional[int] = None) -> int:
    """Return recommended Logstash worker count."""
    if cores is None:
        cores = cpu_cores()
    # Legacy rule: half the logical cores, capped at 6, min 1
    return max(1, min(6, cores // 2))


# ------------------------------------------------------------------
# Snapshot the system facts at import-time so they're reusable anywhere.
# ------------------------------------------------------------------


# Detect system architecture for container images
def get_system_image_architecture():
    """Detect system architecture and return appropriate ImageArchitecture enum."""
    raw_platform = platform.machine().lower()
    if raw_platform in ("aarch64", "arm64"):
        return ImageArchitecture.ARM64
    else:
        return ImageArchitecture.AMD64


# Platform detection utilities


def get_platform_name() -> str:
    """Determine the current host platform name.

    Returns:
        Platform name string: 'linux', 'macos', 'windows', or 'unknown'
    """
    plat = sys.platform
    if plat.startswith("linux"):
        return "linux"
    elif plat == "darwin":
        return "macos"
    elif plat.startswith("win"):
        return "windows"
    else:
        return "unknown"


def get_distro_info() -> tuple[Optional[str], Optional[str], Optional[str], Optional[str]]:
    distro = None
    codename = None
    ubuntu_codename = None
    release = None
    plat = get_platform_name()

    if plat == "linux":
        os_release_info = {}

        # if the distro library can do it for us, prefer that
        if distro_lib := DoDynamicImport("distro", "distro"):
            try:
                distro = distro_lib.id()
                codename = distro_lib.codename()
                release = distro_lib.version()
                os_release_info = distro_lib.os_release_info()
            except Exception:
                pass

        # check /etc/os-release values
        if not os_release_info:
            if os.path.isfile('/etc/os-release'):
                with open("/etc/os-release", 'r') as f:
                    for line in f:
                        try:
                            k, v = line.rstrip().split("=", 1)
                            os_release_info[k.lower()] = v.strip('"')
                        except Exception:
                            pass

        if os_release_info:
            if not distro:
                if os_release_info.get('id'):
                    distro = os_release_info['id'].lower().split()[0]
                elif os_release_info.get('name'):
                    distro = os_release_info['name'].lower().split()[0]

            if not codename:
                if os_release_info.get('version_codename'):
                    codename = os_release_info['version_codename'].lower().split()[0]
                elif os_release_info.get('codename'):
                    codename = os_release_info['codename'].lower().split()[0]

            if (not release) and os_release_info.get('version_id'):
                release = os_release_info['version_id'].lower().split()[0]

            if not ubuntu_codename:
                if os_release_info.get('ubuntu_version_codename'):
                    ubuntu_codename = os_release_info['ubuntu_version_codename'].lower().split()[0]
                elif os_release_info.get('ubuntu_codename'):
                    ubuntu_codename = os_release_info['ubuntu_codename'].lower().split()[0]
                elif codename and (distro == PLATFORM_LINUX_UBUNTU):
                    ubuntu_codename = codename

        # try lsb_release
        if (not all([distro, codename, release])) and which('lsb_release'):
            if not distro:
                err, out = run_process(['lsb_release', '-is'], stderr=False)
                if (err == 0) and out:
                    distro = out[0].lower()

            if not codename:
                err, out = run_process(['lsb_release', '-cs'], stderr=False)
                if (err == 0) and out:
                    codename = out[0].lower()

            if not release:
                err, out = run_process(['lsb_release', '-rs'], stderr=False)
                if (err == 0) and out:
                    release = out[0].lower()

        # try release-specific files
        if not distro:
            if distro_file := next(
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
            ):
                with open(distro_file, 'r') as f:
                    distro_vals = f.read().lower().split()
                    distro_nums = [x for x in distro_vals if x[0].isdigit()]
                    distro = distro_vals[0]
                    if (not release) and (len(distro_nums) > 0):
                        release = distro_nums[0]

    if not distro:
        distro = plat

    return distro, codename, ubuntu_codename, release


def IsMalcolmISOInstalled():
    result = False
    if os.path.isfile(MalcolmISOOsInfoFile):
        os_info = {}
        with open(MalcolmISOOsInfoFile, 'r') as f:
            for line in f:
                try:
                    k, v = line.rstrip().split("=", 1)
                    os_info[k.lower()] = v.strip('"')
                except Exception:
                    pass
        result = (os_info.get('variant_id', '').lower() in (PROFILE_HEDGEHOG, PROFILE_MALCOLM)) and any(
            os_info.get('variant', '').lower().startswith(p) for p in (PROFILE_HEDGEHOG, PROFILE_MALCOLM)
        )

    return result


_rec_puid_pgid = GetUidGidFromEnv()
if (int(_rec_puid_pgid['PUID']) == 0) or (int(_rec_puid_pgid['PGID']) == 0):
    _rec_puid_pgid = GetNonRootUidGid(
        reference_path=get_main_script_path(), fallback_uid=_rec_puid_pgid['PUID'], fallback_gid=_rec_puid_pgid['PGID']
    )
_distro_info = get_distro_info()

# Snapshot of system facts and derived recommendations
SYSTEM_INFO: dict[str, object] = {
    "image_architecture": get_system_image_architecture(),
    "total_mem_gb": total_memory_gb(),
    "cpu_cores": cpu_cores(),
    "uid": os.getuid(),
    "gid": os.getgid(),
    "recommended_nonroot_uid": int(_rec_puid_pgid['PUID']),
    "recommended_nonroot_gid": int(_rec_puid_pgid['PGID']),
    "platform": platform.system(),
    "platform_name": get_platform_name(),
    "distro": _distro_info[0],
    "codename": _distro_info[1],
    "ubuntu_codename": _distro_info[2],
    "release": _distro_info[3],
}

# Derived recommendations appended to dict
SYSTEM_INFO["suggested_os_memory"] = suggest_os_memory(SYSTEM_INFO["total_mem_gb"])
SYSTEM_INFO["suggested_ls_memory"] = suggest_ls_memory(SYSTEM_INFO["total_mem_gb"])
SYSTEM_INFO["suggested_ls_workers"] = suggest_ls_workers(SYSTEM_INFO["cpu_cores"])
SYSTEM_INFO["malcolm_iso_install"] = IsMalcolmISOInstalled()

__all__ = [
    "SYSTEM_INFO",
    "get_platform_name",
    "total_memory_gb",
    "cpu_cores",
    "disk_free_bytes",
    "suggest_os_memory",
    "suggest_ls_memory",
    "suggest_ls_workers",
]

if __name__ == "__main__":
    print(SYSTEM_INFO)
