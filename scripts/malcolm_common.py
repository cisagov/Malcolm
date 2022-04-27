#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2022 Battelle Energy Alliance, LLC.  All rights reserved.

import contextlib
import getpass
import importlib
import json
import os
import platform
import re
import sys
import time

from collections import defaultdict
from enum import IntFlag, auto

try:
    from pwd import getpwuid
except ImportError:
    getpwuid = None
from subprocess import PIPE, STDOUT, Popen, CalledProcessError

try:
    from dialog import Dialog

    MainDialog = Dialog(dialog='dialog', autowidgetsize=True)
except ImportError:
    Dialog = None
    MainDialog = None

###################################################################################################
ScriptPath = os.path.dirname(os.path.realpath(__file__))
MalcolmPath = os.path.abspath(os.path.join(ScriptPath, os.pardir))
MalcolmTmpPath = os.path.join(MalcolmPath, '.tmp')

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

###################################################################################################
# chdir to directory as context manager, returning automatically
@contextlib.contextmanager
def pushd(directory):
    prevDir = os.getcwd()
    os.chdir(directory)
    try:
        yield
    finally:
        os.chdir(prevDir)


###################################################################################################
# print to stderr
def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)


###################################################################################################
def EscapeAnsi(line):
    ansiEscape = re.compile(r'(?:\x1B[@-_]|[\x80-\x9F])[0-?]*[ -/]*[@-~]')
    return ansiEscape.sub('', line)


###################################################################################################
# attempt to clear the screen
def ClearScreen():
    try:
        os.system("clear" if platform.system() != PLATFORM_WINDOWS else "cls")
    except Exception as e:
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
                except ValueError as e:
                    pass
            elif (defaultBehavior & UserInputDefaultsBehavior.DefaultsAccept) and (default is not None):
                break

    else:
        raise RuntimeError("No user interfaces available")

    if (len(reply) == 0) and (defaultBehavior & UserInputDefaultsBehavior.DefaultsAccept):
        reply = "y" if (default is not None) and str2bool(default) else "n"

    if clearScreen == True:
        ClearScreen()

    try:
        return str2bool(reply)
    except ValueError as e:
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

    if clearScreen == True:
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

    if clearScreen == True:
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
    defaulted = next(iter([x for x in validChoices if x[2] == True]), None)

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

    if clearScreen == True:
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
    defaulted = [x[0] for x in validChoices if x[2] == True]

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
        print(f"0: NONE")
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

    if clearScreen == True:
        ClearScreen()

    return reply


###################################################################################################
# convenient boolean argument parsing
def str2bool(v):
    if isinstance(v, bool):
        return v
    elif isinstance(v, str):
        if v.lower() in ("yes", "true", "t", "y", "1"):
            return True
        elif v.lower() in ("no", "false", "f", "n", "0"):
            return False
        else:
            raise ValueError("Boolean value expected")
    else:
        raise ValueError("Boolean value expected")


###################################################################################################
# determine if a program/script exists and is executable in the system path
def Which(cmd, debug=False):
    result = any(os.access(os.path.join(path, cmd), os.X_OK) for path in os.environ["PATH"].split(os.pathsep))
    if debug:
        eprint(f"Which {cmd} returned {result}")
    return result


###################################################################################################
# nice human-readable file sizes
def SizeHumanFormat(num, suffix='B'):
    for unit in ['', 'Ki', 'Mi', 'Gi', 'Ti', 'Pi', 'Ei', 'Zi']:
        if abs(num) < 1024.0:
            return f"{num:3.1f}{unit}{suffix}"
        num /= 1024.0
    return f"{num:.1f}{'Yi'}{suffix}"


###################################################################################################
# is this string valid json? if so, load and return it
def LoadStrIfJson(jsonStr):
    try:
        return json.loads(jsonStr)
    except ValueError as e:
        return None


###################################################################################################
# run command with arguments and return its exit code, stdout, and stderr
def check_output_input(*popenargs, **kwargs):

    if 'stdout' in kwargs:
        raise ValueError('stdout argument not allowed, it will be overridden')

    if 'stderr' in kwargs:
        raise ValueError('stderr argument not allowed, it will be overridden')

    if 'input' in kwargs and kwargs['input']:
        if 'stdin' in kwargs:
            raise ValueError('stdin and input arguments may not both be used')
        inputdata = kwargs['input']
        kwargs['stdin'] = PIPE
    else:
        inputdata = None
    kwargs.pop('input', None)

    process = Popen(*popenargs, stdout=PIPE, stderr=PIPE, **kwargs)
    try:
        output, errput = process.communicate(inputdata)
    except:
        process.kill()
        process.wait()
        raise

    retcode = process.poll()

    return retcode, output, errput


###################################################################################################
# run command with arguments and return its exit code, stdout, and stderr
def run_process(
    command, stdout=True, stderr=True, stdin=None, retry=0, retrySleepSec=5, cwd=None, env=None, debug=False
):

    retcode = -1
    output = []

    try:
        # run the command
        retcode, cmdout, cmderr = check_output_input(
            command, input=stdin.encode() if stdin else stdin, cwd=cwd, env=env
        )

        # split the output on newlines to return a list
        if stderr and (len(cmderr) > 0):
            output.extend(cmderr.decode(sys.getdefaultencoding()).split('\n'))
        if stdout and (len(cmdout) > 0):
            output.extend(cmdout.decode(sys.getdefaultencoding()).split('\n'))

    except (FileNotFoundError, OSError, IOError) as e:
        if stderr:
            output.append(f"Command {command} not found or unable to execute")

    if debug:
        eprint(f"{command}({stdin[:80] + bool(stdin[80:]) * '...' if stdin else ''}) returned {retcode}: {output}")

    if (retcode != 0) and retry and (retry > 0):
        # sleep then retry
        time.sleep(retrySleepSec)
        return run_process(command, stdout, stderr, stdin, retry - 1, retrySleepSec, cwd, env, debug)
    else:
        return retcode, output


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
        except ImportError as e:
            pass

        # see if we can help out by installing the module

        pyPlatform = platform.system()
        pyExec = sys.executable
        pipCmd = "pip3"
        if not Which(pipCmd, debug=debug):
            pipCmd = "pip"

        eprint(f"The {pipPkgName} module is required under Python {platform.python_version()} ({pyExec})")

        if interactive and Which(pipCmd, debug=debug):
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


###################################################################################################
# do the required auth files for Malcolm exist?
def MalcolmAuthFilesExist():
    return (
        os.path.isfile(os.path.join(MalcolmPath, os.path.join('nginx', 'htpasswd')))
        and os.path.isfile(os.path.join(MalcolmPath, os.path.join('nginx', 'nginx_ldap.conf')))
        and os.path.isfile(os.path.join(MalcolmPath, os.path.join('nginx', os.path.join('certs', 'cert.pem'))))
        and os.path.isfile(os.path.join(MalcolmPath, os.path.join('nginx', os.path.join('certs', 'key.pem'))))
        and os.path.isfile(os.path.join(MalcolmPath, os.path.join('htadmin', 'config.ini')))
        and os.path.isfile(os.path.join(MalcolmPath, 'auth.env'))
    )


###################################################################################################
# download to file
def DownloadToFile(url, local_filename, debug=False):
    r = RequestsDynamic.get(url, stream=True, allow_redirects=True)
    with open(local_filename, 'wb') as f:
        for chunk in r.iter_content(chunk_size=1024):
            if chunk:
                f.write(chunk)
    fExists = os.path.isfile(local_filename)
    fSize = os.path.getsize(local_filename)
    if debug:
        eprint(
            f"Download of {url} to {local_filename} {'succeeded' if fExists else 'failed'} ({SizeHumanFormat(fSize)})"
        )
    return fExists and (fSize > 0)


###################################################################################################
# recursively remove empty subfolders
def RemoveEmptyFolders(path, removeRoot=True):
    if not os.path.isdir(path):
        return

    files = os.listdir(path)
    if len(files):
        for f in files:
            fullpath = os.path.join(path, f)
            if os.path.isdir(fullpath):
                RemoveEmptyFolders(fullpath)

    files = os.listdir(path)
    if len(files) == 0 and removeRoot:
        try:
            os.rmdir(path)
        except:
            pass
