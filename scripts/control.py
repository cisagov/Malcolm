#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2025 Battelle Energy Alliance, LLC.  All rights reserved.

import sys

sys.dont_write_bytecode = True

import argparse
import datetime
import errno
import fileinput
import getpass
import glob
import gzip
import json
import logging
import os
import platform
import re
import secrets
import shutil
import signal
import stat
import string
import tarfile
import tempfile
import time

# Add the project root directory to the Python path
script_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.abspath(os.path.join(script_dir, ".."))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from malcolm_constants import (
    CONTAINER_RUNTIME_KEY,
    PROFILE_HEDGEHOG,
    PROFILE_KEY,
    PROFILE_MALCOLM,
    PLATFORM_WINDOWS,
)

from malcolm_common import (
    AskForPassword,
    AskForString,
    BoundPath,
    ChooseOne,
    ClearScreen,
    DetermineYamlFileFormat,
    DisplayMessage,
    DisplayProgramBox,
    DotEnvDynamic,
    EnvValue,
    GetUidGidFromEnv,
    KubernetesDynamic,
    LocalPathForContainerBindMount,
    MainDialog,
    MalcolmAuthFilesExist,
    GetMalcolmPath,
    MalcolmTmpPath,
    OrchestrationFramework,
    OrchestrationFrameworksSupported,
    posInt,
    ProcessLogLine,
    ScriptPath,
    UpdateEnvFiles,
    UserInputDefaultsBehavior,
    YAMLDynamic,
    YesOrNo,
)

from malcolm_utils import (
    CountUntilException,
    deep_get,
    dictsearch,
    flatten,
    EscapeAnsi,
    EscapeForCurl,
    get_iterable,
    get_primary_ip,
    LoadStrIfJson,
    log_level_is_debug,
    ParseCurlFile,
    pushd,
    RemoveEmptyFolders,
    rmtree_except,
    run_process,
    same_file_or_dir,
    set_logging,
    get_verbosity_env_var_count,
    str2bool,
    touch,
    which,
)

from malcolm_kubernetes import (
    CheckPersistentStorageDefs,
    get_node_hostnames_and_ips,
    GetPodNamesForService,
    PodExec,
    PrintNodeStatus,
    PrintPodStatus,
    REQUIRED_VOLUME_OBJECTS,
    StartMalcolm,
    StopMalcolm,
)

from base64 import b64encode
from collections import defaultdict, namedtuple
from subprocess import PIPE, STDOUT, DEVNULL, Popen, TimeoutExpired
from urllib.parse import urlparse
from itertools import chain, groupby

try:
    from contextlib import nullcontext
except ImportError:

    class nullcontext(object):
        def __init__(self, enter_result=None):
            self.enter_result = enter_result

        def __enter__(self):
            return self.enter_result

        def __exit__(self, *args):
            pass


###################################################################################################
ScriptName = os.path.basename(__file__)

pyPlatform = platform.system()

args = None
dockerBin = None
# dockerComposeBin might be e.g., ('docker', 'compose'), ('podman', 'compose'), or 'docker-compose', etc.
#   it will be flattened in run_process
dockerComposeBin = None
dockerComposeYaml = None
kubeImported = None
opensslBin = None
orchMode = None
shuttingDown = [False]
yamlImported = None
dotenvImported = None
MaxAskForValueCount = 100
UsernameRegex = re.compile(r'^[a-zA-Z][a-zA-Z0-9_\-.]+$')
UsernameMinLen = 4
UsernameMaxLen = 32
PasswordMinLen = 8
PasswordMaxLen = 128
TrueOrFalseNoQuote = lambda x: 'true' if x else 'false'

###################################################################################################
try:
    from colorama import init as ColoramaInit, Fore, Back, Style

    ColoramaInit()
    coloramaImported = True
except Exception:
    coloramaImported = False


###################################################################################################
# handle sigint/sigterm and set a global shutdown variable
def shutdown_handler(signum, frame):
    global shuttingDown
    shuttingDown[0] = True


###################################################################################################
def checkEnvFilesAndValues():
    global args
    global dockerComposeBin
    global orchMode
    global dotenvImported
    global yamlImported

    # if a specific config/*.env file doesn't exist, use the *.example.env files as defaults
    if os.path.isdir(examplesConfigDir := os.path.join(GetMalcolmPath(), 'config')):

        # process renames, copies, removes, etc. from env-var-actions.yml
        envVarActionsYaml = None
        envVarActionsFile = os.path.join(examplesConfigDir, 'env-var-actions.yml')
        if os.path.isfile(envVarActionsFile):
            with open(envVarActionsFile, 'r') as f:
                envVarActionsYaml = yamlImported.YAML(typ='safe', pure=True).load(f)
            if envVarActionsYaml and isinstance(envVarActionsYaml, dict):

                # renamed_environment_variable_files renames .env files from their old to new names
                if 'renamed_environment_variable_files' in envVarActionsYaml:
                    for destEnv, sourceEnv in envVarActionsYaml['renamed_environment_variable_files'].items():
                        destEnvFileName = os.path.join(args.configDir, destEnv.replace('_', '-') + '.env')
                        sourceEnvFileName = os.path.join(
                            args.configDir, next(iter(get_iterable(sourceEnv))).replace('_', '-') + '.env'
                        )
                        if os.path.isfile(sourceEnvFileName):
                            if not os.path.isfile(destEnvFileName):
                                shutil.move(sourceEnvFileName, destEnvFileName)
                                logging.info(
                                    f"Renamed {os.path.basename(sourceEnvFileName)} to {os.path.basename(destEnvFileName)}"
                                )
                            else:
                                logging.info(
                                    f"{os.path.basename(destEnvFileName)} does not exist, ignoring rename from {os.path.basename(sourceEnvFileName)}"
                                )
                        else:
                            logging.info(
                                f"{os.path.basename(sourceEnvFileName)} does not exist, ignoring rename to {os.path.basename(destEnvFileName)}"
                            )

                # copied_environment_variables contains values that used to be in one environment variable file
                #   but are now in another. This section only does the creation, not the removal (which should
                #   also be reflected in removed_environment_variables). This is non-destructive, meaning
                #   values already existing in the destination aren't overwritten.
                if 'copied_environment_variables' in envVarActionsYaml:
                    # top level in this hash represents the destination .env file
                    for destEnv, sourceEnvs in envVarActionsYaml['copied_environment_variables'].items():
                        # if the destination .env file already exists, read its current values
                        # if not, create it from .example if possible first
                        destEnvFileName = os.path.join(args.configDir, destEnv.replace('_', '-') + '.env')
                        if not os.path.isfile(destEnvFileName):
                            envExampleFile = os.path.join(
                                examplesConfigDir, os.path.basename(destEnvFileName) + '.example'
                            )
                            if os.path.isfile(envExampleFile):
                                logging.info(f"Creating {destEnvFileName} from {os.path.basename(envExampleFile)}")
                                shutil.copyfile(envExampleFile, destEnvFileName)
                        destVars = (
                            dotenvImported.dotenv_values(destEnvFileName) if os.path.isfile(destEnvFileName) else dict()
                        )
                        # next level in this hash represents the source .env file
                        for sourceEnv, keys in sourceEnvs.items():
                            # read the source .env file's values
                            sourceEnvFileName = os.path.join(
                                args.configDir, next(iter(get_iterable(sourceEnv))).replace('_', '-') + '.env'
                            )
                            if not os.path.isfile(sourceEnvFileName):
                                sourceEnvFileName = os.path.join(
                                    examplesConfigDir, next(iter(get_iterable(sourceEnv))).replace('_', '-') + '.env'
                                )
                            if os.path.isfile(sourceEnvFileName):
                                sourceVars = dotenvImported.dotenv_values(sourceEnvFileName)
                                # open the destination file for writing new values
                                destEnvValues = []
                                for destKey, sourceKey in keys.items():
                                    sourceVarName = None
                                    # in the yml, the variable could be defined like this:
                                    #
                                    # destfile:
                                    #   sourcefile:
                                    #     destvarname:
                                    #       sourcevarname
                                    #
                                    # in which case the value of sourcefile.sourcevarname is added as
                                    #   destfile.destvarname
                                    #
                                    # another option is this:
                                    #
                                    # destfile:
                                    #   sourcefile:
                                    #     destvarname:
                                    #       sourcevarname:
                                    #         "true": disabled
                                    #         "false": local
                                    #
                                    # when this is the case (sourcevarname is a hash), the value of
                                    #   sourcefile.sourcefilename is looked up in this hash, and
                                    #   if it exists, that value is added as destfile.destfilename
                                    if (
                                        (
                                            (isinstance(sourceKey, str) and (sourceVarName := sourceKey))
                                            or (
                                                isinstance(sourceKey, dict)
                                                and (len(sourceKey) == 1)
                                                and (sourceVarName := next(iter(sourceKey)))
                                            )
                                        )
                                        # if a key exists in the source, but is either not in the dest, or IS in the
                                        # dest but it has value map, it needs to be written
                                        and ((destKey not in destVars) or isinstance(sourceKey, dict))
                                        and sourceVarName in sourceVars
                                    ):
                                        if isinstance(sourceKey, str):
                                            logging.info(
                                                f"Creating {os.path.basename(destEnvFileName)}:{destKey} from {os.path.basename(sourceEnvFileName)}:{sourceVarName} ({type(sourceKey).__name__})"
                                            )
                                            destEnvValues.append(
                                                EnvValue(
                                                    True,
                                                    destEnvFileName,
                                                    destKey,
                                                    sourceVars[sourceVarName],
                                                )
                                            )

                                        elif isinstance(sourceKey, dict) and (
                                            destVal := {
                                                str(k): str(v) for k, v in sourceKey[sourceVarName].items()
                                            }.get(str(sourceVars[sourceVarName]), None)
                                        ):
                                            logging.info(
                                                f"Creating {os.path.basename(destEnvFileName)}:{destKey} from {os.path.basename(sourceEnvFileName)}:{sourceVarName} ({type(sourceKey).__name__})"
                                            )
                                            destEnvValues.append(
                                                EnvValue(
                                                    True,
                                                    destEnvFileName,
                                                    destKey,
                                                    destVal,
                                                )
                                            )
                                if destEnvValues:
                                    UpdateEnvFiles(
                                        destEnvValues,
                                        stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH,
                                    )

                # removed_environment_variables contains values that used to be in an environment variable file, but no longer belong there
                if 'removed_environment_variables' in envVarActionsYaml:
                    keyPattern = re.compile(r'^\s*([A-Za-z0-9_]+)\s*=')
                    # top level in this hash represents the .env file to modify
                    for envFile, keys in envVarActionsYaml['removed_environment_variables'].items():
                        envFileName = os.path.join(args.configDir, envFile.replace('_', '-') + '.env')
                        if os.path.isfile(envFileName):
                            # read the keys and filter out the ones to be removed
                            with open(envFileName, 'r') as f:
                                allLines = [x.strip() for x in f.readlines()]
                            filteredLines = [
                                line
                                for line in allLines
                                if (not keyPattern.match(line)) or (keyPattern.match(line).group(1) not in keys)
                            ]
                            # if changes were made, update the .env file
                            if allLines != filteredLines:
                                # if all that remains are comments, blank lines, or the K8S_SECRET key, just delete the .env file
                                remainingLines = [
                                    x
                                    for x in filteredLines
                                    if (len(x) > 0) and (not x.startswith('#')) and (not x.startswith('K8S_SECRET'))
                                ]
                                if remainingLines:
                                    # write the remaining unfiltered lines to the .env file
                                    logging.info(f"Removing {keys} from {os.path.basename(envFileName)}")
                                    with open(envFileName, 'w') as f:
                                        f.write("\n".join(filteredLines))
                                else:
                                    # nothing left, no reason to save this .env file
                                    logging.info(f"Removing {keys}, deleting {os.path.basename(envFileName)}")
                                    os.unlink(envFileName)

        # creating missing .env file from .env.example file
        for envExampleFile in sorted(glob.glob(os.path.join(examplesConfigDir, '*.env.example'))):
            envFile = os.path.join(args.configDir, os.path.basename(envExampleFile[: -len('.example')]))
            if not os.path.isfile(envFile):
                logging.info(f"Creating {envFile} from {os.path.basename(envExampleFile)}")
                shutil.copyfile(envExampleFile, envFile)

        # now, example the .env and .env.example file for individual values, and create any that are
        # in the .example file but missing in the .env file
        for envFile in sorted(glob.glob(os.path.join(args.configDir, '*.env'))):
            envExampleFile = os.path.join(examplesConfigDir, os.path.basename(envFile) + '.example')
            if os.path.isfile(envExampleFile):
                envValues = dotenvImported.dotenv_values(envFile)
                exampleValues = dotenvImported.dotenv_values(envExampleFile)
                missingVars = list(set(exampleValues.keys()).difference(set(envValues.keys())))
                if missingVars:
                    logging.warning(
                        f"Missing {missingVars} in {os.path.basename(envFile)} from {os.path.basename(envExampleFile)}"
                    )
                    with open(envFile, "a") as envFileHandle:
                        print('', file=envFileHandle)
                        print('', file=envFileHandle)
                        print(
                            f'# missing variables created from {os.path.basename(envExampleFile)} at {str(datetime.datetime.now())}',
                            file=envFileHandle,
                        )
                        for missingVar in missingVars:
                            print(f"{missingVar}={exampleValues[missingVar]}", file=envFileHandle)

        # files or directories that need to be relocated, only if:
        #   - deployment mode is docker compose
        #   - Malcolm is not running
        #   - the source exists
        #   - the destination does not exist
        if (
            envVarActionsYaml
            and isinstance(envVarActionsYaml, dict)
            and (orchMode is OrchestrationFramework.DOCKER_COMPOSE)
            and ('relocated_files' in envVarActionsYaml)
        ):
            osEnv = os.environ.copy()
            if not args.noTmpDirOverride:
                osEnv['TMPDIR'] = MalcolmTmpPath
            err, out = run_process(
                [
                    dockerComposeBin,
                    '--profile',
                    args.composeProfile,
                    '-f',
                    args.composeFile,
                    'ps',
                    '--services',
                    '--status=running',
                ],
                env=osEnv,
                stderr=False,
                debug=log_level_is_debug(args.verbose),
            )
            out[:] = [x for x in out if x]
            if (err == 0) and (len(out) == 0):
                for src, dst in envVarActionsYaml['relocated_files'].items():
                    srcPath = os.path.join(GetMalcolmPath(), src)
                    dstPath = os.path.join(GetMalcolmPath(), next(iter(get_iterable(dst))))
                    if os.path.exists(dstPath) or (not os.path.exists(srcPath)):
                        logging.info(f'Either "{dst}" already exists or "{src}" does not, ignoring in relocated_files')
                    else:
                        try:
                            shutil.move(srcPath, dstPath)
                            logging.info(f'Relocated "{src}" to "{dst}"')
                        except Exception as e:
                            logging.error(f'Error relocating "{src}" to "{dst}": {e}')


###################################################################################################
# The Arkime wise service stores all information in  .ini file.
# This function creates the .ini file if it does not exist.
# This files is based off of th wise.ini.example file.
#
def checkWiseFile():
    arkimePath = "./arkime/etc"
    wiseFile = os.path.join(arkimePath, 'wise.ini')
    wiseExampleFile = os.path.join(arkimePath, 'wise.ini.example')
    if not os.path.isfile(wiseFile):
        logging.info(f"Creating {wiseFile} from {os.path.basename(wiseExampleFile)}")
        shutil.copyfile(wiseExampleFile, wiseFile)


###################################################################################################
# perform a service-keystore operation in a container
#
# service - the service in the docker-compose YML file
# keystore_args - arguments to pass to the service-keystore binary in the container
# run_process_kwargs - keyword arguments to pass to run_process
#
# returns True (success) or False (failure)
#
def keystore_op(service, dropPriv=False, *keystore_args, **run_process_kwargs):
    global args
    global dockerBin
    global dockerComposeBin
    global orchMode

    err = -1
    results = []

    # the opensearch containers all follow the same naming pattern for these executables
    keystoreBinProc = f"/usr/share/{service}/bin/{service}-keystore"
    uidGidDict = GetUidGidFromEnv(args.configDir)

    if orchMode is OrchestrationFramework.DOCKER_COMPOSE:
        # if we're using docker-uid-gid-setup.sh to drop privileges as we spin up a container
        dockerUidGuidSetup = "/usr/local/bin/docker-uid-gid-setup.sh"

        # compose use local temporary path
        osEnv = os.environ.copy()
        if not args.noTmpDirOverride:
            osEnv['TMPDIR'] = MalcolmTmpPath

        # open up the docker-compose file and "grep" for the line where the keystore file
        # is bind-mounted into the service container (once and only once). the bind
        # mount needs to exist in the YML file and the local directory containing the
        # keystore file needs to exist (although the file itself might not yet).
        # also get PUID and PGID variables from the docker-compose file.
        localKeystore = None
        localKeystoreDir = None
        localKeystorePreExists = False
        composeFileKeystore = f"/usr/share/{service}/config/persist/{service}.keystore"
        volumeKeystore = f"/usr/share/{service}/config/{service}.keystore"
        volumeKeystoreDir = os.path.dirname(volumeKeystore)

        try:
            localKeystore = LocalPathForContainerBindMount(
                service,
                dockerComposeYaml,
                composeFileKeystore,
                GetMalcolmPath(),
            )
            if localKeystore:
                localKeystore = os.path.realpath(localKeystore)
                localKeystoreDir = os.path.dirname(localKeystore)

            if (localKeystore is not None) and os.path.isdir(localKeystoreDir):
                localKeystorePreExists = os.path.isfile(localKeystore)

                dockerCmd = None

                # determine if Malcolm is running; if so, we'll use docker-compose exec, other wise we'll use docker run
                err, out = run_process(
                    [dockerComposeBin, '--profile', args.composeProfile, '-f', args.composeFile, 'ps', '-q', service],
                    env=osEnv,
                    stderr=False,
                    debug=log_level_is_debug(args.verbose),
                )
                out[:] = [x for x in out if x]
                if (err == 0) and (len(out) > 0):
                    # Malcolm is running, we can use an existing container

                    # assemble the service-keystore command
                    dockerCmd = [
                        dockerComposeBin,
                        '--profile',
                        args.composeProfile,
                        '-f',
                        args.composeFile,
                        'exec',
                        # if using stdin, indicate the container is "interactive", else noop (duplicate --rm)
                        '-T' if ('stdin' in run_process_kwargs and run_process_kwargs['stdin']) else '',
                        # execute as UID:GID in docker-compose.yml file
                        '-u',
                        f'{uidGidDict["PUID"]}:{uidGidDict["PGID"]}',
                        # the work directory in the container is the directory to contain the keystore file
                        '-w',
                        volumeKeystoreDir,
                        # the service name
                        service,
                        # the executable filespec
                        keystoreBinProc,
                    ]

                else:
                    # Malcolm isn't running, do 'docker run' to spin up a temporary container to run the ocmmand

                    # "grep" the docker image out of the service's image: value from the docker-compose YML file
                    serviceImage = None
                    composeFileLines = list()
                    with open(args.composeFile, 'r') as f:
                        composeFileLines = [
                            x for x in f.readlines() if f'image: ghcr.io/idaholab/malcolm/{service}' in x
                        ]
                    if (len(composeFileLines) > 0) and (len(composeFileLines[0]) > 0):
                        imageLineValues = composeFileLines[0].split()
                        if len(imageLineValues) > 1:
                            serviceImage = imageLineValues[1]

                    if serviceImage is not None:
                        # assemble the service-keystore command
                        dockerCmd = [
                            dockerBin,
                            'run',
                            # remove the container when complete
                            '--rm',
                            # if using podman, use --userns keep-id
                            ['--userns', 'keep-id'] if dockerBin.startswith('podman') else '',
                            # if using stdin, indicate the container is "interactive", else noop
                            '-i' if ('stdin' in run_process_kwargs and run_process_kwargs['stdin']) else '',
                            # if     dropPriv, dockerUidGuidSetup will take care of dropping privileges for the correct UID/GID
                            # if NOT dropPriv, enter with the keystore executable directly
                            '--entrypoint',
                            dockerUidGuidSetup if dropPriv else keystoreBinProc,
                            '--env',
                            f'PUID={uidGidDict["PUID"]}',
                            '--env',
                            f'DEFAULT_UID={uidGidDict["PUID"]}',
                            '--env',
                            f'PGID={uidGidDict["PGID"]}',
                            '--env',
                            f'DEFAULT_GID={uidGidDict["PGID"]}',
                            '--env',
                            f'PUSER_CHOWN={volumeKeystoreDir}',
                            # rw bind mount the local directory to contain the keystore file to the container directory
                            '-v',
                            f'{localKeystoreDir}:{volumeKeystoreDir}:rw',
                            # the work directory in the container is the directory to contain the keystore file
                            '-w',
                            volumeKeystoreDir,
                            # if     dropPriv, execute as root, as docker-uid-gid-setup.sh will drop privileges for us
                            # if NOT dropPriv, execute as UID:GID in docker-compose.yml file
                            '-u',
                            'root' if dropPriv else f'{uidGidDict["PUID"]}:{uidGidDict["PGID"]}',
                            # the service image name grepped from the YML file
                            serviceImage,
                        ]

                        if dropPriv:
                            # the keystore executable filespec (as we used dockerUidGuidSetup as the entrypoint)
                            dockerCmd.append(keystoreBinProc)

                    else:
                        raise Exception(f'Unable to identify docker image for {service} in {args.composeFile}')

                if dockerCmd is not None:
                    # append whatever other arguments to pass to the executable filespec
                    if keystore_args:
                        dockerCmd.extend(list(keystore_args))

                    dockerCmd[:] = [x for x in dockerCmd if x]

                    # execute the command, passing through run_process_kwargs to run_process as expanded keyword arguments
                    err, results = run_process(
                        dockerCmd, env=osEnv, debug=log_level_is_debug(args.verbose), **run_process_kwargs
                    )
                    if (err != 0) or (not os.path.isfile(localKeystore)):
                        raise Exception(f'Error processing command {service} keystore: {results}')

                else:
                    raise Exception(f'Unable formulate keystore command for {service} in {args.composeFile}')

            else:
                raise Exception(
                    f'Unable to identify a unique keystore file bind mount for {service} in {args.composeFile}'
                )

        except Exception as e:
            if err == 0:
                err = -1

            if (
                list(keystore_args)
                and (len(list(keystore_args)) > 0)
                and (list(keystore_args)[0].lower() in ('create', 'remove'))
                and localKeystorePreExists
            ):
                # don't be so whiny if the "create" failed just because it already existed or a 'remove' failed on a nonexistant item
                logging.info(e)
            else:
                logging.warning(e)

    elif orchMode is OrchestrationFramework.KUBERNETES:
        cmd = [keystoreBinProc]
        if keystore_args:
            cmd.extend(list(keystore_args))
        cmd = [x for x in cmd if x]

        podsResults = PodExec(
            service,
            args.namespace,
            [x for x in cmd if x],
            stdin=(
                run_process_kwargs['stdin'] if ('stdin' in run_process_kwargs and run_process_kwargs['stdin']) else None
            ),
        )

        err = 0 if all([deep_get(v, ['err'], 1) == 0 for k, v in podsResults.items()]) else 1
        results = list(chain(*[deep_get(v, ['output'], '') for k, v in podsResults.items()]))

        logging.debug(
            f"{len(podsResults)} pods: {cmd}({run_process_kwargs['stdin'][:80] + bool(run_process_kwargs['stdin'][80:]) * '...' if 'stdin' in run_process_kwargs and run_process_kwargs['stdin'] else ''}) returned {err}: {results}"
        )
        for podname, podResults in podsResults.items():
            logging.debug(
                f"{podname}: {cmd}({run_process_kwargs['stdin'][:80] + bool(run_process_kwargs['stdin'][80:]) * '...' if 'stdin' in run_process_kwargs and run_process_kwargs['stdin'] else ''}) returned {deep_get(podResults, ['err'], 1)}: {deep_get(podResults, ['output'], 'unknown')}"
            )

    else:
        raise Exception(
            f'{sys._getframe().f_code.co_name} does not yet support {orchMode} with profile {args.composeProfile}'
        )

    return (err == 0), results


###################################################################################################
def status():
    global args
    global dockerComposeBin
    global orchMode

    if orchMode is OrchestrationFramework.DOCKER_COMPOSE:
        # docker-compose use local temporary path
        osEnv = os.environ.copy()
        if not args.noTmpDirOverride:
            osEnv['TMPDIR'] = MalcolmTmpPath

        cmd = [dockerComposeBin, '--profile', args.composeProfile, '-f', args.composeFile, 'ps']
        if args.service is not None:
            cmd.append(args.service)

        err, out = run_process(
            cmd,
            env=osEnv,
            debug=log_level_is_debug(args.verbose),
        )
        if err == 0:
            print("\n".join(out))
        else:
            logging.warning("Failed to display Malcolm status\n")
            logging.warning("\n".join(out))

    elif orchMode is OrchestrationFramework.KUBERNETES:
        try:
            PrintNodeStatus()
            print()
        except Exception as e:
            logging.debug(f'Error getting node status: {e}')
        try:
            PrintPodStatus(namespace=args.namespace)
            print()
        except Exception as e:
            logging.error(f'Error getting {args.namespace} status: {e}')

    else:
        raise Exception(f'{sys._getframe().f_code.co_name} does not yet support {orchMode}')


###################################################################################################
def printURLs():
    global orchMode

    if orchMode is OrchestrationFramework.KUBERNETES:
        addrs = get_node_hostnames_and_ips(mastersOnly=True)
        if not any((addrs['external'], addrs['hostname'])):
            addrs = get_node_hostnames_and_ips(mastersOnly=False)
        if addrs['external']:
            myIp = addrs['external'][0]
        elif addrs['hostname']:
            myIp = addrs['hostname'][0]
        elif addrs['internal']:
            myIp = addrs['internal'][0]
        else:
            myIp = '<cluster IP>'
    else:
        myIp = get_primary_ip()

    print(f"\nMalcolm services can be accessed at https://{myIp}/")
    print("------------------------------------------------------------------------------")


###################################################################################################
def netboxBackup(backupFileName=None):
    global args
    global dockerComposeBin
    global orchMode
    global dotenvImported

    backupFileName, backupMediaFileName = None, None

    uidGidDict = GetUidGidFromEnv(args.configDir)

    postgresEnvFile = os.path.join(args.configDir, 'postgres.env')
    postgresEnvs = dict()
    if os.path.isfile(postgresEnvFile):
        postgresEnvs.update(dotenvImported.dotenv_values(postgresEnvFile))

    if (orchMode is OrchestrationFramework.DOCKER_COMPOSE) and (args.composeProfile == PROFILE_MALCOLM):
        # docker-compose use local temporary path
        osEnv = os.environ.copy()
        if not args.noTmpDirOverride:
            osEnv['TMPDIR'] = MalcolmTmpPath

        dockerCmd = [
            dockerComposeBin,
            '--profile',
            args.composeProfile,
            '-f',
            args.composeFile,
            'exec',
            # disable pseudo-TTY allocation
            '-T',
            # execute as UID:GID in docker-compose.yml file
            '-u',
            f'{uidGidDict["PUID"]}:{uidGidDict["PGID"]}',
            'postgres',
            'pg_dump',
            '--username',
            postgresEnvs.get('POSTGRES_NETBOX_USER', 'netbox'),
            '-d',
            postgresEnvs.get('POSTGRES_NETBOX_DB', 'netbox'),
        ]

        err, results = run_process(
            dockerCmd, env=osEnv, debug=log_level_is_debug(args.verbose), stdout=True, stderr=False
        )
        if (err != 0) or (len(results) == 0):
            raise Exception('Error creating NetBox configuration database backup')

        if (backupFileName is None) or (len(backupFileName) == 0):
            backupFileName = f"malcolm_netbox_backup_{time.strftime('%Y%m%d-%H%M%S')}.gz"

        with gzip.GzipFile(backupFileName, "wb") as f:
            f.write(bytes('\n'.join(results), 'utf-8'))

        backupFileParts = os.path.splitext(backupFileName)
        backupMediaFileName = backupFileParts[0] + ".media.tar.gz"
        with tarfile.open(backupMediaFileName, 'w:gz') as t:
            t.add(os.path.join(os.path.join(GetMalcolmPath(), 'netbox'), 'media'), arcname='.')

    elif orchMode is OrchestrationFramework.KUBERNETES:
        if podsResults := PodExec(
            service='postgres',
            container='postgres-container',
            namespace=args.namespace,
            command=[
                'pg_dump',
                '--username',
                postgresEnvs.get('POSTGRES_NETBOX_USER', 'netbox'),
                '-d',
                postgresEnvs.get('POSTGRES_NETBOX_DB', 'netbox'),
            ],
            maxPodsToExec=1,
        ):
            podName = next(iter(podsResults))
            err = podsResults[podName]['err']
            results = podsResults[podName]['output']
        else:
            err = 1
            results = []

        if (err != 0) or (len(results) == 0):
            raise Exception('Error creating NetBox configuration database backup')

        if (backupFileName is None) or (len(backupFileName) == 0):
            backupFileName = f"malcolm_netbox_backup_{time.strftime('%Y%m%d-%H%M%S')}.gz"

        with gzip.GzipFile(backupFileName, "wb") as f:
            f.write(bytes('\n'.join(results), 'utf-8'))

        # TODO: can't backup netbox/media directory via kubernetes at the moment
        backupMediaFileName = None

    else:
        raise Exception(
            f'{sys._getframe().f_code.co_name} does not yet support {orchMode} with profile {args.composeProfile}'
        )

    return backupFileName, backupMediaFileName


###################################################################################################
def netboxRestore(backupFileName=None):
    global args
    global dockerComposeBin
    global orchMode

    if backupFileName and os.path.isfile(backupFileName):
        uidGidDict = GetUidGidFromEnv(args.configDir)

        if (orchMode is OrchestrationFramework.DOCKER_COMPOSE) and (args.composeProfile == PROFILE_MALCOLM):
            # docker-compose use local temporary path
            osEnv = os.environ.copy()
            if not args.noTmpDirOverride:
                osEnv['TMPDIR'] = MalcolmTmpPath

            dockerCmdBase = [
                dockerComposeBin,
                '--profile',
                args.composeProfile,
                '-f',
                args.composeFile,
                'exec',
                # disable pseudo-TTY allocation
                '-T',
                # execute as UID:GID in docker-compose.yml file
                '-u',
                f'{uidGidDict["PUID"]}:{uidGidDict["PGID"]}',
                # run in the netbox container
                'netbox',
            ]

            # get remote temporary directory for restore
            dockerCmd = dockerCmdBase + ['mktemp', '-d', '-t', 'restore.XXXXXXXXXX']
            err, results = run_process(dockerCmd, env=osEnv, debug=log_level_is_debug(args.verbose))
            if (err == 0) and results:
                tmpRestoreDir = results[0]
            else:
                tmpRestoreDir = '/tmp'

            try:
                # copy database backup and media backup to remote temporary directory
                for tmpFile in [
                    x
                    for x in [backupFileName, os.path.splitext(backupFileName)[0] + ".media.tar.gz"]
                    if os.path.isfile(x)
                ]:
                    dockerCmd = dockerCmdBase + ['tee', os.path.join(tmpRestoreDir, os.path.basename(tmpFile))]
                    with open(tmpFile, 'rb') as f:
                        err, results = run_process(
                            dockerCmd,
                            env=osEnv,
                            debug=log_level_is_debug(args.verbose),
                            stdout=False,
                            stderr=True,
                            stdin=f.read(),
                        )
                    if err != 0:
                        raise Exception(
                            f'Error {err} copying backed-up NetBox file {os.path.basename(tmpFile)} to {tmpRestoreDir}: {results}'
                        )

                # perform the restore inside the container
                dockerCmd = dockerCmdBase + [
                    '/opt/netbox/venv/bin/python',
                    '/usr/local/bin/netbox_init.py',
                    '--preload-backup',
                    os.path.join(tmpRestoreDir, os.path.basename(backupFileName)),
                ]
                err, results = run_process(dockerCmd, env=osEnv, debug=log_level_is_debug(args.verbose))
                if err != 0:
                    raise Exception(
                        f'Error {err} restoring NetBox database {os.path.basename(backupFileName)}: {results}'
                    )

            finally:
                # cleanup the remote directory
                if tmpRestoreDir != '/tmp':
                    dockerCmd = dockerCmdBase + ['rm', '-rf', tmpRestoreDir]
                else:
                    dockerCmd = dockerCmdBase + [
                        'bash',
                        '-c',
                        f"rm -f {tmpRestoreDir}/{os.path.splitext(backupFileName)[0]}*",
                    ]
                run_process(dockerCmd, env=osEnv, debug=log_level_is_debug(args.verbose))

        elif orchMode is OrchestrationFramework.KUBERNETES:
            # copy database backup and media backup to remote temporary directory
            try:
                service_name = "netbox"
                container_name = "netbox-container"
                tmpRestoreDir = '/tmp'
                tmpRestoreFile = os.path.join(
                    tmpRestoreDir, os.path.splitext(os.path.basename(backupFileName))[0] + '.txt'
                )
                with gzip.open(backupFileName, 'rt') as f:
                    if podsResults := PodExec(
                        service=service_name,
                        namespace=args.namespace,
                        command=['tee', tmpRestoreFile],
                        stdout=False,
                        stderr=True,
                        stdin=f.read(),
                        container=container_name,
                    ):
                        err = 0 if all([deep_get(v, ['err'], 1) == 0 for k, v in podsResults.items()]) else 1
                        results = list(chain(*[deep_get(v, ['output'], '') for k, v in podsResults.items()]))
                    else:
                        err = 1
                        results = []
                if err != 0:
                    raise Exception(
                        f'Error {err} copying backed-up NetBox file {os.path.basename(backupFileName)} to {tmpRestoreFile}: {results}'
                    )

                # perform the restore inside the container
                if podsResults := PodExec(
                    service=service_name,
                    namespace=args.namespace,
                    command=[
                        '/opt/netbox/venv/bin/python',
                        '/usr/local/bin/netbox_init.py',
                        '--preload-backup',
                        tmpRestoreFile,
                    ],
                    container=container_name,
                ):
                    err = 0 if all([deep_get(v, ['err'], 1) == 0 for k, v in podsResults.items()]) else 1
                    results = list(chain(*[deep_get(v, ['output'], '') for k, v in podsResults.items()]))
                else:
                    err = 1
                    results = []
                if err != 0:
                    raise Exception(
                        f'Error {err} restoring NetBox database {os.path.basename(backupFileName)}: {results}'
                    )

            finally:
                # cleanup on other side
                PodExec(
                    service=service_name,
                    namespace=args.namespace,
                    command=[
                        'bash',
                        '-c',
                        f"rm -f {tmpRestoreDir}/{os.path.splitext(backupFileName)[0]}*",
                    ],
                    container=container_name,
                )

        else:
            raise Exception(
                f'{sys._getframe().f_code.co_name} does not yet support {orchMode} with profile {args.composeProfile}'
            )


###################################################################################################
def logs():
    global args
    global dockerBin
    global dockerComposeBin
    global orchMode
    global shuttingDown

    finishedStartingRegEx = re.compile(r'.+Pipelines\s+running\s+\{.*:non_running_pipelines=>\[\]\}')

    osEnv = os.environ.copy()
    # use local temporary path
    if not args.noTmpDirOverride:
        osEnv['TMPDIR'] = MalcolmTmpPath

    cmd = []

    if orchMode is OrchestrationFramework.DOCKER_COMPOSE:
        # increase COMPOSE_HTTP_TIMEOUT to be ridiculously large so docker-compose never times out the TTY doing debug output
        osEnv['COMPOSE_HTTP_TIMEOUT'] = '100000000'

        cmd = [dockerComposeBin, '--profile', args.composeProfile, '-f', args.composeFile, 'ps']
        if args.service is not None:
            cmd.append(args.service)
        err, out = run_process(
            cmd,
            env=osEnv,
            debug=log_level_is_debug(args.verbose),
        )
        print("\n".join(out))

        cmd = [
            dockerComposeBin,
            '--profile',
            args.composeProfile,
            '-f',
            args.composeFile,
            'logs',
            '--tail',
            str(args.logLineCount) if args.logLineCount else 'all',
            '-f',
        ]
        if args.service is not None:
            cmd.append(args.service)

    elif orchMode is OrchestrationFramework.KUBERNETES:
        if which("stern"):
            cmd = [
                "stern",
                "--kubeconfig",
                args.composeFile,
                "--only-log-lines",
                "--color",
                'auto' if coloramaImported else 'never',
                "--template",
                (
                    '{{.Namespace}}/{{color .PodColor .PodName}}/{{color .ContainerColor .ContainerName}} | {{.Message}}{{"\\n"}}'
                    if log_level_is_debug(args.verbose)
                    else '{{color .ContainerColor .ContainerName}} | {{.Message}}{{"\\n"}}'
                ),
                '--tail',
                str(args.logLineCount) if args.logLineCount else '-1',
            ]

            if args.namespace:
                cmd.extend(['--namespace', args.namespace])
            else:
                cmd.append('--all-namespaces')
            cmd.append(args.service if args.service else '.*')

        else:
            logging.error(
                f'{sys._getframe().f_code.co_name} with orchestration mode {orchMode} requires "stern" (https://github.com/stern/stern/releases/latest)'
            )

    else:
        raise Exception(f'{sys._getframe().f_code.co_name} does not yet support {orchMode}')

    if cmd:
        process = Popen(
            list(flatten(cmd)),
            env=osEnv,
            stdout=PIPE,
            stderr=None if log_level_is_debug(args.verbose) else DEVNULL,
        )
        while not shuttingDown[0]:
            output = process.stdout.readline()
            if not output:
                if process.poll() is not None:
                    break
                else:
                    time.sleep(0.5)

            elif output := ProcessLogLine(output, debug=log_level_is_debug(args.verbose)):
                print(output)

            if (
                output
                and (args.cmdStart or args.cmdRestart)
                and (not args.cmdLogs)
                and finishedStartingRegEx.match(output)
            ):
                shuttingDown[0] = True
                process.terminate()
                try:
                    process.wait(timeout=5.0)
                except TimeoutExpired:
                    process.kill()

                print("\nStarted Malcolm\n")
                printURLs()

        process.poll()


###################################################################################################
def stop(wipe=False):
    global args
    global dockerBin
    global dockerComposeBin
    global dockerComposeYaml
    global orchMode

    if orchMode is OrchestrationFramework.DOCKER_COMPOSE:
        # docker-compose use local temporary path
        osEnv = os.environ.copy()
        if not args.noTmpDirOverride:
            osEnv['TMPDIR'] = MalcolmTmpPath

        if args.service is not None:
            # stopping a single (or multiple services)
            err, out = run_process(
                [dockerComposeBin, '--profile', args.composeProfile, '-f', args.composeFile, 'stop'] + args.service,
                env=osEnv,
                debug=log_level_is_debug(args.verbose),
            )
            if err == 0:
                logging.info(f"Stopped Malcolm's {args.service} services\n")
                err, out = run_process(
                    [dockerComposeBin, '--profile', args.composeProfile, '-f', args.composeFile, 'rm', '--force']
                    + args.service,
                    env=osEnv,
                    debug=log_level_is_debug(args.verbose),
                )
                if err == 0:
                    logging.info(f"Removed Malcolm's {args.service} services\n")
                else:
                    logging.critical(f"Malcolm's {args.service} services failed to remove\n")
                    logging.critical("\n".join(out))
                    exit(err)
            else:
                logging.critical(f"Malcolm's {args.service} services failed to stop\n")
                logging.critical("\n".join(out))
                exit(err)

        else:
            # stopping malcolm
            # if stop.sh is being called with wipe.sh (after the docker-compose file)
            # then also remove named and anonymous volumes (not external volumes, of course)
            err, out = run_process(
                [dockerComposeBin, '--profile', args.composeProfile, '-f', args.composeFile, 'down', '--volumes'][
                    : 7 if wipe else -1
                ],
                env=osEnv,
                debug=log_level_is_debug(args.verbose),
            )
            if err == 0:
                logging.info("Stopped Malcolm\n")
            else:
                logging.critical("Malcolm failed to stop\n")
                logging.critical("\n".join(out))
                exit(err)

            if wipe:
                # there is some overlap here among some of these containers, but it doesn't matter
                boundPathsToWipe = (
                    BoundPath("filebeat", "/zeek", True, None, None),
                    BoundPath("file-monitor", "/zeek/logs", True, None, None),
                    BoundPath("opensearch", "/usr/share/opensearch/data", True, ["nodes"], None),
                    BoundPath("pcap-monitor", "/pcap", True, ["arkime-live", "processed", "upload"], None),
                    BoundPath("suricata", "/var/log/suricata", True, None, ["."]),
                    BoundPath(
                        "upload",
                        "/var/www/upload/server/php/chroot/files",
                        True,
                        [os.path.join('tmp', 'spool'), "variants"],
                        None,
                    ),
                    BoundPath("zeek", "/zeek/extract_files", True, None, None),
                    BoundPath("zeek", "/zeek/upload", True, None, None),
                    BoundPath("zeek-live", "/zeek/live", True, ["spool"], None),
                    BoundPath(
                        "filebeat",
                        "/zeek",
                        False,
                        ["processed", "current", "live"],
                        ["processed", "current", "live"],
                    ),
                )
                for boundPath in boundPathsToWipe:
                    localPath = LocalPathForContainerBindMount(
                        boundPath.service,
                        dockerComposeYaml,
                        boundPath.target,
                        GetMalcolmPath(),
                    )
                    if localPath and os.path.isdir(localPath):
                        # delete files
                        if boundPath.files:
                            logging.info(f'Walking "{localPath}" for file deletion')
                            for root, dirnames, filenames in os.walk(localPath, topdown=True, onerror=None):
                                for file in filenames:
                                    fileSpec = os.path.join(root, file)
                                    if (os.path.isfile(fileSpec) or os.path.islink(fileSpec)) and (
                                        not file.startswith('.git')
                                    ):
                                        try:
                                            os.remove(fileSpec)
                                        except Exception:
                                            pass
                        # delete whole directories
                        if boundPath.relative_dirs:
                            for relDir in get_iterable(boundPath.relative_dirs):
                                tmpPath = os.path.join(localPath, relDir)
                                if os.path.isdir(tmpPath):
                                    logging.info(f'Performing rmtree_except on "{tmpPath}"')
                                    rmtree_except(tmpPath, exclude_patterns=['.gitignore'], ignore_errors=True)
                        # cleanup empty directories
                        if boundPath.clean_empty_dirs:
                            for cleanDir in get_iterable(boundPath.clean_empty_dirs):
                                tmpPath = os.path.join(localPath, cleanDir)
                                if os.path.isdir(tmpPath):
                                    logging.info(f'Performing RemoveEmptyFolders on "{tmpPath}"')
                                    RemoveEmptyFolders(tmpPath, removeRoot=False)

                logging.info("Malcolm has been stopped and its data cleared\n")

    elif orchMode is OrchestrationFramework.KUBERNETES:
        stopResults = StopMalcolm(
            namespace=args.namespace,
            deleteNamespace=args.deleteNamespace and wipe,
            deletePVCsAndPVs=wipe,
        )
        if dictsearch(stopResults, 'error'):
            logging.error(f"Removing resources in the {args.namespace} namespace returned the following error(s):\n")
            logging.error(stopResults)
        else:
            logging.info(f"The resources in the {args.namespace} namespace have been removed\n")
            logging.debug(stopResults)

        if wipe:
            logging.warning(
                f'Underlying storage artifacts on PersistentVolumes cannot be deleted by {ScriptName}: they must be deleted manually\n'
            )

    else:
        raise Exception(f'{sys._getframe().f_code.co_name} does not yet support {orchMode}')


###################################################################################################
def start():
    global args
    global dockerBin
    global dockerComposeBin
    global orchMode

    if args.service is None:
        touch(os.path.join(GetMalcolmPath(), os.path.join('htadmin', 'metadata')))
        touch(os.path.join(GetMalcolmPath(), '.opensearch.primary.curlrc'))
        touch(os.path.join(GetMalcolmPath(), '.opensearch.secondary.curlrc'))
        touch(os.path.join(GetMalcolmPath(), os.path.join('nginx', 'nginx_ldap.conf')))

        # make sure the auth files exist. if we are in an interactive shell and we're
        # missing any of the auth files, prompt to create them now
        if sys.__stdin__.isatty() and (not MalcolmAuthFilesExist(configDir=args.configDir)):
            authSetup()

        # still missing? sorry charlie
        if not MalcolmAuthFilesExist(configDir=args.configDir):
            raise Exception(
                'Malcolm administrator account authentication files are missing, please run ./scripts/auth_setup to generate them'
            )

        # if the OpenSearch keystore doesn't exist exist, create empty ones
        if not os.path.isfile(os.path.join(GetMalcolmPath(), os.path.join('opensearch', 'opensearch.keystore'))):
            print ("here")
            keystore_op('opensearch', True, 'create')

        # make sure permissions are set correctly for the worker processes
        for authFile in [
            os.path.join(GetMalcolmPath(), os.path.join('nginx', 'htpasswd')),
            os.path.join(GetMalcolmPath(), os.path.join('htadmin', 'metadata')),
        ]:
            # chmod 644 authFile
            os.chmod(authFile, stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH)
        for authFile in [
            os.path.join(GetMalcolmPath(), os.path.join('nginx', 'nginx_ldap.conf')),
            os.path.join(GetMalcolmPath(), '.opensearch.primary.curlrc'),
            os.path.join(GetMalcolmPath(), '.opensearch.secondary.curlrc'),
        ]:
            # chmod 600 authFile
            os.chmod(authFile, stat.S_IRUSR | stat.S_IWUSR)
        with pushd(args.configDir):
            for envFile in glob.glob("*.env"):
                # chmod 600 envFile
                os.chmod(envFile, stat.S_IRUSR | stat.S_IWUSR)

        # touch the zeek intel file and zeek custom file
        touch(os.path.join(GetMalcolmPath(), os.path.join('zeek', os.path.join('intel', '__load__.zeek'))))
        touch(os.path.join(GetMalcolmPath(), os.path.join('zeek', os.path.join('custom', '__load__.zeek'))))

        # clean up any leftover intel update locks
        shutil.rmtree(
            os.path.join(GetMalcolmPath(), os.path.join('zeek', os.path.join('intel', 'lock'))), ignore_errors=True
        )

    if orchMode is OrchestrationFramework.DOCKER_COMPOSE:
        if args.service is None:
            # make sure some directories exist before we start
            boundPathsToCreate = (
                BoundPath("file-monitor", "/zeek/logs", False, None, None),
                BoundPath("nginx-proxy", "/var/local/ca-trust", False, None, None),
                BoundPath("netbox", "/opt/netbox/netbox/media", False, None, None),
                BoundPath("postgres", "/var/lib/postgresql/data", False, None, None),
                BoundPath("redis", "/data", False, None, None),
                BoundPath("opensearch", "/usr/share/opensearch/data", False, ["nodes"], None),
                BoundPath("opensearch", "/opt/opensearch/backup", False, None, None),
                BoundPath("pcap-monitor", "/pcap", False, ["arkime-live", "processed", "upload"], None),
                BoundPath("suricata", "/var/log/suricata", False, ["live"], None),
                BoundPath(
                    "upload",
                    "/var/www/upload/server/php/chroot/files",
                    False,
                    [os.path.join('tmp', 'spool'), "variants"],
                    None,
                ),
                BoundPath("zeek", "/zeek/extract_files", False, None, None),
                BoundPath("zeek", "/zeek/upload", False, None, None),
                BoundPath("zeek", "/opt/zeek/share/zeek/site/custom", False, None, None),
                BoundPath("zeek", "/opt/zeek/share/zeek/site/intel", False, ["Mandiant", "MISP", "STIX"], None),
                BoundPath("zeek-live", "/zeek/live", False, ["spool"], None),
                BoundPath(
                    "filebeat", "/zeek", False, ["processed", "current", "live", "extract_files", "upload"], None
                ),
            )
            for boundPath in boundPathsToCreate:
                localPath = LocalPathForContainerBindMount(
                    boundPath.service,
                    dockerComposeYaml,
                    boundPath.target,
                    GetMalcolmPath(),
                )
                if localPath:
                    try:
                        logging.info(f'Ensuring "{localPath}" exists')
                        os.makedirs(localPath)
                    except OSError as exc:
                        if (exc.errno == errno.EEXIST) and os.path.isdir(localPath):
                            pass
                        else:
                            raise
                    if boundPath.relative_dirs:
                        for relDir in get_iterable(boundPath.relative_dirs):
                            tmpPath = os.path.join(localPath, relDir)
                            try:
                                logging.info(f'Ensuring "{tmpPath}" exists')
                                os.makedirs(tmpPath)
                            except OSError as exc:
                                if (exc.errno == errno.EEXIST) and os.path.isdir(tmpPath):
                                    pass
                                else:
                                    raise

        # increase COMPOSE_HTTP_TIMEOUT to be ridiculously large so docker-compose never times out the TTY doing debug output
        osEnv = os.environ.copy()
        osEnv['COMPOSE_HTTP_TIMEOUT'] = '100000000'
        # docker-compose use local temporary path
        if not args.noTmpDirOverride:
            osEnv['TMPDIR'] = MalcolmTmpPath

        # start docker
        cmd = [
            dockerComposeBin,
            '--profile',
            args.composeProfile,
            '-f',
            args.composeFile,
            'up',
            '--detach',
        ]
        if args.service is not None:
            cmd.append(['--no-deps', args.service])

        print("\nStarting Malcolm\n")
        err, out = run_process(
            cmd,
            env=osEnv,
            debug=log_level_is_debug(args.verbose),
        )
        if err != 0:
            logging.critical("Malcolm failed to start\n")
            logging.critical("\n".join(out))
            exit(err)

    elif orchMode is OrchestrationFramework.KUBERNETES:
        if args.skipPerVolChecks or CheckPersistentStorageDefs(
            namespace=args.namespace,
            malcolmPath=GetMalcolmPath(),
            profile=args.composeProfile,
        ):
            print("\nStarting Malcolm\n")
            startResults = StartMalcolm(
                namespace=args.namespace,
                malcolmPath=GetMalcolmPath(),
                configPath=args.configDir,
                profile=args.composeProfile,
                imageSource=args.imageSource,
                imageTag=args.imageTag,
                injectResources=args.injectResources,
                startCapturePods=not args.noCapturePodsStart,
                noCapabilities=args.noCapabilities,
            )

            if dictsearch(startResults, 'error'):
                logging.error(
                    f"Starting the {args.namespace} namespace and creating its underlying resources returned the following error(s):\n"
                )
                logging.error(startResults)

            else:
                logging.debug(startResults)

        else:
            groupedStorageEntries = {
                i: [j[0] for j in j]
                for i, j in groupby(
                    sorted(REQUIRED_VOLUME_OBJECTS.items(), key=lambda x: tuple(x[1].items())),
                    lambda x: tuple(x[1].items()),
                )
            }
            raise Exception(
                f'Storage objects required by Malcolm are not defined in {os.path.join(GetMalcolmPath(), "kubernetes")}: {groupedStorageEntries}'
            )

    else:
        raise Exception(f'{sys._getframe().f_code.co_name} does not yet support {orchMode}')


###################################################################################################
def clientForwarderCertGen(caCrt, caKey, clientConf, outputDir):
    global args
    global opensslBin

    clientKey = None
    clientCrt = None
    clientCaCrt = None

    with tempfile.TemporaryDirectory(dir=MalcolmTmpPath) as tmpCertDir:
        with pushd(tmpCertDir):
            err, out = run_process(
                [opensslBin, 'genrsa', '-out', 'client.key', '2048'],
                stderr=True,
                debug=log_level_is_debug(args.verbose),
            )
            if err != 0:
                raise Exception(f'Unable to generate client.key: {out}')

            err, out = run_process(
                [
                    opensslBin,
                    'req',
                    '-sha512',
                    '-new',
                    '-key',
                    'client.key',
                    '-out',
                    'client.csr',
                    '-config',
                    clientConf,
                ],
                stderr=True,
                debug=log_level_is_debug(args.verbose),
            )
            if err != 0:
                raise Exception(f'Unable to generate client.csr: {out}')

            err, out = run_process(
                [
                    opensslBin,
                    'x509',
                    '-days',
                    '3650',
                    '-req',
                    '-sha512',
                    '-in',
                    'client.csr',
                    '-CAcreateserial',
                    '-CA',
                    caCrt,
                    '-CAkey',
                    caKey,
                    '-out',
                    'client.crt',
                    '-extensions',
                    'v3_req',
                    '-extensions',
                    'usr_cert',
                    '-extfile',
                    clientConf,
                ],
                stderr=True,
                debug=log_level_is_debug(args.verbose),
            )
            if err != 0:
                raise Exception(f'Unable to generate client.crt: {out}')

            if os.path.isfile('client.key'):
                shutil.move('client.key', outputDir)
                clientKey = os.path.join(outputDir, 'client.key')
            if os.path.isfile('client.crt'):
                shutil.move('client.crt', outputDir)
                clientCrt = os.path.join(outputDir, 'client.crt')
            clientCaCrt = os.path.join(outputDir, os.path.basename(caCrt))
            if not os.path.isfile(clientCaCrt) or not same_file_or_dir(caCrt, clientCaCrt):
                shutil.copy2(caCrt, clientCaCrt)
            # -----------------------------------------------

    return clientKey, clientCrt, clientCaCrt


###################################################################################################
def authSetup():
    global args
    global opensslBin
    global dotenvImported

    # for beats/logstash self-signed certificates
    logstashPath = os.path.join(GetMalcolmPath(), os.path.join('logstash', 'certs'))
    filebeatPath = os.path.join(GetMalcolmPath(), os.path.join('filebeat', 'certs'))

    txRxScript = None
    if (pyPlatform != PLATFORM_WINDOWS) and which("croc"):
        txRxScript = 'tx-rx-secure.sh' if which('tx-rx-secure.sh') else None
        if not txRxScript:
            txRxScript = os.path.join(GetMalcolmPath(), os.path.join('shared', os.path.join('bin', 'tx-rx-secure.sh')))
            txRxScript = (
                txRxScript
                if (txRxScript and os.path.isfile(txRxScript))
                else os.path.join(GetMalcolmPath(), os.path.join('scripts', 'tx-rx-secure.sh'))
            )
            txRxScript = txRxScript if (txRxScript and os.path.isfile(txRxScript)) else '/usr/local/bin/tx-rx-secure.sh'
            txRxScript = txRxScript if (txRxScript and os.path.isfile(txRxScript)) else '/usr/bin/tx-rx-secure.sh'
            txRxScript = txRxScript if (txRxScript and os.path.isfile(txRxScript)) else None

    netboxCommonEnvFile = os.path.join(args.configDir, 'netbox-common.env')
    authCommonEnvFile = os.path.join(args.configDir, 'auth-common.env')
    nginxEnvFile = os.path.join(args.configDir, 'nginx.env')
    openSearchEnvFile = os.path.join(args.configDir, 'opensearch.env')

    if args.authMode:
        nginxAuthMode = str(args.authMode).lower()
    else:
        nginxAuthMode = 'unknown'
        if os.path.isfile(authCommonEnvFile):
            nginxAuthMode = str(
                dotenvImported.dotenv_values(authCommonEnvFile).get('NGINX_AUTH_MODE', nginxAuthMode)
            ).lower()
    netboxMode = ''
    if os.path.isfile(netboxCommonEnvFile):
        netboxMode = str(dotenvImported.dotenv_values(netboxCommonEnvFile).get('NETBOX_MODE', '')).lower()
    osPrimaryMode = ''
    osSecondaryMode = ''
    if os.path.isfile(openSearchEnvFile):
        osPrimaryMode = str(dotenvImported.dotenv_values(openSearchEnvFile).get('OPENSEARCH_PRIMARY', '')).lower()
        osSecondaryMode = str(dotenvImported.dotenv_values(openSearchEnvFile).get('OPENSEARCH_SECONDARY', '')).lower()

    # don't make them go through every thing every time, give them a choice instead
    # 0 - key
    # 1 - description
    # 2 - preselected choice
    # 3 - option default (yes/no) for if they're doing "all""
    # 4 - perform automatically if the listed files don't exist (auto first-time generation)
    authConfigChoices = [
        x
        for x in [
            (
                'all',
                "Configure all authentication-related settings",
                True,
                True,
                [],
            ),
            (
                'method',
                f"Select authentication method (currently \"{nginxAuthMode}\")",
                False,
                (not args.cmdAuthSetupNonInteractive) or bool(args.authMode),
                [],
            ),
            (
                'admin',
                "Store administrator username/password for basic HTTP authentication",
                False,
                (not args.cmdAuthSetupNonInteractive)
                or (bool(args.authUserName) and bool(args.authPasswordOpenssl) and bool(args.authPasswordHtpasswd)),
                [],
            ),
            (
                'webcerts',
                "(Re)generate self-signed certificates for HTTPS access",
                False,
                not args.cmdAuthSetupNonInteractive
                or (
                    args.authGenWebCerts
                    or not os.path.isfile(
                        os.path.join(GetMalcolmPath(), os.path.join('nginx', os.path.join('certs', 'key.pem')))
                    )
                ),
                [os.path.join(GetMalcolmPath(), os.path.join('nginx', os.path.join('certs', 'key.pem')))],
            ),
            (
                'fwcerts',
                "(Re)generate self-signed certificates for a remote log forwarder",
                False,
                not args.cmdAuthSetupNonInteractive
                or (
                    args.authGenFwCerts
                    or not os.path.isfile(os.path.join(logstashPath, 'server.key'))
                    or not os.path.isfile(os.path.join(filebeatPath, 'client.key'))
                ),
                [
                    os.path.join(logstashPath, 'server.key'),
                    os.path.join(filebeatPath, 'client.key'),
                ],
            ),
            (
                'keycloak' if nginxAuthMode.startswith('keycloak') else None,
                "Configure Keycloak",
                False,
                bool(
                    nginxAuthMode.startswith('keycloak')
                    or args.authKeycloakRealm
                    or args.authKeycloakRedirectUri
                    or args.authKeycloakUrl
                    or args.authKeycloakClientId
                    or args.authKeycloakClientSecret
                    or args.authKeycloakBootstrapUser
                    or args.authKeycloakBootstrapPassword
                    or args.authRequireGroup
                    or args.authRequireRole
                ),
                [],
            ),
            (
                'rbac' if nginxAuthMode.startswith('keycloak') else None,
                "Configure Role-Based Access Control",
                False,
                bool(nginxAuthMode.startswith('keycloak') or args.authRbacEnabled),
                [],
            ),
            (
                'remoteos' if any('-remote' in x for x in [osPrimaryMode, osSecondaryMode]) else None,
                "Configure remote primary or secondary OpenSearch/Elasticsearch instance",
                False,
                False,
                [],
            ),
            (
                'localos' if osPrimaryMode == 'opensearch-local' else None,
                "(Re)generate internal passwords for local primary OpenSearch instance",
                False,
                (not args.cmdAuthSetupNonInteractive) or args.authGenOpensearchCreds,
                [os.path.join(GetMalcolmPath(), '.opensearch.primary.curlrc')],
            ),
            (
                'email',
                "Store username/password for OpenSearch Alerting email sender account",
                False,
                False,
                [],
            ),
            (
                'netbox' if (netboxMode == 'local') else None,
                "(Re)generate internal passwords for NetBox",
                False,
                (not args.cmdAuthSetupNonInteractive) or args.authGenNetBoxPasswords,
                [],
            ),
            (
                'netbox-remote-token' if (netboxMode == 'remote') else None,
                "Store API token for remote NetBox instance",
                False,
                (not args.cmdAuthSetupNonInteractive) or (bool(args.authNetBoxRemoteToken)),
                [],
            ),
            (
                'keycloakdb' if nginxAuthMode == 'keycloak' else None,
                "(Re)generate internal passwords for Keycloak's PostgreSQL database",
                False,
                (not args.cmdAuthSetupNonInteractive) or args.authGenKeycloakDbPassword,
                [],
            ),
            (
                'postgres',
                "(Re)generate internal superuser passwords for PostgreSQL",
                False,
                (not args.cmdAuthSetupNonInteractive) or args.authGenPostgresPassword,
                [],
            ),
            (
                'redis',
                "(Re)generate internal passwords for Redis",
                False,
                (not args.cmdAuthSetupNonInteractive) or args.authGenRedisPassword,
                [],
            ),
            (
                'arkime',
                "Store password hash secret for Arkime viewer cluster",
                False,
                (not args.cmdAuthSetupNonInteractive) or bool(args.authArkimePassword),
                [],
            ),
            (
                'txfwcerts' if txRxScript else None,
                "Transfer self-signed client certificates to a remote log forwarder",
                False,
                False,
                [],
            ),
        ]
        if x[0]
    ]

    authConfigChoice = (
        ChooseOne(
            'Configure Authentication',
            choices=[x[:-2] for x in authConfigChoices],
        )
        if not args.cmdAuthSetupNonInteractive
        else 'all'
    )
    noninteractiveBehavior = (
        UserInputDefaultsBehavior.DefaultsPrompt
        | UserInputDefaultsBehavior.DefaultsAccept
        | UserInputDefaultsBehavior.DefaultsNonInteractive
    )
    defaultBehavior = (
        UserInputDefaultsBehavior.DefaultsPrompt if not args.cmdAuthSetupNonInteractive else noninteractiveBehavior
    )

    try:
        for authItem in authConfigChoices[1:]:
            if (
                (authConfigChoice == 'all')
                and YesOrNo(
                    f'{authItem[1]}?',
                    default=authItem[3],
                    defaultBehavior=(
                        noninteractiveBehavior
                        if (authItem[4] and (not all([os.path.isfile(x) for x in authItem[4]])))
                        else defaultBehavior
                    ),
                )
            ) or ((authConfigChoice != 'all') and (authConfigChoice == authItem[0])):

                if authItem[0] == 'method':

                    authMethodChoices = (
                        (
                            'basic',
                            "Use basic HTTP authentication",
                            (not nginxAuthMode) or (nginxAuthMode.lower() == 'basic'),
                        ),
                        (
                            'ldap',
                            "Use Lightweight Directory Access Protocol (LDAP) for authentication",
                            (nginxAuthMode.lower() == 'ldap'),
                        ),
                        (
                            'keycloak',
                            "Use embedded Keycloak for authentication",
                            (nginxAuthMode.lower() == 'keycloak'),
                        ),
                        (
                            'keycloak_remote',
                            "Use remote Keycloak for authentication",
                            (nginxAuthMode.lower() == 'keycloak_remote'),
                        ),
                        (
                            'no_authentication',
                            "Disable authentication",
                            (nginxAuthMode.lower() == 'no_authentication'),
                        ),
                    )
                    newNginxAuthMode = None if (args.composeProfile == PROFILE_MALCOLM) else 'basic'
                    loopBreaker = CountUntilException(MaxAskForValueCount, 'Invalid authentication method')
                    while (
                        (not args.cmdAuthSetupNonInteractive)
                        and (newNginxAuthMode not in list([x[0] for x in authMethodChoices]))
                        and loopBreaker.increment()
                    ):
                        newNginxAuthMode = ChooseOne(
                            'Select authentication method',
                            choices=authMethodChoices,
                        ).lower()
                    if newNginxAuthMode:
                        nginxAuthMode = newNginxAuthMode

                    ldapStartTLS = False
                    if nginxAuthMode == 'ldap':
                        ldapStartTLS = YesOrNo(
                            'Use StartTLS (rather than LDAPS) for LDAP connection security?',
                            default=args.ldapStartTLS,
                            defaultBehavior=defaultBehavior,
                        )

                        ldapConfFile = os.path.join(GetMalcolmPath(), os.path.join('nginx', 'nginx_ldap.conf'))
                        if (
                            (not os.path.isfile(ldapConfFile))
                            or (os.path.getsize(ldapConfFile) == 0)
                            or YesOrNo(
                                'nginx_ldap.conf already exists, overwrite with fresh template?',
                                default=False,
                                defaultBehavior=defaultBehavior,
                            )
                        ):
                            ldapServerTypeDefault = args.ldapServerType if args.ldapServerType else 'winldap'
                            if not args.cmdAuthSetupNonInteractive:
                                allowedLdapModes = ('winldap', 'openldap')
                                ldapServerType = None
                                loopBreaker = CountUntilException(
                                    MaxAskForValueCount, 'Invalid LDAP server compatibility type'
                                )
                                while ldapServerType not in allowedLdapModes and loopBreaker.increment():
                                    ldapServerType = ChooseOne(
                                        'Select LDAP server compatibility type',
                                        choices=[(x, '', x == ldapServerTypeDefault) for x in allowedLdapModes],
                                    )
                            else:
                                ldapServerType = ldapServerTypeDefault

                            # stub out default LDAP stuff (they'll have to edit it by hand later)
                            ldapProto = 'ldap://' if ldapStartTLS else 'ldaps://'
                            ldapHost = "ds.example.com"
                            ldapPort = 3268 if ldapStartTLS else 3269
                            if ldapServerType == "openldap":
                                ldapUri = 'DC=example,DC=com?uid?sub?(objectClass=posixAccount)'
                                ldapGroupAttr = "memberUid"
                                ldapGroupAttrIsDN = "off"
                            else:
                                ldapUri = 'DC=example,DC=com?sAMAccountName?sub?(objectClass=person)'
                                ldapGroupAttr = "member"
                                ldapGroupAttrIsDN = "on"
                            with open(ldapConfFile, 'w') as f:
                                f.write('# This is a sample configuration for the ldap_server section of nginx.conf.\n')
                                f.write(
                                    '# Yours will vary depending on how your Active Directory/LDAP server is configured.\n'
                                )
                                f.write(
                                    '# See https://github.com/kvspb/nginx-auth-ldap#available-config-parameters for options.\n\n'
                                )
                                f.write('ldap_server ad_server {\n')
                                f.write(f'  url "{ldapProto}{ldapHost}:{ldapPort}/{ldapUri}";\n\n')
                                f.write('  binddn "bind_dn";\n')
                                f.write('  binddn_passwd "bind_dn_password";\n\n')
                                f.write(f'  group_attribute {ldapGroupAttr};\n')
                                f.write(f'  group_attribute_is_dn {ldapGroupAttrIsDN};\n')
                                f.write('  require group "CN=malcolm,OU=groups,DC=example,DC=com";\n')
                                f.write('  require valid_user;\n')
                                f.write('  satisfy all;\n')
                                f.write('}\n\n')
                                f.write('auth_ldap_cache_enabled on;\n')
                                f.write('auth_ldap_cache_expiration_time 10000;\n')
                                f.write('auth_ldap_cache_size 1000;\n')
                            os.chmod(ldapConfFile, stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH)

                    # write env files
                    with pushd(args.configDir):
                        UpdateEnvFiles(
                            [
                                EnvValue(
                                    True,
                                    authCommonEnvFile,
                                    'NGINX_AUTH_MODE',
                                    nginxAuthMode,
                                ),
                                EnvValue(
                                    True,
                                    nginxEnvFile,
                                    'NGINX_LDAP_TLS_STUNNEL',
                                    TrueOrFalseNoQuote((nginxAuthMode == 'ldap') and ldapStartTLS),
                                ),
                            ],
                            stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH,
                        )

                elif authItem[0] == 'admin':
                    # prompt username and password
                    usernamePrevious = None
                    password = None
                    passwordConfirm = None
                    passwordEncrypted = ''

                    loopBreaker = CountUntilException(MaxAskForValueCount, 'Invalid administrator username')
                    while loopBreaker.increment():
                        username = AskForString(
                            f"Administrator username (between {UsernameMinLen} and {UsernameMaxLen} characters; alphanumeric, _, -, and . allowed)",
                            default=args.authUserName,
                            defaultBehavior=defaultBehavior,
                        )
                        if UsernameRegex.match(username) and (UsernameMinLen <= len(username) <= UsernameMaxLen):
                            break

                    loopBreaker = CountUntilException(MaxAskForValueCount, 'Invalid password')
                    while (not args.cmdAuthSetupNonInteractive) and loopBreaker.increment():
                        password = AskForPassword(
                            f"{username} password  (between {PasswordMinLen} and {PasswordMaxLen} characters): ",
                            default='',
                            defaultBehavior=defaultBehavior,
                        )
                        if PasswordMinLen <= len(password) <= PasswordMaxLen:
                            passwordConfirm = AskForPassword(
                                f"{username} password (again): ",
                                default='',
                                defaultBehavior=defaultBehavior,
                            )
                            if password and (password == passwordConfirm):
                                break

                    # get previous admin username to remove from htpasswd file if it's changed
                    authEnvFile = os.path.join(args.configDir, 'auth.env')
                    prevAuthInfo = defaultdict(str)
                    if os.path.isfile(authEnvFile):
                        prevAuthInfo.update(dotenvImported.dotenv_values(authEnvFile))
                        if prevAuthInfo['MALCOLM_USERNAME']:
                            usernamePrevious = prevAuthInfo['MALCOLM_USERNAME']

                    # get openssl hash of password
                    if args.cmdAuthSetupNonInteractive:
                        passwordEncrypted = args.authPasswordOpenssl
                    else:
                        err, out = run_process(
                            [opensslBin, 'passwd', '-1', '-stdin'],
                            stdin=password,
                            stderr=False,
                            debug=log_level_is_debug(args.verbose),
                        )
                        if (err == 0) and (len(out) > 0) and (len(out[0]) > 0):
                            passwordEncrypted = out[0]
                        else:
                            raise Exception('Unable to generate password hash with openssl')

                    # write auth.env (used by htadmin and file-upload containers)
                    UpdateEnvFiles(
                        [
                            EnvValue(
                                True,
                                authEnvFile,
                                'MALCOLM_USERNAME',
                                username,
                            ),
                            EnvValue(
                                True,
                                authEnvFile,
                                'MALCOLM_PASSWORD',
                                b64encode(passwordEncrypted.encode()).decode("ascii"),
                            ),
                        ],
                        stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH,
                    )

                    # create or update the htpasswd file
                    htpasswdFile = os.path.join(GetMalcolmPath(), os.path.join('nginx', 'htpasswd'))
                    if not args.cmdAuthSetupNonInteractive:
                        htpasswdCmd = ['htpasswd', '-i', '-B', htpasswdFile, username]
                        if not os.path.isfile(htpasswdFile):
                            htpasswdCmd.insert(1, '-c')
                        err, out = run_process(
                            htpasswdCmd, stdin=password, stderr=True, debug=log_level_is_debug(args.verbose)
                        )
                        if err != 0:
                            raise Exception(f'Unable to generate htpasswd file: {out}')

                    if (
                        (usernamePrevious is not None) and (usernamePrevious != username)
                    ) or args.cmdAuthSetupNonInteractive:
                        htpasswdLines = list()
                        if os.path.isfile(htpasswdFile):
                            with open(htpasswdFile, 'r') as f:
                                htpasswdLines = f.readlines()
                        with open(htpasswdFile, 'w') as f:
                            if args.cmdAuthSetupNonInteractive and username and args.authPasswordHtpasswd:
                                f.write(f'{username}:{args.authPasswordHtpasswd}')
                            for line in htpasswdLines:
                                # if the admininstrator username has changed, remove the previous administrator username from htpasswd
                                if (
                                    (usernamePrevious is not None)
                                    and (usernamePrevious != username)
                                    and (not line.startswith(f"{usernamePrevious}:"))
                                ):
                                    f.write(line)

                    # touch the metadata file
                    touch(os.path.join(GetMalcolmPath(), os.path.join('htadmin', 'metadata')))

                    if nginxAuthMode in ['basic', 'true']:
                        DisplayMessage(
                            'Additional local accounts can be created at https://localhost/auth/ when Malcolm is running',
                            defaultBehavior=defaultBehavior,
                        )
                    else:
                        DisplayMessage(
                            f'Authentication method is "{nginxAuthMode}", local credentials are only valid for OpenSearch endpoint, if enabled.',
                            defaultBehavior=defaultBehavior,
                        )

                # generate HTTPS self-signed certificates
                elif authItem[0] == 'webcerts':
                    with pushd(os.path.join(GetMalcolmPath(), os.path.join('nginx', 'certs'))):
                        # remove previous files
                        for oldfile in glob.glob("*.pem"):
                            os.remove(oldfile)

                        # generate dhparam -------------------------------
                        err, out = run_process(
                            [opensslBin, 'dhparam', '-out', 'dhparam.pem', '2048'],
                            stderr=True,
                            debug=log_level_is_debug(args.verbose),
                        )
                        if err != 0:
                            raise Exception(f'Unable to generate dhparam.pem file: {out}')

                        # generate key/cert -------------------------------
                        err, out = run_process(
                            [
                                opensslBin,
                                'req',
                                '-subj',
                                '/CN=localhost',
                                '-x509',
                                '-newkey',
                                'rsa:4096',
                                '-nodes',
                                '-keyout',
                                'key.pem',
                                '-out',
                                'cert.pem',
                                '-days',
                                '3650',
                            ],
                            stderr=True,
                            debug=log_level_is_debug(args.verbose),
                        )
                        if err != 0:
                            raise Exception(f'Unable to generate key.pem/cert.pem file(s): {out}')

                elif authItem[0] == 'fwcerts':
                    with pushd(logstashPath):
                        # make clean to clean previous files
                        for pat in ['*.srl', '*.csr', '*.key', '*.crt', '*.pem']:
                            for oldfile in glob.glob(pat):
                                os.remove(oldfile)

                        # -----------------------------------------------
                        # generate new ca/server/client certificates/keys
                        # ca -------------------------------
                        err, out = run_process(
                            [opensslBin, 'genrsa', '-out', 'ca.key', '2048'],
                            stderr=True,
                            debug=log_level_is_debug(args.verbose),
                        )
                        if err != 0:
                            raise Exception(f'Unable to generate ca.key: {out}')

                        err, out = run_process(
                            [
                                opensslBin,
                                'req',
                                '-x509',
                                '-new',
                                '-nodes',
                                '-key',
                                'ca.key',
                                '-sha256',
                                '-days',
                                '9999',
                                '-subj',
                                '/C=US/ST=ID/O=sensor/OU=ca',
                                '-out',
                                'ca.crt',
                            ],
                            stderr=True,
                            debug=log_level_is_debug(args.verbose),
                        )
                        if err != 0:
                            raise Exception(f'Unable to generate ca.crt: {out}')

                        # server -------------------------------
                        err, out = run_process(
                            [opensslBin, 'genrsa', '-out', 'server.key', '2048'],
                            stderr=True,
                            debug=log_level_is_debug(args.verbose),
                        )
                        if err != 0:
                            raise Exception(f'Unable to generate server.key: {out}')

                        err, out = run_process(
                            [
                                opensslBin,
                                'req',
                                '-sha512',
                                '-new',
                                '-key',
                                'server.key',
                                '-out',
                                'server.csr',
                                '-config',
                                'server.conf',
                            ],
                            stderr=True,
                            debug=log_level_is_debug(args.verbose),
                        )
                        if err != 0:
                            raise Exception(f'Unable to generate server.csr: {out}')

                        err, out = run_process(
                            [
                                opensslBin,
                                'x509',
                                '-days',
                                '3650',
                                '-req',
                                '-sha512',
                                '-in',
                                'server.csr',
                                '-CAcreateserial',
                                '-CA',
                                'ca.crt',
                                '-CAkey',
                                'ca.key',
                                '-out',
                                'server.crt',
                                '-extensions',
                                'v3_req',
                                '-extfile',
                                'server.conf',
                            ],
                            stderr=True,
                            debug=log_level_is_debug(args.verbose),
                        )
                        if err != 0:
                            raise Exception(f'Unable to generate server.crt: {out}')

                        shutil.move("server.key", "server.key.pem")
                        err, out = run_process(
                            [opensslBin, 'pkcs8', '-in', 'server.key.pem', '-topk8', '-nocrypt', '-out', 'server.key'],
                            stderr=True,
                            debug=log_level_is_debug(args.verbose),
                        )
                        if err != 0:
                            raise Exception(f'Unable to generate server.key: {out}')

                        # client -------------------------------
                        # mkdir filebeat/certs if it doesn't exist
                        try:
                            os.makedirs(filebeatPath)
                        except OSError as exc:
                            if (exc.errno == errno.EEXIST) and os.path.isdir(filebeatPath):
                                pass
                            else:
                                raise

                        # remove previous files in filebeat/certs
                        for oldfile in glob.glob(os.path.join(filebeatPath, "*")):
                            os.remove(oldfile)

                        clientKey, clientCrt, clientCaCrt = clientForwarderCertGen(
                            caCrt=os.path.join(logstashPath, 'ca.crt'),
                            caKey=os.path.join(logstashPath, 'ca.key'),
                            clientConf=os.path.join(logstashPath, 'client.conf'),
                            outputDir=filebeatPath,
                        )
                        if (
                            (not clientKey)
                            or (not clientCrt)
                            or (not clientCaCrt)
                            or (not os.path.isfile(clientKey))
                            or (not os.path.isfile(clientCrt))
                            or (not os.path.isfile(clientCaCrt))
                        ):
                            raise Exception(f'Unable to generate client key/crt')
                        # -----------------------------------------------

                # create and populate connection parameters file for remote OpenSearch instance(s)
                elif authItem[0] == 'remoteos':
                    for instance in ['primary', 'secondary']:
                        openSearchCredFileName = os.path.join(GetMalcolmPath(), f'.opensearch.{instance}.curlrc')
                        if YesOrNo(
                            f'Store username/password for {instance} remote OpenSearch/Elasticsearch instance?',
                            default=False,
                            defaultBehavior=defaultBehavior,
                        ):
                            prevCurlContents = ParseCurlFile(openSearchCredFileName)

                            # prompt host, username and password
                            esUsername = None
                            esPassword = None
                            esPasswordConfirm = None

                            loopBreaker = CountUntilException(
                                MaxAskForValueCount, 'Invalid OpenSearch/Elasticsearch username'
                            )
                            while loopBreaker.increment():
                                esUsername = AskForString(
                                    "OpenSearch/Elasticsearch username",
                                    default=prevCurlContents['user'],
                                    defaultBehavior=defaultBehavior,
                                )
                                if (len(esUsername) > 0) and (':' not in esUsername):
                                    break
                                logging.error("Username is blank (or contains a colon, which is not allowed)")

                            loopBreaker = CountUntilException(
                                MaxAskForValueCount, 'Invalid OpenSearch/Elasticsearch password'
                            )
                            while loopBreaker.increment():
                                esPassword = AskForPassword(
                                    f"{esUsername} password: ",
                                    default='',
                                    defaultBehavior=defaultBehavior,
                                )
                                if (
                                    (len(esPassword) == 0)
                                    and (prevCurlContents['password'] is not None)
                                    and YesOrNo(
                                        f'Use previously entered password for "{esUsername}"?',
                                        default=True,
                                        defaultBehavior=defaultBehavior,
                                    )
                                ):
                                    esPassword = prevCurlContents['password']
                                    esPasswordConfirm = esPassword
                                else:
                                    esPasswordConfirm = AskForPassword(
                                        f"{esUsername} password (again): ",
                                        default='',
                                        defaultBehavior=defaultBehavior,
                                    )
                                if (esPassword == esPasswordConfirm) and (len(esPassword) > 0):
                                    break
                                logging.error("Passwords do not match")

                            esSslVerify = YesOrNo(
                                'Require SSL certificate validation for OpenSearch/Elasticsearch communication?',
                                default=False,
                                defaultBehavior=defaultBehavior,
                            )

                            with open(openSearchCredFileName, 'w') as f:
                                f.write(f'user: "{EscapeForCurl(esUsername)}:{EscapeForCurl(esPassword)}"\n')
                                if not esSslVerify:
                                    f.write('insecure\n')

                        else:
                            try:
                                os.remove(openSearchCredFileName)
                            except Exception:
                                pass
                        touch(openSearchCredFileName)
                        os.chmod(openSearchCredFileName, stat.S_IRUSR | stat.S_IWUSR)

                # OpenSearch internal service account credentials
                elif authItem[0] == 'localos':
                    esUsername = 'malcolm_internal'
                    esPassword = str(
                        ''.join(secrets.choice(string.ascii_letters + string.digits + '_') for i in range(36)),
                    )
                    openSearchCredFileName = os.path.join(GetMalcolmPath(), f'.opensearch.primary.curlrc')
                    with open(openSearchCredFileName, 'w') as f:
                        f.write(f'user: "{EscapeForCurl(esUsername)}:{EscapeForCurl(esPassword)}"\n')
                        f.write('insecure\n')
                    touch(openSearchCredFileName)
                    os.chmod(openSearchCredFileName, stat.S_IRUSR | stat.S_IWUSR)

                # OpenSearch authenticate sender account credentials
                # https://opensearch.org/docs/latest/monitoring-plugins/alerting/monitors/#authenticate-sender-account
                elif authItem[0] == 'email':
                    # prompt username and password
                    emailPassword = None
                    emailPasswordConfirm = None
                    emailSender = AskForString("OpenSearch alerting email sender name", defaultBehavior=defaultBehavior)
                    loopBreaker = CountUntilException(MaxAskForValueCount, 'Invalid Email account username')
                    while loopBreaker.increment():
                        emailUsername = AskForString("Email account username", defaultBehavior=defaultBehavior)
                        if len(emailUsername) > 0:
                            break

                    loopBreaker = CountUntilException(MaxAskForValueCount, 'Invalid Email account password')
                    while loopBreaker.increment():
                        emailPassword = AskForPassword(
                            f"{emailUsername} password: ",
                            default='',
                            defaultBehavior=defaultBehavior,
                        )
                        emailPasswordConfirm = AskForPassword(
                            f"{emailUsername} password (again): ",
                            default='',
                            defaultBehavior=defaultBehavior,
                        )
                        if emailPassword and (emailPassword == emailPasswordConfirm):
                            break
                        logging.error("Passwords do not match")

                    # create OpenSearch keystore file, don't complain if it already exists, and set the keystore items
                    usernameKey = f'plugins.alerting.destination.email.{emailSender}.username'
                    passwordKey = f'plugins.alerting.destination.email.{emailSender}.password'

                    keystore_op('opensearch', True, 'create', stdin='N')
                    keystore_op('opensearch', True, 'remove', usernameKey)
                    keystore_op('opensearch', True, 'add', usernameKey, '--stdin', stdin=emailUsername)
                    keystore_op('opensearch', True, 'remove', passwordKey)
                    keystore_op('opensearch', True, 'add', passwordKey, '--stdin', stdin=emailPassword)
                    success, results = keystore_op('opensearch', True, 'list')
                    results = [
                        x
                        for x in results
                        if x and (not x.upper().startswith('WARNING')) and (not x.upper().startswith('KEYSTORE'))
                    ]
                    if success and (usernameKey in results) and (passwordKey in results):
                        logging.info(f"Email alert sender account variables stored: {', '.join(results)}")
                    else:
                        logging.error("Failed to store email alert sender account variables:\n")
                        logging.error("\n".join(results))

                elif authItem[0] == 'keycloak':
                    with pushd(args.configDir):
                        keycloakEnvFile = 'keycloak.env'
                        authCommonEnvFile = 'auth-common.env'
                        # changeMade tracks if the user made changes to the vars in an .env file
                        #   e.g., {'keycloak.env': True, 'auth-common.env': False}
                        changeMade = defaultdict(lambda: False)
                        # envValues is a dict (keyed by filename) of dicts of variable name/value pairs
                        #   e.g., {"keycloak.env": {"foo": "bar"}, "auth-common.env": {"bar": "baz"}}
                        envValues = defaultdict(lambda: defaultdict(str))

                        if os.path.isfile(keycloakEnvFile):
                            envValues[keycloakEnvFile].update(dotenvImported.dotenv_values(keycloakEnvFile))

                        if os.path.isfile(authCommonEnvFile):
                            envValues[authCommonEnvFile].update(dotenvImported.dotenv_values(authCommonEnvFile))

                        keyCloakOpts = (
                            # opt[0] - human readable description
                            # opt[1] - env. file
                            # opt[2] - env. variable name
                            # opt[3] - can be blank
                            # opt[4] - is a secret
                            # opt[5] - default value
                            (
                                'Keycloak realm',
                                keycloakEnvFile,
                                'KEYCLOAK_AUTH_REALM',
                                False,
                                False,
                                (
                                    args.authKeycloakRealm
                                    if args.authKeycloakRealm
                                    else envValues[keycloakEnvFile].get('KEYCLOAK_AUTH_REALM', 'master')
                                ),
                            ),
                            (
                                'Keycloak redirect URI',
                                keycloakEnvFile,
                                'KEYCLOAK_AUTH_REDIRECT_URI',
                                False,
                                False,
                                (
                                    args.authKeycloakRedirectUri
                                    if args.authKeycloakRedirectUri
                                    else envValues[keycloakEnvFile].get('KEYCLOAK_AUTH_REDIRECT_URI', '/index.html')
                                ),
                            ),
                            (
                                'Keycloak URL',
                                keycloakEnvFile,
                                'KEYCLOAK_AUTH_URL',
                                False,
                                False,
                                (
                                    args.authKeycloakUrl
                                    if args.authKeycloakUrl
                                    else envValues[keycloakEnvFile]['KEYCLOAK_AUTH_URL']
                                ),
                            ),
                            (
                                'Keycloak client ID',
                                keycloakEnvFile,
                                'KEYCLOAK_CLIENT_ID',
                                True,
                                False,
                                (
                                    args.authKeycloakClientId
                                    if args.authKeycloakClientId
                                    else envValues[keycloakEnvFile]['KEYCLOAK_CLIENT_ID']
                                ),
                            ),
                            (
                                'Keycloak client secret (blank to retain the previous value)',
                                keycloakEnvFile,
                                'KEYCLOAK_CLIENT_SECRET',
                                True,
                                True,
                                (
                                    args.authKeycloakClientSecret
                                    if args.authKeycloakClientSecret
                                    else envValues[keycloakEnvFile]['KEYCLOAK_CLIENT_SECRET']
                                ),
                            ),
                            (
                                'Required group(s) to which users must belong',
                                authCommonEnvFile,
                                'NGINX_REQUIRE_GROUP',
                                True,
                                False,
                                (
                                    args.authRequireGroup
                                    if args.authRequireGroup
                                    else envValues[authCommonEnvFile]['NGINX_REQUIRE_GROUP']
                                ),
                            ),
                            (
                                'Required role(s) which users must be assigned',
                                authCommonEnvFile,
                                'NGINX_REQUIRE_ROLE',
                                True,
                                False,
                                (
                                    args.authRequireRole
                                    if args.authRequireRole
                                    else envValues[authCommonEnvFile]['NGINX_REQUIRE_ROLE']
                                ),
                            ),
                            (
                                'Temporary Keycloak admin bootstrap username',
                                keycloakEnvFile,
                                'KC_BOOTSTRAP_ADMIN_USERNAME',
                                True,
                                False,
                                (
                                    args.authKeycloakBootstrapUser
                                    if args.authKeycloakBootstrapUser
                                    else envValues[keycloakEnvFile]['KC_BOOTSTRAP_ADMIN_USERNAME']
                                ),
                            ),
                            (
                                'Temporary Keycloak admin bootstrap password (blank to retain the previous value)',
                                keycloakEnvFile,
                                'KC_BOOTSTRAP_ADMIN_PASSWORD',
                                True,
                                True,
                                (
                                    args.authKeycloakBootstrapPassword
                                    if args.authKeycloakBootstrapPassword
                                    else envValues[keycloakEnvFile]['KC_BOOTSTRAP_ADMIN_PASSWORD']
                                ),
                            ),
                        )
                        # see comment on keyCloakOpts above for definitions
                        for opt in keyCloakOpts:
                            if (nginxAuthMode == 'keycloak') or (not opt[2].startswith('KC_')):
                                loopBreaker = CountUntilException(MaxAskForValueCount, f'Invalid {opt[0]}')
                                while loopBreaker.increment():
                                    tmpVal = (
                                        AskForString(
                                            opt[0],
                                            default=opt[5],
                                            defaultBehavior=defaultBehavior,
                                        )
                                        if (opt[4] == False)
                                        else AskForPassword(
                                            opt[0],
                                            default=opt[5],
                                            defaultBehavior=defaultBehavior,
                                        )
                                    )

                                    if (len(tmpVal) == 0) and (opt[4] == True):
                                        # if this is a password/secret and they
                                        #   leave it blank, retain the old value
                                        tmpVal = opt[5]

                                    if (len(tmpVal) > 0) or (opt[3] == True):
                                        if envValues[opt[1]][opt[2]] != tmpVal:
                                            changeMade[opt[1]] = True
                                        envValues[opt[1]][opt[2]] = tmpVal
                                        break
                                    else:
                                        logging.error(f"{opt[0]} cannot be empty")

                        # update .env file(s) with the new values, if any
                        for filename in [f for f, changed in changeMade.items() if changed]:
                            UpdateEnvFiles(
                                [
                                    EnvValue(
                                        True,
                                        filename,
                                        k,
                                        v,
                                    )
                                    for k, v in envValues[filename].items()
                                ],
                                stat.S_IRUSR | stat.S_IWUSR,
                            )

                        if not nginxAuthMode.startswith('keycloak'):
                            DisplayMessage(
                                f'Authentication method is "{nginxAuthMode}", Keycloak configuration will have no effect.',
                                defaultBehavior=defaultBehavior,
                            )

                elif authItem[0] == 'rbac':
                    authRbacEnabled = YesOrNo(
                        'Enable role-based access control?',
                        default=args.authRbacEnabled,
                        defaultBehavior=defaultBehavior,
                    )
                    with pushd(args.configDir):
                        UpdateEnvFiles(
                            [
                                EnvValue(
                                    True,
                                    authCommonEnvFile,
                                    'ROLE_BASED_ACCESS',
                                    str(authRbacEnabled).lower(),
                                ),
                            ],
                            stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH,
                        )

                    if authRbacEnabled:
                        DisplayMessage(
                            f'See Keycloak or {os.path.basename(authCommonEnvFile)} for realm roles.',
                            defaultBehavior=defaultBehavior,
                        )
                        if not nginxAuthMode.startswith('keycloak'):
                            DisplayMessage(
                                f'Authentication method is "{nginxAuthMode}", RBAC settings will have no effect.',
                                defaultBehavior=defaultBehavior,
                            )

                elif authItem[0] in ['netbox', 'postgres', 'keycloakdb']:
                    with pushd(args.configDir):

                        # Check for the presence of existing passwords prior to setting new NetBox/PostgreSQL passwords.
                        #   see cisagov/Malcolm#565 (NetBox fails to start due to invalid internal password
                        #   if NetBox passwords have been changed).
                        preExistingPasswordFound = False
                        if authItem[0] == 'netbox':
                            preExistingPasswords = {
                                'postgres.env': (
                                    'POSTGRES_NETBOX_PASSWORD',
                                    'DB_PASSWORD',
                                ),
                                'netbox-secret.env': (
                                    'SECRET_KEY',
                                    'SUPERUSER_PASSWORD',
                                    'SUPERUSER_API_TOKEN',
                                ),
                            }
                        elif authItem[0] == 'keycloakdb':
                            preExistingPasswords = {
                                'postgres.env': ('POSTGRES_KEYCLOAK_PASSWORD',),
                            }
                        else:
                            preExistingPasswords = {
                                'postgres.env': ('POSTGRES_PASSWORD',),
                            }

                        for envFile, keys in preExistingPasswords.items():
                            envValues = defaultdict(None)
                            if os.path.isfile(envFile):
                                envValues.update(dotenvImported.dotenv_values(envFile))
                            for key in keys:
                                if keyVal := envValues.get(key, None):
                                    if all(c in "xX" for c in keyVal) or (
                                        (authItem[0] == 'netbox')
                                        and (key == 'SUPERUSER_PASSWORD')
                                        and (keyVal == 'admin')
                                    ):
                                        # all good, no password has been set yet
                                        pass
                                    else:
                                        # preexisting password was found, need to warn the user
                                        preExistingPasswordFound = True

                        if (not preExistingPasswordFound) or YesOrNo(
                            f'Internal passwords for {authItem[0]} already exist. Overwriting them will break access to a populated {authItem[0]} database. Are you sure?',
                            default=args.cmdAuthSetupNonInteractive,
                            defaultBehavior=defaultBehavior,
                        ):
                            pwAlphabet = string.ascii_letters + string.digits + '_'
                            apiKeyAlphabet = string.ascii_letters + string.digits + '%@<=>?~^_-'
                            if authItem[0] == 'netbox':
                                envFiles = [
                                    EnvValue(
                                        True,
                                        'postgres.env',
                                        'POSTGRES_NETBOX_PASSWORD',
                                        ''.join(secrets.choice(pwAlphabet) for i in range(24)),
                                    ),
                                    EnvValue(
                                        True,
                                        'netbox-secret.env',
                                        'SECRET_KEY',
                                        ''.join(secrets.choice(apiKeyAlphabet) for i in range(50)),
                                    ),
                                    EnvValue(
                                        True,
                                        'netbox-secret.env',
                                        'SUPERUSER_PASSWORD',
                                        ''.join(secrets.choice(pwAlphabet) for i in range(24)),
                                    ),
                                    EnvValue(
                                        True,
                                        'netbox-secret.env',
                                        'SUPERUSER_API_TOKEN',
                                        ''.join(secrets.choice(pwAlphabet) for i in range(40)),
                                    ),
                                ]
                            elif authItem[0] == 'keycloakdb':
                                envFiles = [
                                    EnvValue(
                                        True,
                                        'postgres.env',
                                        'POSTGRES_KEYCLOAK_PASSWORD',
                                        ''.join(secrets.choice(pwAlphabet) for i in range(24)),
                                    ),
                                ]
                            else:
                                envFiles = [
                                    EnvValue(
                                        True,
                                        'postgres.env',
                                        'POSTGRES_PASSWORD',
                                        ''.join(secrets.choice(pwAlphabet) for i in range(24)),
                                    ),
                                ]

                            UpdateEnvFiles(
                                envFiles,
                                stat.S_IRUSR | stat.S_IWUSR,
                            )

                        else:
                            DisplayMessage(
                                f'Internal passwords for {authItem[0]} were left unmodified.',
                                defaultBehavior=defaultBehavior,
                            )

                elif (authItem[0] == 'netbox-remote-token') and (netboxMode == 'remote'):
                    # prompt Token
                    netboxToken = ''

                    netboxSecretFile = os.path.join(args.configDir, 'netbox-secret.env')
                    prevNetboxToken = None
                    if os.path.isfile(netboxSecretFile):
                        prevNetboxToken = dotenvImported.dotenv_values(netboxSecretFile).get('NETBOX_TOKEN', '')

                    loopBreaker = CountUntilException(MaxAskForValueCount, 'Invalid NetBox API token')
                    while loopBreaker.increment():
                        netboxToken = AskForString(
                            f"Remote NetBox instance API token (40 characters): ",
                            default=args.authNetBoxRemoteToken or prevNetboxToken,
                            defaultBehavior=defaultBehavior,
                        ).lower()
                        if (len(netboxToken) == 40) and all(c in string.hexdigits for c in netboxToken):
                            break
                        logging.error("Invalid NetBox API token")

                    with pushd(args.configDir):
                        UpdateEnvFiles(
                            [
                                EnvValue(
                                    True,
                                    'netbox-secret.env',
                                    'NETBOX_TOKEN',
                                    netboxToken,
                                ),
                            ],
                            stat.S_IRUSR | stat.S_IWUSR,
                        )

                elif authItem[0] == 'redis':
                    with pushd(args.configDir):
                        UpdateEnvFiles(
                            [
                                EnvValue(
                                    True,
                                    'redis.env',
                                    'REDIS_PASSWORD',
                                    ''.join(
                                        secrets.choice(string.ascii_letters + string.digits + '_') for i in range(24)
                                    ),
                                ),
                            ],
                            stat.S_IRUSR | stat.S_IWUSR,
                        )

                elif authItem[0] == 'arkime':
                    # prompt password
                    arkimePassword = None
                    arkimePasswordConfirm = None

                    loopBreaker = CountUntilException(MaxAskForValueCount, 'Invalid password hash secret')
                    while (not args.cmdAuthSetupNonInteractive) and loopBreaker.increment():
                        arkimePassword = AskForPassword(
                            f"Arkime password hash secret: ",
                            default='',
                            defaultBehavior=defaultBehavior,
                        )
                        arkimePasswordConfirm = AskForPassword(
                            f"Arkime password hash secret (again): ",
                            default='',
                            defaultBehavior=defaultBehavior,
                        )
                        if arkimePassword and (arkimePassword == arkimePasswordConfirm):
                            break
                        logging.error("Passwords do not match")

                    if (not arkimePassword) and args.cmdAuthSetupNonInteractive and args.authArkimePassword:
                        arkimePassword = args.authArkimePassword

                    with pushd(args.configDir):
                        UpdateEnvFiles(
                            [
                                EnvValue(
                                    True,
                                    'arkime-secret.env',
                                    'ARKIME_PASSWORD_SECRET',
                                    arkimePassword,
                                ),
                            ],
                            stat.S_IRUSR | stat.S_IWUSR,
                        )

                elif authItem[0] == 'txfwcerts':
                    DisplayMessage(
                        'Run configure-capture on the remote log forwarder, select "Configure Forwarding," then "Receive client SSL files..."',
                        defaultBehavior=defaultBehavior,
                    )
                    # generate new client key/crt and send it
                    with tempfile.TemporaryDirectory(dir=MalcolmTmpPath) as tmpCertDir:
                        with pushd(tmpCertDir):
                            clientKey, clientCrt, clientCaCrt = clientForwarderCertGen(
                                caCrt=os.path.join(logstashPath, 'ca.crt'),
                                caKey=os.path.join(logstashPath, 'ca.key'),
                                clientConf=os.path.join(logstashPath, 'client.conf'),
                                outputDir=tmpCertDir,
                            )
                            if (
                                (not clientKey)
                                or (not clientCrt)
                                or (not clientCaCrt)
                                or (not os.path.isfile(clientKey))
                                or (not os.path.isfile(clientCrt))
                                or (not os.path.isfile(clientCaCrt))
                            ):
                                raise Exception(f'Unable to generate client key/crt')

                            with Popen(
                                [txRxScript, '-t', clientCaCrt, clientCrt, clientKey],
                                stdout=PIPE,
                                stderr=STDOUT,
                                bufsize=0 if MainDialog else -1,
                            ) as p:
                                if MainDialog:
                                    DisplayProgramBox(
                                        fileDescriptor=p.stdout.fileno(),
                                        text='ssl-client-transmit',
                                        clearScreen=True,
                                    )
                                else:
                                    while True:
                                        output = p.stdout.readline()
                                        if (len(output) == 0) and (p.poll() is not None):
                                            break
                                        if output:
                                            print(output.decode('utf-8').rstrip())
                                        else:
                                            time.sleep(0.5)

                                p.poll()
    finally:
        if MainDialog and (not args.cmdAuthSetupNonInteractive):
            ClearScreen()


###################################################################################################
# main
def main():
    global args
    global dockerBin
    global dockerComposeBin
    global dockerComposeYaml
    global kubeImported
    global opensslBin
    global orchMode
    global shuttingDown
    global yamlImported
    global dotenvImported

    # extract arguments from the command line
    # print (sys.argv[1:]);
    parser = argparse.ArgumentParser(
        description='Malcolm control script',
        add_help=True,
        usage=f'{ScriptName} <arguments>',
    )
    parser.add_argument(
        '--verbose',
        '-v',
        action='count',
        default=get_verbosity_env_var_count("VERBOSITY"),
        help='Increase verbosity (e.g., -v, -vv, etc.)',
    )
    parser.add_argument(
        '-f',
        '--file',
        required=False,
        dest='composeFile',
        metavar='<string>',
        type=str,
        default=os.getenv('MALCOLM_COMPOSE_FILE', os.path.join(GetMalcolmPath(), 'docker-compose.yml')),
        help='docker-compose or kubeconfig YML file',
    )
    parser.add_argument(
        '-e',
        '--environment-dir',
        required=False,
        dest='configDir',
        metavar='<string>',
        type=str,
        default=os.getenv('MALCOLM_CONFIG_DIR', None),
        help="Directory containing Malcolm's .env files",
    )
    parser.add_argument(
        '-p',
        '--profile',
        required=False,
        dest='composeProfile',
        metavar='<string>',
        type=str,
        default=None,
        help='docker-compose profile to enable',
    )
    parser.add_argument(
        '-r',
        '--runtime',
        required=False,
        dest='runtimeBin',
        metavar='<string>',
        type=str,
        default=os.getenv('MALCOLM_CONTAINER_RUNTIME', ''),
        help='Container runtime binary (e.g., docker, podman)',
    )
    parser.add_argument(
        '--no-tmpdir-override',
        required=False,
        dest='noTmpDirOverride',
        type=str2bool,
        nargs='?',
        const=True,
        default=str2bool(os.getenv('MALCOLM_NO_TMPDIR_OVERRIDE', default='False')),
        help="Don't override TMPDIR for compose commands",
    )

    operationsGroup = parser.add_argument_group('Runtime Control')
    operationsGroup.add_argument(
        '--start',
        dest='cmdStart',
        type=str2bool,
        nargs='?',
        const=True,
        default=False,
        help="Start Malcolm",
    )
    operationsGroup.add_argument(
        '--restart',
        dest='cmdRestart',
        type=str2bool,
        nargs='?',
        const=True,
        default=False,
        help="Stop and restart Malcolm",
    )
    operationsGroup.add_argument(
        '--stop',
        dest='cmdStop',
        type=str2bool,
        nargs='?',
        const=True,
        default=False,
        help="Stop Malcolm",
    )
    operationsGroup.add_argument(
        '--wipe',
        dest='cmdWipe',
        type=str2bool,
        nargs='?',
        const=True,
        default=False,
        help="Stop Malcolm and delete all data",
    )

    kubernetesGroup = parser.add_argument_group('Kubernetes')
    kubernetesGroup.add_argument(
        '-n',
        '--namespace',
        required=False,
        dest='namespace',
        metavar='<string>',
        type=str,
        default=os.getenv('MALCOLM_NAMESPACE', 'malcolm'),
        help="Kubernetes namespace",
    )
    kubernetesGroup.add_argument(
        '--skip-persistent-volume-checks',
        dest='skipPerVolChecks',
        type=str2bool,
        nargs='?',
        const=True,
        default=False,
        help='Skip checks for PersistentVolumes/PersistentVolumeClaims in manifests (only for "start" operation with Kubernetes)',
    )
    kubernetesGroup.add_argument(
        '--no-capture-pods',
        dest='noCapturePodsStart',
        type=str2bool,
        nargs='?',
        const=True,
        default=False,
        help='Do not deploy pods for traffic live capture/analysis (only for "start" operation with Kubernetes)',
    )
    kubernetesGroup.add_argument(
        '--no-capabilities',
        dest='noCapabilities',
        type=str2bool,
        nargs='?',
        const=True,
        default=False,
        help='Do not specify modifications to container capabilities (only for "start" operation with Kubernetes)',
    )
    kubernetesGroup.add_argument(
        '--inject-resources',
        dest='injectResources',
        type=str2bool,
        nargs='?',
        const=True,
        default=False,
        help='Inject container resources from kubernetes-container-resources.yml (only for "start" operation with Kubernetes)',
    )
    kubernetesGroup.add_argument(
        '--image-source',
        required=False,
        dest='imageSource',
        metavar='<string>',
        type=str,
        default=os.getenv('MALCOLM_IMAGE_SOURCE', None),
        help='Source for container images (e.g., "ghcr.io/idaholab/malcolm"; only for "start" operation with Kubernetes)',
    )
    kubernetesGroup.add_argument(
        '--image-tag',
        required=False,
        dest='imageTag',
        metavar='<string>',
        type=str,
        default=os.getenv('MALCOLM_IMAGE_TAG', None),
        help='Tag for container images (e.g., "25.09.0"; only for "start" operation with Kubernetes)',
    )
    kubernetesGroup.add_argument(
        '--delete-namespace',
        dest='deleteNamespace',
        type=str2bool,
        nargs='?',
        const=True,
        default=False,
        help='Delete Kubernetes namespace (only for "wipe" operation with Kubernetes)',
    )

    authSetupGroup = parser.add_argument_group('Authentication Setup')
    authSetupGroup.add_argument(
        '--auth',
        dest='cmdAuthSetup',
        type=str2bool,
        nargs='?',
        const=True,
        default=False,
        help="Configure Malcolm authentication",
    )
    authSetupGroup.add_argument(
        '--auth-noninteractive',
        dest='cmdAuthSetupNonInteractive',
        type=str2bool,
        nargs='?',
        const=True,
        default=False,
        help="Configure Malcolm authentication (noninteractive using arguments provided)",
    )
    authSetupGroup.add_argument(
        '--auth-method',
        dest='authMode',
        required=False,
        metavar='<basic|ldap|keycloak|keycloak_remote|no_authentication>',
        type=str,
        default='',
        help='Authentication method (for --auth-noninteractive)',
    )
    authSetupGroup.add_argument(
        '--auth-ldap-mode',
        dest='ldapServerType',
        required=False,
        metavar='<openldap|winldap>',
        type=str,
        default=None,
        help='LDAP server compatibility type (for --auth-noninteractive when --auth-method is ldap)',
    )
    authSetupGroup.add_argument(
        '--auth-ldap-start-tls',
        dest='ldapStartTLS',
        type=str2bool,
        metavar="true|false",
        nargs='?',
        const=True,
        default=False,
        help="Use StartTLS (rather than LDAPS) for LDAP connection security (for --auth-noninteractive when --auth-method is ldap)",
    )
    authSetupGroup.add_argument(
        '--auth-admin-username',
        dest='authUserName',
        required=False,
        metavar='<string>',
        type=str,
        default='',
        help='Administrator username (for --auth-noninteractive)',
    )
    authSetupGroup.add_argument(
        '--auth-admin-password-openssl',
        dest='authPasswordOpenssl',
        required=False,
        metavar='<string>',
        type=str,
        default='',
        help='Administrator password hash from "openssl -passwd -1" (for --auth-noninteractive)',
    )
    authSetupGroup.add_argument(
        '--auth-admin-password-htpasswd',
        dest='authPasswordHtpasswd',
        required=False,
        metavar='<string>',
        type=str,
        default='',
        help='Administrator password hash from "htpasswd -n -B username | cut -d: -f2" (for --auth-noninteractive)',
    )
    authSetupGroup.add_argument(
        '--auth-arkime-password',
        dest='authArkimePassword',
        required=False,
        metavar='<string>',
        type=str,
        default='Malcolm',
        help='Password hash secret for Arkime viewer cluster (for --auth-noninteractive)',
    )
    authSetupGroup.add_argument(
        '--auth-generate-webcerts',
        dest='authGenWebCerts',
        type=str2bool,
        nargs='?',
        const=True,
        default=False,
        help="(Re)generate self-signed certificates for HTTPS access (for --auth-noninteractive)",
    )
    authSetupGroup.add_argument(
        '--auth-generate-fwcerts',
        dest='authGenFwCerts',
        type=str2bool,
        nargs='?',
        const=True,
        default=False,
        help="(Re)generate self-signed certificates for a remote log forwarder",
    )
    authSetupGroup.add_argument(
        '--auth-netbox-token',
        dest='authNetBoxRemoteToken',
        required=False,
        metavar='<string>',
        type=str,
        default='',
        help='API token for remote NetBox instance (for --auth-noninteractive when NETBOX_MODE=remote in netbox-common.env)',
    )
    authSetupGroup.add_argument(
        '--auth-generate-netbox-passwords',
        dest='authGenNetBoxPasswords',
        type=str2bool,
        nargs='?',
        const=True,
        default=False,
        help="(Re)generate internal passwords for NetBox",
    )
    authSetupGroup.add_argument(
        '--auth-generate-redis-password',
        dest='authGenRedisPassword',
        type=str2bool,
        nargs='?',
        const=True,
        default=False,
        help="(Re)generate internal passwords for Redis",
    )
    authSetupGroup.add_argument(
        '--auth-generate-postgres-password',
        dest='authGenPostgresPassword',
        type=str2bool,
        nargs='?',
        const=True,
        default=False,
        help="(Re)generate internal superuser passwords for PostgreSQL",
    )
    authSetupGroup.add_argument(
        '--auth-generate-opensearch-internal-creds',
        dest='authGenOpensearchCreds',
        type=str2bool,
        nargs='?',
        const=True,
        default=False,
        help="(Re)generate internal credentials for embedded OpenSearch instance",
    )
    authSetupGroup.add_argument(
        '--auth-generate-keycloak-db-password',
        dest='authGenKeycloakDbPassword',
        type=str2bool,
        nargs='?',
        const=True,
        default=False,
        help="(Re)generate internal passwords for Keycloak's PostgreSQL database",
    )
    authSetupGroup.add_argument(
        '--auth-keycloak-realm',
        dest='authKeycloakRealm',
        required=False,
        metavar='<string>',
        type=str,
        default='',
        help='Keycloak realm',
    )
    authSetupGroup.add_argument(
        '--auth-keycloak-redirect-uri',
        dest='authKeycloakRedirectUri',
        required=False,
        metavar='<string>',
        type=str,
        default='',
        help='Keycloak redirect URI',
    )
    authSetupGroup.add_argument(
        '--auth-keycloak-url',
        dest='authKeycloakUrl',
        required=False,
        metavar='<string>',
        type=str,
        default='',
        help='Keycloak URL',
    )
    authSetupGroup.add_argument(
        '--auth-keycloak-client-id',
        dest='authKeycloakClientId',
        required=False,
        metavar='<string>',
        type=str,
        default='',
        help='Keycloak client ID',
    )
    authSetupGroup.add_argument(
        '--auth-keycloak-client-secret',
        dest='authKeycloakClientSecret',
        required=False,
        metavar='<string>',
        type=str,
        default='',
        help='Keycloak client secret',
    )
    authSetupGroup.add_argument(
        '--auth-keycloak-bootstrap-user',
        dest='authKeycloakBootstrapUser',
        required=False,
        metavar='<string>',
        type=str,
        default='',
        help='Temporary Keycloak admin bootstrap username',
    )
    authSetupGroup.add_argument(
        '--auth-keycloak-bootstrap-password',
        dest='authKeycloakBootstrapPassword',
        required=False,
        metavar='<string>',
        type=str,
        default='',
        help='Temporary Keycloak admin bootstrap password',
    )
    authSetupGroup.add_argument(
        '--auth-require-group',
        dest='authRequireGroup',
        required=False,
        metavar='<string>',
        type=str,
        default='',
        help='Required group(s) to which users must belong (--auth-method is keycloak|keycloak_remote)',
    )
    authSetupGroup.add_argument(
        '--auth-require-role',
        dest='authRequireRole',
        required=False,
        metavar='<string>',
        type=str,
        default='',
        help='Required role(s) which users must be assigned (--auth-method is keycloak|keycloak_remote)',
    )
    authSetupGroup.add_argument(
        '--auth-role-based-access-control',
        dest='authRbacEnabled',
        type=str2bool,
        nargs='?',
        const=True,
        default=False,
        help='Enable Role-Based Access Control (--auth-method is keycloak|keycloak_remote)',
    )

    logsAndStatusGroup = parser.add_argument_group('Logs and Status')
    logsAndStatusGroup.add_argument(
        '-l',
        '--logs',
        dest='cmdLogs',
        type=str2bool,
        nargs='?',
        const=True,
        default=False,
        help="Tail Malcolm logs",
    )
    logsAndStatusGroup.add_argument(
        '--lines',
        dest='logLineCount',
        type=posInt,
        nargs='?',
        const=False,
        default=None,
        help='Number of log lines to output. Outputs all lines by default (only for logs operation)',
    )
    logsAndStatusGroup.add_argument(
        '--status',
        dest='cmdStatus',
        type=str2bool,
        nargs='?',
        const=True,
        default=False,
        help="Display status of Malcolm components",
    )
    logsAndStatusGroup.add_argument(
        '--urls',
        dest='cmdPrintURLs',
        type=str2bool,
        nargs='?',
        const=True,
        default=False,
        help="Display Malcolm URLs",
    )
    logsAndStatusGroup.add_argument(
        '-s',
        '--service',
        required=False,
        dest='service',
        metavar='<string>',
        nargs='*',
        type=str,
        default=None,
        help='docker-compose service(s) (only applies to some operations)',
    )
    logsAndStatusGroup.add_argument(
        '-q',
        '--quiet',
        dest='quiet',
        type=str2bool,
        nargs='?',
        const=True,
        default=False,
        help="Don't show logs as part of start/stop operations",
    )

    netboxGroup = parser.add_argument_group('NetBox Backup and Restore')
    netboxGroup.add_argument(
        '--netbox-backup',
        dest='netboxBackupFile',
        required=False,
        metavar='<string>',
        type=str,
        default=None,
        help='Filename to which to back up NetBox configuration database',
    )
    netboxGroup.add_argument(
        '--netbox-restore',
        dest='netboxRestoreFile',
        required=False,
        metavar='<string>',
        type=str,
        default=None,
        help='Filename from which to restore NetBox configuration database',
    )

    try:
        args = parser.parse_args()
    except SystemExit as e:
        if e.code == 2:
            parser.print_help()
        sys.exit(e.code)

    args.verbose = set_logging(
        os.getenv("LOGLEVEL", ""),
        args.verbose,
        set_traceback_limit=True,
        logfmt='%(message)s',
    )
    logging.debug(os.path.join(ScriptPath, ScriptName))
    logging.debug(f"Arguments: {sys.argv[1:]}")
    logging.debug(f"Arguments: {args}")
    logging.info(f"Malcolm path: {GetMalcolmPath()}")

    # handle sigint and sigterm for graceful shutdown
    signal.signal(signal.SIGINT, shutdown_handler)
    signal.signal(signal.SIGTERM, shutdown_handler)

    yamlImported = YAMLDynamic(debug=log_level_is_debug(args.verbose))
    logging.info(f"Imported yaml: {yamlImported}")
    if not yamlImported:
        exit(2)

    dotenvImported = DotEnvDynamic(debug=log_level_is_debug(args.verbose))
    logging.info(f"Imported dotenv: {dotenvImported}")
    if not dotenvImported:
        exit(2)

    if not ((orchMode := DetermineYamlFileFormat(args.composeFile)) and (orchMode in OrchestrationFrameworksSupported)):
        raise Exception(f'{args.composeFile} must be a docker-compose or kubeconfig YAML file')

    with pushd(GetMalcolmPath()):
        # don't run this as root
        if (pyPlatform != PLATFORM_WINDOWS) and (
            (os.getuid() == 0) or (os.geteuid() == 0) or (getpass.getuser() == 'root')
        ):
            raise Exception(f'{ScriptName} should not be run as root')

        # if .env directory is unspecified, use the default ./config directory
        for firstLoop in (True, False):
            if (args.configDir is None) or (not os.path.isdir(args.configDir)):
                if firstLoop:
                    if args.configDir is None:
                        args.configDir = os.path.join(GetMalcolmPath(), 'config')
                    try:
                        os.makedirs(args.configDir)
                    except OSError as exc:
                        if (exc.errno == errno.EEXIST) and os.path.isdir(args.configDir):
                            pass
                        else:
                            raise
                else:
                    raise Exception("Could not determine configuration directory containing Malcolm's .env files")

        # create local temporary directory for docker-compose because we may have noexec on /tmp
        try:
            os.makedirs(MalcolmTmpPath)
        except OSError as exc:
            if (exc.errno == errno.EEXIST) and os.path.isdir(MalcolmTmpPath):
                pass
            else:
                raise

        # docker-compose use local temporary path
        osEnv = os.environ.copy()
        if not args.noTmpDirOverride:
            osEnv['TMPDIR'] = MalcolmTmpPath

        if orchMode is OrchestrationFramework.DOCKER_COMPOSE:
            # identify runtime engine
            runtimeBinSrc = ''
            if args.runtimeBin:
                dockerBin = args.runtimeBin
                runtimeBinSrc = 'specified'
            else:
                processEnvFile = os.path.join(args.configDir, 'process.env')
                try:
                    if os.path.isfile(processEnvFile):
                        dockerBin = dotenvImported.get_key(processEnvFile, CONTAINER_RUNTIME_KEY)
                        runtimeBinSrc = os.path.basename(processEnvFile)
                    else:
                        runtimeBinSrc = 'process.env not found'
                except Exception as e:
                    runtimeBinSrc = f'exception ({e})'
            if not dockerBin:
                dockerBin = 'docker.exe' if ((pyPlatform == PLATFORM_WINDOWS) and which('docker.exe')) else 'docker'
                runtimeBinSrc = 'default'
            logging.info(f"Container runtime ({runtimeBinSrc}): {dockerBin}")

            # make sure docker and docker compose are available
            err, out = run_process([dockerBin, 'info'], debug=log_level_is_debug(args.verbose))
            if err != 0:
                raise Exception(f'{ScriptName} requires docker, please run install.py')
            # first check if compose is available as a docker plugin
            dockerComposeBin = (dockerBin, 'compose')
            err, out = run_process(
                [dockerComposeBin, '--profile', PROFILE_MALCOLM, '-f', args.composeFile, 'version'],
                env=osEnv,
                debug=log_level_is_debug(args.verbose),
            )
            if err != 0:
                if (pyPlatform == PLATFORM_WINDOWS) and which('docker-compose.exe'):
                    dockerComposeBin = 'docker-compose.exe'
                elif which('docker-compose'):
                    dockerComposeBin = 'docker-compose'
                elif os.path.isfile('/usr/libexec/docker/cli-plugins/docker-compose'):
                    dockerComposeBin = '/usr/libexec/docker/cli-plugins/docker-compose'
                elif os.path.isfile('/usr/local/opt/docker-compose/bin/docker-compose'):
                    dockerComposeBin = '/usr/local/opt/docker-compose/bin/docker-compose'
                elif os.path.isfile('/usr/local/bin/docker-compose'):
                    dockerComposeBin = '/usr/local/bin/docker-compose'
                elif os.path.isfile('/usr/bin/docker-compose'):
                    dockerComposeBin = '/usr/bin/docker-compose'
                else:
                    dockerComposeBin = 'docker-compose'
                err, out = run_process(
                    [dockerComposeBin, '--profile', PROFILE_MALCOLM, '-f', args.composeFile, 'version'],
                    env=osEnv,
                    debug=log_level_is_debug(args.verbose),
                )
            if err != 0:
                raise Exception(f'{ScriptName} requires docker-compose, please run install.py')

            # load compose file YAML (used to find some volume bind mount locations)
            with open(args.composeFile, 'r') as cf:
                dockerComposeYaml = yamlImported.YAML(typ='safe', pure=True).load(cf)

        elif orchMode is OrchestrationFramework.KUBERNETES:
            kubeImported = KubernetesDynamic(debug=log_level_is_debug(args.verbose))
            logging.info(f"Imported kubernetes: {kubeImported}")
            if kubeImported:
                kubeImported.config.load_kube_config(args.composeFile)
            else:
                raise Exception(
                    f'{ScriptName} requires the official Python client library for kubernetes for {orchMode} mode'
                )

        # identify running profile
        runProfileSrc = ''
        if not args.composeProfile:
            profileEnvFile = os.path.join(args.configDir, 'process.env')
            try:
                if os.path.isfile(profileEnvFile):
                    args.composeProfile = dotenvImported.get_key(profileEnvFile, PROFILE_KEY)
                    runProfileSrc = os.path.basename(profileEnvFile)
                else:
                    logging.warning('process.env not found')
            except Exception as e:
                runProfileSrc = f'exception ({e})'
        else:
            runProfileSrc = 'specified'
        if (not args.composeProfile) or (
            (args.composeProfile not in (PROFILE_MALCOLM, PROFILE_HEDGEHOG)) and str2bool(args.composeProfile)
        ):
            args.composeProfile = PROFILE_MALCOLM
            runProfileSrc = runProfileSrc or 'default'
        logging.info(f"Run profile ({runProfileSrc}): {args.composeProfile}")

        # identify openssl binary
        opensslBin = 'openssl.exe' if ((pyPlatform == PLATFORM_WINDOWS) and which('openssl.exe')) else 'openssl'

        # if executed via a symlink, figure out what was intended via the symlink name
        if os.path.islink(os.path.join(ScriptPath, ScriptName)):
            if ScriptName == "logs":
                args.cmdLogs = True
            elif ScriptName == "status":
                args.cmdStatus = True
            elif ScriptName == "start":
                args.cmdStart = True
            elif ScriptName == "restart":
                args.cmdRestart = True
            elif ScriptName == "stop":
                args.cmdStop = True
            elif ScriptName == "wipe":
                args.cmdWipe = True
            elif ScriptName.startswith("auth"):
                args.cmdAuthSetup = True
            elif ScriptName == "netbox-backup":
                args.netboxBackupFile = ""
            elif ScriptName == "netbox-restore" and (
                (not args.netboxRestoreFile) or (not os.path.isfile(args.netboxRestoreFile))
            ):
                raise Exception('NetBox configuration database file must be specified with --netbox-restore')

        # the compose file references various .env files in just about every operation this script does,
        # so make sure they exist right off the bat
        checkEnvFilesAndValues()
        checkWiseFile()

        # stop Malcolm (and wipe data if requestsed)
        if args.cmdRestart or args.cmdStop or args.cmdWipe:
            stop(wipe=args.cmdWipe)

        # configure Malcolm authentication
        if args.cmdAuthSetup or args.cmdAuthSetupNonInteractive:
            authSetup()

        # start Malcolm
        if args.cmdStart or args.cmdRestart:
            start()

        # tail Malcolm logs
        if ((not args.quiet) and (args.cmdStart or args.cmdRestart)) or args.cmdLogs:
            logs()

        # display Malcolm status
        if args.cmdStatus:
            status()

        # display Malcolm URLS
        if args.cmdPrintURLs:
            printURLs()

        # backup NetBox files
        if args.netboxBackupFile is not None:
            print(f"NetBox configuration database saved to {netboxBackup(args.netboxBackupFile)}")

        # restore NetBox files
        if args.netboxRestoreFile is not None:
            netboxRestore(args.netboxRestoreFile)


if __name__ == '__main__':
    main()
    if coloramaImported:
        print(Style.RESET_ALL)
