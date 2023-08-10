#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2023 Battelle Energy Alliance, LLC.  All rights reserved.

import sys

sys.dont_write_bytecode = True

import argparse
import errno
import fileinput
import getpass
import glob
import gzip
import json
import os
import platform
import re
import secrets
import shutil
import signal
import stat
import string
import tarfile
import time

from malcolm_common import (
    AskForPassword,
    AskForString,
    BoundPath,
    ChooseOne,
    DetermineYamlFileFormat,
    DisplayMessage,
    DisplayProgramBox,
    DotEnvDynamic,
    GetUidGidFromEnv,
    KubernetesDynamic,
    LocalPathForContainerBindMount,
    MainDialog,
    MalcolmAuthFilesExist,
    MalcolmPath,
    MalcolmTmpPath,
    OrchestrationFramework,
    OrchestrationFrameworksSupported,
    PLATFORM_WINDOWS,
    posInt,
    ProcessLogLine,
    ScriptPath,
    YAMLDynamic,
    YesOrNo,
)

from malcolm_utils import (
    deep_get,
    dictsearch,
    eprint,
    EscapeAnsi,
    EscapeForCurl,
    get_iterable,
    get_primary_ip,
    LoadStrIfJson,
    ParseCurlFile,
    pushd,
    RemoveEmptyFolders,
    run_process,
    same_file_or_dir,
    str2bool,
    which,
)

from malcolm_kubernetes import (
    CheckPersistentStorageDefs,
    DeleteNamespace,
    get_node_hostnames_and_ips,
    GetPodNamesForService,
    PodExec,
    PrintNodeStatus,
    PrintPodStatus,
    REQUIRED_VOLUME_OBJECTS,
    StartMalcolm,
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
dockerComposeBin = None
dockerComposeYaml = None
kubeImported = None
opensslBin = None
orchMode = None
shuttingDown = [False]
yamlImported = None
dotenvImported = None


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
def checkEnvFilesExist():
    global args

    # first, if the configDir is completely empty, then populate from defaults
    defaultConfigDir = os.path.join(MalcolmPath, 'config')
    if (
        (args.configDir is not None)
        and os.path.isdir(args.configDir)
        and os.path.isdir(defaultConfigDir)
        and (not same_file_or_dir(defaultConfigDir, args.configDir))
        and (not os.listdir(args.configDir))
    ):
        for defaultEnvExampleFile in glob.glob(os.path.join(defaultConfigDir, '*.env.example')):
            shutil.copy2(defaultEnvExampleFile, args.configDir)

    # if a specific config/*.env file doesn't exist, use the *.example.env files as defaults
    envExampleFiles = glob.glob(os.path.join(args.configDir, '*.env.example'))
    for envExampleFile in envExampleFiles:
        envFile = envExampleFile[: -len('.example')]
        if not os.path.isfile(envFile):
            shutil.copyfile(envExampleFile, envFile)


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

        # docker-compose use local temporary path
        osEnv = os.environ.copy()
        osEnv['TMPDIR'] = MalcolmTmpPath

        # open up the docker-compose file and "grep" for the line where the keystore file
        # is bind-mounted into the service container (once and only once). the bind
        # mount needs to exist in the YML file and the local directory containing the
        # keystore file needs to exist (although the file itself might not yet).
        # also get PUID and PGID variables from the docker-compose file.
        localKeystore = None
        localKeystoreDir = None
        localKeystorePreExists = False
        volumeKeystore = f"/usr/share/{service}/config/{service}.keystore"
        volumeKeystoreDir = os.path.dirname(volumeKeystore)

        try:
            composeFileLines = list()
            with open(args.composeFile, 'r') as f:
                allLines = f.readlines()
                composeFileLines = [
                    x for x in allLines if re.search(fr'-.*?{service}.keystore\s*:.*{service}.keystore', x)
                ]

            if (len(composeFileLines) == 1) and (len(composeFileLines[0]) > 0):
                matches = re.search(
                    fr'-\s*(?P<localKeystore>.*?{service}.keystore)\s*:\s*.*?{service}.keystore',
                    composeFileLines[0],
                )
                if matches:
                    localKeystore = os.path.realpath(matches.group('localKeystore'))
                    localKeystoreDir = os.path.dirname(localKeystore)

            if (localKeystore is not None) and os.path.isdir(localKeystoreDir):
                localKeystorePreExists = os.path.isfile(localKeystore)

                dockerCmd = None

                # determine if Malcolm is running; if so, we'll use docker-compose exec, other wise we'll use docker run
                err, out = run_process(
                    [dockerComposeBin, '-f', args.composeFile, 'ps', '-q', service], env=osEnv, debug=args.debug
                )
                out[:] = [x for x in out if x]
                if (err == 0) and (len(out) > 0):
                    # Malcolm is running, we can use an existing container

                    # assemble the service-keystore command
                    dockerCmd = [
                        dockerComposeBin,
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
                    err, results = run_process(dockerCmd, env=osEnv, debug=args.debug, **run_process_kwargs)
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

            # don't be so whiny if the "create" failed just because it already existed or a 'remove' failed on a nonexistant item
            if (
                (not args.debug)
                and list(keystore_args)
                and (len(list(keystore_args)) > 0)
                and (list(keystore_args)[0].lower() in ('create', 'remove'))
                and localKeystorePreExists
            ):
                pass
            else:
                eprint(e)

    elif orchMode is OrchestrationFramework.KUBERNETES:
        cmd = [keystoreBinProc]
        if keystore_args:
            cmd.extend(list(keystore_args))
        cmd = [x for x in cmd if x]

        podsResults = PodExec(
            service,
            args.namespace,
            [x for x in cmd if x],
            stdin=run_process_kwargs['stdin']
            if ('stdin' in run_process_kwargs and run_process_kwargs['stdin'])
            else None,
        )

        err = 0 if all([deep_get(v, ['err'], 1) == 0 for k, v in podsResults.items()]) else 1
        results = list(chain(*[deep_get(v, ['output'], '') for k, v in podsResults.items()]))

        if args.debug:
            dbgStr = f"{len(podsResults)} pods: {cmd}({run_process_kwargs['stdin'][:80] + bool(run_process_kwargs['stdin'][80:]) * '...' if 'stdin' in run_process_kwargs and run_process_kwargs['stdin'] else ''}) returned {err}: {results}"
            eprint(dbgStr)
            for podname, podResults in podsResults.items():
                dbgStr = f"{podname}: {cmd}({run_process_kwargs['stdin'][:80] + bool(run_process_kwargs['stdin'][80:]) * '...' if 'stdin' in run_process_kwargs and run_process_kwargs['stdin'] else ''}) returned {deep_get(podResults, ['err'], 1)}: {deep_get(podResults, ['output'], 'unknown')}"
                eprint(dbgStr)

    else:
        raise Exception(f'{sys._getframe().f_code.co_name} does not yet support {orchMode}')

    return (err == 0), results


###################################################################################################
def status():
    global args
    global dockerComposeBin
    global orchMode

    if orchMode is OrchestrationFramework.DOCKER_COMPOSE:
        # docker-compose use local temporary path
        osEnv = os.environ.copy()
        osEnv['TMPDIR'] = MalcolmTmpPath

        err, out = run_process(
            [dockerComposeBin, '-f', args.composeFile, 'ps', args.service][: 5 if args.service is not None else -1],
            env=osEnv,
            debug=args.debug,
        )
        if err == 0:
            print("\n".join(out))
        else:
            eprint("Failed to display Malcolm status\n")
            eprint("\n".join(out))

    elif orchMode is OrchestrationFramework.KUBERNETES:
        try:
            PrintNodeStatus()
            print()
        except Exception as e:
            if args.debug:
                eprint(f'Error getting node status: {e}')
        try:
            PrintPodStatus(namespace=args.namespace)
            print()
        except Exception as e:
            eprint(f'Error getting {args.namespace} status: {e}')

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

    print("\nMalcolm services can be accessed via the following URLs:")
    print("------------------------------------------------------------------------------")
    print(f"  - Arkime: https://{myIp}/")
    print(f"  - OpenSearch Dashboards: https://{myIp}/dashboards/")
    print(f"  - PCAP upload (web): https://{myIp}/upload/")
    if orchMode is not OrchestrationFramework.KUBERNETES:
        print(f"  - PCAP upload (sftp): sftp://username@{myIp}:8022/files/")
    print(f"  - NetBox: https://{myIp}/netbox/")
    print(f"  - Account management: https://{myIp}/auth/")
    print(f"  - Documentation: https://{myIp}/readme/")


###################################################################################################
def netboxBackup(backupFileName=None):
    global args
    global dockerComposeBin
    global orchMode

    backupFileName, backupMediaFileName = None, None

    uidGidDict = GetUidGidFromEnv(args.configDir)

    if orchMode is OrchestrationFramework.DOCKER_COMPOSE:
        # docker-compose use local temporary path
        osEnv = os.environ.copy()
        osEnv['TMPDIR'] = MalcolmTmpPath

        dockerCmd = [
            dockerComposeBin,
            '-f',
            args.composeFile,
            'exec',
            # disable pseudo-TTY allocation
            '-T',
            # execute as UID:GID in docker-compose.yml file
            '-u',
            f'{uidGidDict["PUID"]}:{uidGidDict["PGID"]}',
            'netbox-postgres',
            'pg_dump',
            '-U',
            'netbox',
            '-d',
            'netbox',
        ]

        err, results = run_process(dockerCmd, env=osEnv, debug=args.debug, stdout=True, stderr=False)
        if (err != 0) or (len(results) == 0):
            raise Exception('Error creating NetBox configuration database backup')

        if (backupFileName is None) or (len(backupFileName) == 0):
            backupFileName = f"malcolm_netbox_backup_{time.strftime('%Y%m%d-%H%M%S')}.gz"

        with gzip.GzipFile(backupFileName, "wb") as f:
            f.write(bytes('\n'.join(results), 'utf-8'))

        backupFileParts = os.path.splitext(backupFileName)
        backupMediaFileName = backupFileParts[0] + ".media.tar.gz"
        with tarfile.open(backupMediaFileName, 'w:gz') as t:
            t.add(os.path.join(os.path.join(MalcolmPath, 'netbox'), 'media'), arcname='.')

    elif orchMode is OrchestrationFramework.KUBERNETES:
        if podsResults := PodExec(
            service='netbox-postgres',
            namespace=args.namespace,
            command=[
                'pg_dump',
                '-U',
                'netbox',
                '-d',
                'netbox',
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
        raise Exception(f'{sys._getframe().f_code.co_name} does not yet support {orchMode}')

    return backupFileName, backupMediaFileName


###################################################################################################
def netboxRestore(backupFileName=None):
    global args
    global dockerComposeBin
    global orchMode

    if backupFileName and os.path.isfile(backupFileName):
        uidGidDict = GetUidGidFromEnv(args.configDir)

        if orchMode is OrchestrationFramework.DOCKER_COMPOSE:
            # docker-compose use local temporary path
            osEnv = os.environ.copy()
            osEnv['TMPDIR'] = MalcolmTmpPath

            dockerCmdBase = [
                dockerComposeBin,
                '-f',
                args.composeFile,
                'exec',
                # disable pseudo-TTY allocation
                '-T',
                # execute as UID:GID in docker-compose.yml file
                '-u',
                f'{uidGidDict["PUID"]}:{uidGidDict["PGID"]}',
            ]

            # if the netbox_init.py process is happening, interrupt it
            dockerCmd = dockerCmdBase + [
                'netbox',
                'bash',
                '-c',
                'pgrep -f /usr/local/bin/netbox_init.py | xargs -r kill',
            ]
            err, results = run_process(dockerCmd, env=osEnv, debug=args.debug)
            if (err != 0) and args.debug:
                eprint(f'Error interrupting netbox_init.py: {results}')

            # drop the existing netbox database
            dockerCmd = dockerCmdBase + ['netbox-postgres', 'dropdb', '-U', 'netbox', 'netbox', '--force']
            err, results = run_process(dockerCmd, env=osEnv, debug=args.debug)
            if ((err != 0) or (len(results) == 0)) and args.debug:
                eprint(f'Error dropping NetBox database: {results}')

            # create a new netbox database
            dockerCmd = dockerCmdBase + ['netbox-postgres', 'createdb', '-U', 'netbox', 'netbox']
            err, results = run_process(dockerCmd, env=osEnv, debug=args.debug)
            if err != 0:
                raise Exception('Error creating new NetBox database')

            # load the backed-up psql dump
            dockerCmd = dockerCmdBase + ['netbox-postgres', 'psql', '-U', 'netbox']
            with gzip.open(backupFileName, 'rt') as f:
                err, results = run_process(dockerCmd, env=osEnv, debug=args.debug, stdin=f.read())
            if (err != 0) or (len(results) == 0):
                raise Exception('Error loading NetBox database')

            # migrations if needed
            dockerCmd = dockerCmdBase + ['netbox', '/opt/netbox/netbox/manage.py', 'migrate']
            err, results = run_process(dockerCmd, env=osEnv, debug=args.debug)
            if (err != 0) or (len(results) == 0):
                raise Exception('Error performing NetBox migration')

            # restore media directory
            backupFileParts = os.path.splitext(backupFileName)
            backupMediaFileName = backupFileParts[0] + ".media.tar.gz"
            mediaPath = os.path.join(os.path.join(MalcolmPath, 'netbox'), 'media')
            if os.path.isfile(backupMediaFileName) and os.path.isdir(mediaPath):
                RemoveEmptyFolders(mediaPath, removeRoot=False)
                with tarfile.open(backupMediaFileName) as t:
                    t.extractall(mediaPath)

        elif orchMode is OrchestrationFramework.KUBERNETES:
            # if the netbox_init.py process is happening, interrupt it
            if podsResults := PodExec(
                service='netbox',
                namespace=args.namespace,
                command=['bash', '-c', 'pgrep -f /usr/local/bin/netbox_init.py | xargs -r kill'],
            ):
                err = 0 if all([deep_get(v, ['err'], 1) == 0 for k, v in podsResults.items()]) else 1
                results = list(chain(*[deep_get(v, ['output'], '') for k, v in podsResults.items()]))
            else:
                err = 1
                results = []
            if (err != 0) and args.debug:
                eprint(f'Error ({err}) interrupting netbox_init.py: {results}')

            # drop the existing netbox database
            if podsResults := PodExec(
                service='netbox-postgres',
                namespace=args.namespace,
                command=['dropdb', '-U', 'netbox', 'netbox', '--force'],
            ):
                err = 0 if all([deep_get(v, ['err'], 1) == 0 for k, v in podsResults.items()]) else 1
                results = list(chain(*[deep_get(v, ['output'], '') for k, v in podsResults.items()]))
            else:
                err = 1
                results = []
            if ((err != 0) or (len(results) == 0)) and args.debug:
                eprint(f'Error dropping NetBox database: {results}')

            # create a new netbox database
            if podsResults := PodExec(
                service='netbox-postgres',
                namespace=args.namespace,
                command=['createdb', '-U', 'netbox', 'netbox'],
            ):
                err = 0 if all([deep_get(v, ['err'], 1) == 0 for k, v in podsResults.items()]) else 1
                results = list(chain(*[deep_get(v, ['output'], '') for k, v in podsResults.items()]))
            else:
                err = 1
                results = []
            if err != 0:
                raise Exception(f'Error creating new NetBox database: {results}')

            # load the backed-up psql dump
            with gzip.open(backupFileName, 'rt') as f:
                if podsResults := PodExec(
                    service='netbox-postgres',
                    namespace=args.namespace,
                    command=['psql', '-U', 'netbox'],
                    stdin=f.read(),
                ):
                    err = 0 if all([deep_get(v, ['err'], 1) == 0 for k, v in podsResults.items()]) else 1
                    results = list(chain(*[deep_get(v, ['output'], '') for k, v in podsResults.items()]))
                else:
                    err = 1
                    results = []
            if (err != 0) or (len(results) == 0):
                raise Exception(f'Error loading NetBox database: {results}')

            # migrations if needed
            if podsResults := PodExec(
                service='netbox',
                namespace=args.namespace,
                command=['/opt/netbox/netbox/manage.py', 'migrate'],
            ):
                err = 0 if all([deep_get(v, ['err'], 1) == 0 for k, v in podsResults.items()]) else 1
                results = list(chain(*[deep_get(v, ['output'], '') for k, v in podsResults.items()]))
            else:
                err = 1
                results = []
            if (err != 0) or (len(results) == 0):
                raise Exception(f'Error performing NetBox migration: {results}')

            # TODO: can't restore netbox/media directory via kubernetes at the moment

        else:
            raise Exception(f'{sys._getframe().f_code.co_name} does not yet support {orchMode}')


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
    osEnv['TMPDIR'] = MalcolmTmpPath

    if orchMode is OrchestrationFramework.DOCKER_COMPOSE:
        # increase COMPOSE_HTTP_TIMEOUT to be ridiculously large so docker-compose never times out the TTY doing debug output
        osEnv['COMPOSE_HTTP_TIMEOUT'] = '100000000'

        err, out = run_process(
            [dockerComposeBin, '-f', args.composeFile, 'ps', args.service][: 5 if args.service is not None else -1],
            env=osEnv,
            debug=args.debug,
        )
        print("\n".join(out))

        cmd = [
            dockerComposeBin,
            '-f',
            args.composeFile,
            'logs',
            '--tail',
            str(args.logLineCount) if args.logLineCount else 'all',
            '-f',
            args.service,
        ][: 8 if args.service else -1]

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
                '{{.Namespace}}/{{color .PodColor .PodName}}/{{color .ContainerColor .ContainerName}} | {{.Message}}{{"\\n"}}'
                if args.debug
                else '{{color .ContainerColor .ContainerName}} | {{.Message}}{{"\\n"}}',
                '--tail',
                str(args.logLineCount) if args.logLineCount else '-1',
            ]

            if args.namespace:
                cmd.extend(['--namespace', args.namespace])
            else:
                cmd.append('--all-namespaces')
            cmd.append(args.service if args.service else '.*')

        else:
            raise Exception(
                f'{sys._getframe().f_code.co_name} with orchestration mode {orchMode} requires "stern" (https://github.com/stern/stern/releases/latest)'
            )

    else:
        cmd = []
        raise Exception(f'{sys._getframe().f_code.co_name} does not yet support {orchMode}')

    if cmd:
        process = Popen(
            cmd,
            env=osEnv,
            stdout=PIPE,
            stderr=None if args.debug else DEVNULL,
        )
        while not shuttingDown[0]:
            output = process.stdout.readline()
            if not output:
                if process.poll() is not None:
                    break
                else:
                    time.sleep(0.5)

            elif output := ProcessLogLine(output, debug=args.debug):
                print(output)

            if (
                output
                and (args.cmdStart or args.cmdRestart)
                and (not args.cmdLogs)
                and finishedStartingRegEx.match(output)
            ):
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
        osEnv['TMPDIR'] = MalcolmTmpPath

        # if stop.sh is being called with wipe.sh (after the docker-compose file)
        # then also remove named and anonymous volumes (not external volumes, of course)
        err, out = run_process(
            [dockerComposeBin, '-f', args.composeFile, 'down', '--volumes'][: 5 if wipe else -1],
            env=osEnv,
            debug=args.debug,
        )
        if err == 0:
            eprint("Stopped Malcolm\n")
        else:
            eprint("Malcolm failed to stop\n")
            eprint("\n".join(out))
            exit(err)

        if wipe:
            # there is some overlap here among some of these containers, but it doesn't matter
            boundPathsToWipe = (
                BoundPath("arkime", "/opt/arkime/logs", True, None, None),
                BoundPath("arkime", "/opt/arkime/raw", True, None, None),
                BoundPath("filebeat", "/zeek", True, None, None),
                BoundPath("file-monitor", "/zeek/logs", True, None, None),
                BoundPath("netbox", "/opt/netbox/netbox/media", True, None, ["."]),
                BoundPath("netbox-postgres", "/var/lib/postgresql/data", True, None, ["."]),
                BoundPath("netbox-redis", "/data", True, None, ["."]),
                BoundPath("opensearch", "/usr/share/opensearch/data", True, ["nodes"], None),
                BoundPath("pcap-monitor", "/pcap", True, ["processed", "upload"], None),
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
                    boundPath.container_dir,
                    MalcolmPath,
                )
                if localPath and os.path.isdir(localPath):
                    # delete files
                    if boundPath.files:
                        if args.debug:
                            eprint(f'Walking "{localPath}" for file deletion')
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
                                if args.debug:
                                    eprint(f'Performing rmtree on "{tmpPath}"')
                                shutil.rmtree(tmpPath, ignore_errors=True)
                    # cleanup empty directories
                    if boundPath.clean_empty_dirs:
                        for cleanDir in get_iterable(boundPath.clean_empty_dirs):
                            tmpPath = os.path.join(localPath, cleanDir)
                            if os.path.isdir(tmpPath):
                                if args.debug:
                                    eprint(f'Performing RemoveEmptyFolders on "{tmpPath}"')
                                RemoveEmptyFolders(tmpPath, removeRoot=False)

            eprint("Malcolm has been stopped and its data cleared\n")

    elif orchMode is OrchestrationFramework.KUBERNETES:
        deleteResults = DeleteNamespace(
            namespace=args.namespace,
            deleteRetPerVol=args.deleteRetPerVol,
        )

        if dictsearch(deleteResults, 'error'):
            eprint(
                f"Deleting {args.namespace} namespace and its underlying resources returned the following error(s):\n"
            )
            eprint(deleteResults)
            eprint()

        else:
            eprint(f"The {args.namespace} namespace and its underlying resources have been deleted\n")
            if args.debug:
                eprint(deleteResults)
                eprint()

        if wipe:
            eprint(f'Data on PersistentVolume storage cannot be deleted by {ScriptName}: it must be deleted manually\n')

    else:
        raise Exception(f'{sys._getframe().f_code.co_name} does not yet support {orchMode}')


###################################################################################################
def start():
    global args
    global dockerBin
    global dockerComposeBin
    global orchMode

    # touch the htadmin metadata file and .opensearch.*.curlrc files
    open(os.path.join(MalcolmPath, os.path.join('htadmin', 'metadata')), 'a').close()
    open(os.path.join(MalcolmPath, '.opensearch.primary.curlrc'), 'a').close()
    open(os.path.join(MalcolmPath, '.opensearch.secondary.curlrc'), 'a').close()

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
    if not os.path.isfile(os.path.join(MalcolmPath, os.path.join('opensearch', 'opensearch.keystore'))):
        keystore_op('opensearch', True, 'create')

    # make sure permissions are set correctly for the worker processes
    for authFile in [
        os.path.join(MalcolmPath, os.path.join('nginx', 'htpasswd')),
        os.path.join(MalcolmPath, os.path.join('htadmin', 'config.ini')),
        os.path.join(MalcolmPath, os.path.join('htadmin', 'metadata')),
    ]:
        # chmod 644 authFile
        os.chmod(authFile, stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH)
    for authFile in [
        os.path.join(MalcolmPath, os.path.join('nginx', 'nginx_ldap.conf')),
        os.path.join(MalcolmPath, '.opensearch.primary.curlrc'),
        os.path.join(MalcolmPath, '.opensearch.secondary.curlrc'),
    ]:
        # chmod 600 authFile
        os.chmod(authFile, stat.S_IRUSR | stat.S_IWUSR)
    with pushd(args.configDir):
        for envFile in glob.glob("*.env"):
            # chmod 600 envFile
            os.chmod(envFile, stat.S_IRUSR | stat.S_IWUSR)

    # touch the zeek intel file
    open(os.path.join(MalcolmPath, os.path.join('zeek', os.path.join('intel', '__load__.zeek'))), 'a').close()

    # clean up any leftover intel update locks
    shutil.rmtree(os.path.join(MalcolmPath, os.path.join('zeek', os.path.join('intel', 'lock'))), ignore_errors=True)

    if orchMode is OrchestrationFramework.DOCKER_COMPOSE:
        # make sure some directories exist before we start
        boundPathsToCreate = (
            BoundPath("arkime", "/opt/arkime/logs", False, None, None),
            BoundPath("arkime", "/opt/arkime/raw", False, None, None),
            BoundPath("file-monitor", "/zeek/logs", False, None, None),
            BoundPath("nginx-proxy", "/var/local/ca-trust", False, None, None),
            BoundPath("netbox", "/opt/netbox/netbox/media", False, None, None),
            BoundPath("netbox-postgres", "/var/lib/postgresql/data", False, None, None),
            BoundPath("netbox-redis", "/data", False, None, None),
            BoundPath("opensearch", "/usr/share/opensearch/data", False, ["nodes"], None),
            BoundPath("opensearch", "/opt/opensearch/backup", False, None, None),
            BoundPath("pcap-monitor", "/pcap", False, ["processed", "upload"], None),
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
            BoundPath("zeek", "/opt/zeek/share/zeek/site/intel", False, ["MISP", "STIX"], None),
            BoundPath("zeek-live", "/zeek/live", False, ["spool"], None),
            BoundPath("filebeat", "/zeek", False, ["processed", "current", "live", "extract_files", "upload"], None),
        )
        for boundPath in boundPathsToCreate:
            localPath = LocalPathForContainerBindMount(
                boundPath.service,
                dockerComposeYaml,
                boundPath.container_dir,
                MalcolmPath,
            )
            if localPath:
                try:
                    if args.debug:
                        eprint(f'Ensuring "{localPath}" exists')
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
                            if args.debug:
                                eprint(f'Ensuring "{tmpPath}" exists')
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
        osEnv['TMPDIR'] = MalcolmTmpPath

        # start docker
        err, out = run_process(
            [dockerComposeBin, '-f', args.composeFile, 'up', '--detach'], env=osEnv, debug=args.debug
        )
        if err != 0:
            eprint("Malcolm failed to start\n")
            eprint("\n".join(out))
            exit(err)

    elif orchMode is OrchestrationFramework.KUBERNETES:
        if CheckPersistentStorageDefs(
            namespace=args.namespace,
            malcolmPath=MalcolmPath,
        ):
            startResults = StartMalcolm(
                namespace=args.namespace,
                malcolmPath=MalcolmPath,
                configPath=args.configDir,
            )

            if dictsearch(startResults, 'error'):
                eprint(
                    f"Starting the {args.namespace} namespace and creating its underlying resources returned the following error(s):\n"
                )
                eprint(startResults)
                eprint()

            elif args.debug:
                eprint()
                eprint(startResults)
                eprint()

        else:
            groupedStorageEntries = {
                i: [j[0] for j in j]
                for i, j in groupby(sorted(REQUIRED_VOLUME_OBJECTS.items(), key=lambda x: x[1]), lambda x: x[1])
            }
            raise Exception(
                f'Storage objects required by Malcolm are not defined in {os.path.join(MalcolmPath, "kubernetes")}: {groupedStorageEntries}'
            )

    else:
        raise Exception(f'{sys._getframe().f_code.co_name} does not yet support {orchMode}')


###################################################################################################
def authSetup(wipe=False):
    global args
    global opensslBin

    # for beats/logstash self-signed certificates
    logstashPath = os.path.join(MalcolmPath, os.path.join('logstash', 'certs'))
    filebeatPath = os.path.join(MalcolmPath, os.path.join('filebeat', 'certs'))

    txRxScript = None
    if (pyPlatform != PLATFORM_WINDOWS) and which("croc"):
        txRxScript = 'tx-rx-secure.sh' if which('tx-rx-secure.sh') else None
        if not txRxScript:
            txRxScript = os.path.join(
                MalcolmPath, os.path.join('shared', os.path.join('bin', os.path.join('tx-rx-secure.sh')))
            )
            txRxScript = txRxScript if (txRxScript and os.path.isfile(txRxScript)) else '/usr/local/bin/tx-rx-secure.sh'
            txRxScript = txRxScript if (txRxScript and os.path.isfile(txRxScript)) else '/usr/bin/tx-rx-secure.sh'
            txRxScript = txRxScript if (txRxScript and os.path.isfile(txRxScript)) else None

    # don't make them go through every thing every time, give them a choice instead
    authModeChoices = (
        (
            'all',
            "Configure all authentication-related settings",
            True,
            True,
        ),
        (
            'admin',
            "Store administrator username/password for local Malcolm access",
            False,
            True,
        ),
        (
            'webcerts',
            "(Re)generate self-signed certificates for HTTPS access",
            False,
            True,
        ),
        (
            'fwcerts',
            "(Re)generate self-signed certificates for a remote log forwarder",
            False,
            True,
        ),
        (
            'remoteos',
            "Configure remote primary or secondary OpenSearch instance",
            False,
            False,
        ),
        (
            'email',
            "Store username/password for email alert sender account",
            False,
            False,
        ),
        (
            'netbox',
            "(Re)generate internal passwords for NetBox",
            False,
            not os.path.isfile(
                os.path.join(MalcolmPath, os.path.join('netbox', os.path.join('env', 'netbox-secret.env')))
            ),
        ),
        (
            'txfwcerts',
            "Transfer self-signed client certificates to a remote log forwarder",
            False,
            False,
        ),
    )[: 8 if txRxScript else -1]

    authMode = ChooseOne(
        'Configure Authentication',
        choices=[x[:-1] for x in authModeChoices],
    )

    for authItem in authModeChoices[1:]:
        if ((authMode == 'all') and YesOrNo(f'{authItem[1]}?', default=authItem[3])) or (
            (authMode != 'all') and (authMode == authItem[0])
        ):
            if authItem[0] == 'admin':
                # prompt username and password
                usernamePrevious = None
                password = None
                passwordConfirm = None
                passwordEncrypted = ''

                while True:
                    username = AskForString("Administrator username")
                    if len(username) > 0:
                        break

                while True:
                    password = AskForPassword(f"{username} password: ")
                    passwordConfirm = AskForPassword(f"{username} password (again): ")
                    if password == passwordConfirm:
                        break
                    eprint("Passwords do not match")

                # get previous admin username to remove from htpasswd file if it's changed
                authEnvFile = os.path.join(args.configDir, 'auth.env')
                if os.path.isfile(authEnvFile):
                    prevAuthInfo = defaultdict(str)
                    with open(authEnvFile, 'r') as f:
                        for line in f:
                            try:
                                k, v = line.rstrip().split("=")
                                prevAuthInfo[k] = v.strip('"')
                            except Exception:
                                pass
                    if len(prevAuthInfo['MALCOLM_USERNAME']) > 0:
                        usernamePrevious = prevAuthInfo['MALCOLM_USERNAME']

                # get openssl hash of password
                err, out = run_process(
                    [opensslBin, 'passwd', '-1', '-stdin'],
                    stdin=password,
                    stderr=False,
                    debug=args.debug,
                )
                if (err == 0) and (len(out) > 0) and (len(out[0]) > 0):
                    passwordEncrypted = out[0]
                else:
                    raise Exception('Unable to generate password hash with openssl')

                # write auth.env (used by htadmin and file-upload containers)
                with open(authEnvFile, 'w') as f:
                    f.write(
                        "# Malcolm Administrator username and encrypted password for nginx reverse proxy (and upload server's SFTP access)\n"
                    )
                    f.write(f'MALCOLM_USERNAME={username}\n')
                    f.write(f'MALCOLM_PASSWORD={b64encode(passwordEncrypted.encode()).decode("ascii")}\n')
                    f.write('K8S_SECRET=True\n')
                os.chmod(authEnvFile, stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH)

                # create or update the htpasswd file
                htpasswdFile = os.path.join(MalcolmPath, os.path.join('nginx', 'htpasswd'))
                htpasswdCmd = ['htpasswd', '-i', '-B', htpasswdFile, username]
                if not os.path.isfile(htpasswdFile):
                    htpasswdCmd.insert(1, '-c')
                err, out = run_process(htpasswdCmd, stdin=password, stderr=True, debug=args.debug)
                if err != 0:
                    raise Exception(f'Unable to generate htpasswd file: {out}')

                # if the admininstrator username has changed, remove the previous administrator username from htpasswd
                if (usernamePrevious is not None) and (usernamePrevious != username):
                    htpasswdLines = list()
                    with open(htpasswdFile, 'r') as f:
                        htpasswdLines = f.readlines()
                    with open(htpasswdFile, 'w') as f:
                        for line in htpasswdLines:
                            if not line.startswith(f"{usernamePrevious}:"):
                                f.write(line)

                # configure default LDAP stuff (they'll have to edit it by hand later)
                ldapConfFile = os.path.join(MalcolmPath, os.path.join('nginx', 'nginx_ldap.conf'))
                if not os.path.isfile(ldapConfFile):
                    ldapDefaults = defaultdict(str)
                    if os.path.isfile(os.path.join(MalcolmPath, '.ldap_config_defaults')):
                        ldapDefaults = defaultdict(str)
                        with open(os.path.join(MalcolmPath, '.ldap_config_defaults'), 'r') as f:
                            for line in f:
                                try:
                                    k, v = line.rstrip().split("=")
                                    ldapDefaults[k] = v.strip('"').strip("'")
                                except Exception:
                                    pass
                    ldapProto = ldapDefaults.get("LDAP_PROTO", "ldap://")
                    ldapHost = ldapDefaults.get("LDAP_HOST", "ds.example.com")
                    ldapPort = ldapDefaults.get("LDAP_PORT", "3268")
                    ldapType = ldapDefaults.get("LDAP_SERVER_TYPE", "winldap")
                    if ldapType == "openldap":
                        ldapUri = 'DC=example,DC=com?uid?sub?(objectClass=posixAccount)'
                        ldapGroupAttr = "memberUid"
                        ldapGroupAttrIsDN = "off"
                    else:
                        ldapUri = 'DC=example,DC=com?sAMAccountName?sub?(objectClass=person)'
                        ldapGroupAttr = "member"
                        ldapGroupAttrIsDN = "on"
                    with open(ldapConfFile, 'w') as f:
                        f.write('# This is a sample configuration for the ldap_server section of nginx.conf.\n')
                        f.write('# Yours will vary depending on how your Active Directory/LDAP server is configured.\n')
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

                # populate htadmin config file
                with open(os.path.join(MalcolmPath, os.path.join('htadmin', 'config.ini')), 'w') as f:
                    f.write('; HTAdmin config file.\n\n')
                    f.write('[application]\n')
                    f.write('; Change this to customize your title:\n')
                    f.write('app_title = Malcolm User Management\n\n')
                    f.write('; htpasswd file\n')
                    f.write('secure_path  = ./auth/htpasswd\n')
                    f.write('; metadata file\n')
                    f.write('metadata_path  = ./config/metadata\n\n')
                    f.write('; administrator user/password (htpasswd -b -c -B ...)\n')
                    f.write(f'admin_user = {username}\n\n')
                    f.write('; username field quality checks\n')
                    f.write(';\n')
                    f.write('min_username_len = 4\n')
                    f.write('max_username_len = 32\n\n')
                    f.write('; Password field quality checks\n')
                    f.write(';\n')
                    f.write('min_password_len = 8\n')
                    f.write('max_password_len = 128\n\n')

                # touch the metadata file
                open(os.path.join(MalcolmPath, os.path.join('htadmin', 'metadata')), 'a').close()

                DisplayMessage(
                    'Additional local accounts can be created at https://localhost/auth/ when Malcolm is running',
                )

            # generate HTTPS self-signed certificates
            elif authItem[0] == 'webcerts':
                with pushd(os.path.join(MalcolmPath, os.path.join('nginx', 'certs'))):
                    # remove previous files
                    for oldfile in glob.glob("*.pem"):
                        os.remove(oldfile)

                    # generate dhparam -------------------------------
                    err, out = run_process(
                        [opensslBin, 'dhparam', '-out', 'dhparam.pem', '2048'],
                        stderr=True,
                        debug=args.debug,
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
                        debug=args.debug,
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
                        debug=args.debug,
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
                        debug=args.debug,
                    )
                    if err != 0:
                        raise Exception(f'Unable to generate ca.crt: {out}')

                    # server -------------------------------
                    err, out = run_process(
                        [opensslBin, 'genrsa', '-out', 'server.key', '2048'],
                        stderr=True,
                        debug=args.debug,
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
                        debug=args.debug,
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
                        debug=args.debug,
                    )
                    if err != 0:
                        raise Exception(f'Unable to generate server.crt: {out}')

                    shutil.move("server.key", "server.key.pem")
                    err, out = run_process(
                        [opensslBin, 'pkcs8', '-in', 'server.key.pem', '-topk8', '-nocrypt', '-out', 'server.key'],
                        stderr=True,
                        debug=args.debug,
                    )
                    if err != 0:
                        raise Exception(f'Unable to generate server.key: {out}')

                    # client -------------------------------
                    err, out = run_process(
                        [opensslBin, 'genrsa', '-out', 'client.key', '2048'],
                        stderr=True,
                        debug=args.debug,
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
                            'client.conf',
                        ],
                        stderr=True,
                        debug=args.debug,
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
                            'ca.crt',
                            '-CAkey',
                            'ca.key',
                            '-out',
                            'client.crt',
                            '-extensions',
                            'v3_req',
                            '-extensions',
                            'usr_cert',
                            '-extfile',
                            'client.conf',
                        ],
                        stderr=True,
                        debug=args.debug,
                    )
                    if err != 0:
                        raise Exception(f'Unable to generate client.crt: {out}')
                    # -----------------------------------------------

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

                    # copy the ca so logstasn and filebeat both have it
                    shutil.copy2(os.path.join(logstashPath, "ca.crt"), filebeatPath)

                    # move the client certs for filebeat
                    for f in ['client.key', 'client.crt']:
                        shutil.move(os.path.join(logstashPath, f), filebeatPath)

                    # remove leftovers
                    for pat in ['*.srl', '*.csr', '*.pem']:
                        for oldfile in glob.glob(pat):
                            os.remove(oldfile)

            # create and populate connection parameters file for remote OpenSearch instance(s)
            elif authItem[0] == 'remoteos':
                for instance in ['primary', 'secondary']:
                    openSearchCredFileName = os.path.join(MalcolmPath, f'.opensearch.{instance}.curlrc')
                    if YesOrNo(
                        f'Store username/password for {instance} remote OpenSearch instance?',
                        default=False,
                    ):
                        prevCurlContents = ParseCurlFile(openSearchCredFileName)

                        # prompt host, username and password
                        esUsername = None
                        esPassword = None
                        esPasswordConfirm = None

                        while True:
                            esUsername = AskForString(
                                "OpenSearch username",
                                default=prevCurlContents['user'],
                            )
                            if (len(esUsername) > 0) and (':' not in esUsername):
                                break
                            eprint("Username is blank (or contains a colon, which is not allowed)")

                        while True:
                            esPassword = AskForPassword(f"{esUsername} password: ")
                            if (
                                (len(esPassword) == 0)
                                and (prevCurlContents['password'] is not None)
                                and YesOrNo(f'Use previously entered password for "{esUsername}"?', default=True)
                            ):
                                esPassword = prevCurlContents['password']
                                esPasswordConfirm = esPassword
                            else:
                                esPasswordConfirm = AskForPassword(f"{esUsername} password (again): ")
                            if (esPassword == esPasswordConfirm) and (len(esPassword) > 0):
                                break
                            eprint("Passwords do not match")

                        esSslVerify = YesOrNo(
                            'Require SSL certificate validation for OpenSearch communication?',
                            default=(not (('k' in prevCurlContents) or ('insecure' in prevCurlContents))),
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
                    open(openSearchCredFileName, 'a').close()
                    os.chmod(openSearchCredFileName, stat.S_IRUSR | stat.S_IWUSR)

            # OpenSearch authenticate sender account credentials
            # https://opensearch.org/docs/latest/monitoring-plugins/alerting/monitors/#authenticate-sender-account
            elif authItem[0] == 'email':
                # prompt username and password
                emailPassword = None
                emailPasswordConfirm = None
                emailSender = AskForString("OpenSearch alerting email sender name")
                while True:
                    emailUsername = AskForString("Email account username")
                    if len(emailUsername) > 0:
                        break

                while True:
                    emailPassword = AskForPassword(f"{emailUsername} password: ")
                    emailPasswordConfirm = AskForPassword(f"{emailUsername} password (again): ")
                    if emailPassword == emailPasswordConfirm:
                        break
                    eprint("Passwords do not match")

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
                    eprint(f"Email alert sender account variables stored: {', '.join(results)}")
                else:
                    eprint("Failed to store email alert sender account variables:\n")
                    eprint("\n".join(results))

            elif authItem[0] == 'netbox':
                with pushd(args.configDir):
                    netboxPwAlphabet = string.ascii_letters + string.digits + '_'
                    netboxKeyAlphabet = string.ascii_letters + string.digits + '%@<=>?~^_-'
                    netboxPostGresPassword = ''.join(secrets.choice(netboxPwAlphabet) for i in range(24))
                    netboxRedisPassword = ''.join(secrets.choice(netboxPwAlphabet) for i in range(24))
                    netboxRedisCachePassword = ''.join(secrets.choice(netboxPwAlphabet) for i in range(24))
                    netboxSuPassword = ''.join(secrets.choice(netboxPwAlphabet) for i in range(24))
                    netboxSuToken = ''.join(secrets.choice(netboxPwAlphabet) for i in range(40))
                    netboxSecretKey = ''.join(secrets.choice(netboxKeyAlphabet) for i in range(50))

                    with open('netbox-postgres.env', 'w') as f:
                        f.write('POSTGRES_DB=netbox\n')
                        f.write(f'POSTGRES_PASSWORD={netboxPostGresPassword}\n')
                        f.write('POSTGRES_USER=netbox\n')
                        f.write('K8S_SECRET=True\n')
                    os.chmod('netbox-postgres.env', stat.S_IRUSR | stat.S_IWUSR)

                    with open('netbox-redis-cache.env', 'w') as f:
                        f.write(f'REDIS_PASSWORD={netboxRedisCachePassword}\n')
                        f.write('K8S_SECRET=True\n')
                    os.chmod('netbox-redis-cache.env', stat.S_IRUSR | stat.S_IWUSR)

                    with open('netbox-redis.env', 'w') as f:
                        f.write(f'REDIS_PASSWORD={netboxRedisPassword}\n')
                        f.write('K8S_SECRET=True\n')
                    os.chmod('netbox-redis.env', stat.S_IRUSR | stat.S_IWUSR)

                    if (not os.path.isfile('netbox-secret.env')) and (os.path.isfile('netbox-secret.env.example')):
                        shutil.copy2('netbox-secret.env.example', 'netbox-secret.env')

                    with fileinput.FileInput('netbox-secret.env', inplace=True, backup=None) as envFile:
                        for line in envFile:
                            line = line.rstrip("\n")

                            if line.startswith('DB_PASSWORD'):
                                line = re.sub(
                                    r'(DB_PASSWORD\s*=\s*)(\S+)',
                                    fr"\g<1>{netboxPostGresPassword}",
                                    line,
                                )
                            elif line.startswith('REDIS_CACHE_PASSWORD'):
                                line = re.sub(
                                    r'(REDIS_CACHE_PASSWORD\s*=\s*)(\S+)',
                                    fr"\g<1>{netboxRedisCachePassword}",
                                    line,
                                )
                            elif line.startswith('REDIS_PASSWORD'):
                                line = re.sub(
                                    r'(REDIS_PASSWORD\s*=\s*)(\S+)',
                                    fr"\g<1>{netboxRedisPassword}",
                                    line,
                                )
                            elif line.startswith('SECRET_KEY'):
                                line = re.sub(
                                    r'(SECRET_KEY\s*=\s*)(\S+)',
                                    fr"\g<1>{netboxSecretKey}",
                                    line,
                                )
                            elif line.startswith('SUPERUSER_PASSWORD'):
                                line = re.sub(
                                    r'(SUPERUSER_PASSWORD\s*=\s*)(\S+)',
                                    fr"\g<1>{netboxSuPassword}",
                                    line,
                                )
                            elif line.startswith('SUPERUSER_API_TOKEN'):
                                line = re.sub(
                                    r'(SUPERUSER_API_TOKEN\s*=\s*)(\S+)',
                                    fr"\g<1>{netboxSuToken}",
                                    line,
                                )
                            elif line.startswith('K8S_SECRET'):
                                line = re.sub(
                                    r'(SUPERUSER_API_TOKEN\s*=\s*)(\S+)',
                                    fr"\g<1>True",
                                    line,
                                )

                            print(line)

                    os.chmod('netbox-secret.env', stat.S_IRUSR | stat.S_IWUSR)

            elif authItem[0] == 'txfwcerts':
                DisplayMessage(
                    'Run configure-capture on the remote log forwarder, select "Configure Forwarding," then "Receive client SSL files..."',
                )
                with pushd(filebeatPath):
                    with Popen(
                        [txRxScript, '-t', "ca.crt", "client.crt", "client.key"],
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
        add_help=False,
        usage=f'{ScriptName} <arguments>',
    )
    parser.add_argument(
        '-v',
        '--verbose',
        dest='debug',
        type=str2bool,
        nargs='?',
        const=True,
        default=False,
        help="Verbose output",
    )
    parser.add_argument(
        '-f',
        '--file',
        required=False,
        dest='composeFile',
        metavar='<STR>',
        type=str,
        default='docker-compose.yml',
        help='docker-compose or kubeconfig YML file',
    )
    parser.add_argument(
        '-e',
        '--environment-dir',
        required=False,
        dest='configDir',
        metavar='<STR>',
        type=str,
        default=None,
        help="Directory containing Malcolm's .env files",
    )
    parser.add_argument(
        '-n',
        '--namespace',
        required=False,
        dest='namespace',
        metavar='<STR>',
        type=str,
        default='malcolm',
        help="Kubernetes namespace",
    )
    parser.add_argument(
        '-s',
        '--service',
        required=False,
        dest='service',
        metavar='<STR>',
        type=str,
        default=None,
        help='docker-compose service (only for status and logs operations)',
    )
    parser.add_argument(
        '-l',
        '--logs',
        dest='cmdLogs',
        type=str2bool,
        nargs='?',
        const=True,
        default=False,
        help="Tail Malcolm logs",
    )
    parser.add_argument(
        '--lines',
        dest='logLineCount',
        type=posInt,
        nargs='?',
        const=False,
        default=None,
        help='Number of log lines to output. Outputs all lines by default (only for logs operation)',
    )
    parser.add_argument(
        '--netbox-backup',
        dest='netboxBackupFile',
        required=False,
        metavar='<STR>',
        type=str,
        default=None,
        help='Filename to which to back up NetBox configuration database',
    )
    parser.add_argument(
        '--netbox-restore',
        dest='netboxRestoreFile',
        required=False,
        metavar='<STR>',
        type=str,
        default=None,
        help='Filename from which to restore NetBox configuration database',
    )
    parser.add_argument(
        '--start',
        dest='cmdStart',
        type=str2bool,
        nargs='?',
        const=True,
        default=False,
        help="Start Malcolm",
    )
    parser.add_argument(
        '--restart',
        dest='cmdRestart',
        type=str2bool,
        nargs='?',
        const=True,
        default=False,
        help="Stop and restart Malcolm",
    )
    parser.add_argument(
        '--stop',
        dest='cmdStop',
        type=str2bool,
        nargs='?',
        const=True,
        default=False,
        help="Stop Malcolm",
    )
    parser.add_argument(
        '--wipe',
        dest='cmdWipe',
        type=str2bool,
        nargs='?',
        const=True,
        default=False,
        help="Stop Malcolm and delete all data",
    )
    parser.add_argument(
        '--reclaim-persistent-volume',
        dest='deleteRetPerVol',
        action='store_true',
        help='Delete PersistentVolumes with Retain reclaim policy (default; only for "stop" operation with Kubernetes)',
    )
    parser.add_argument(
        '--no-reclaim-persistent-volume',
        dest='deleteRetPerVol',
        action='store_false',
        help='Do not delete PersistentVolumes with Retain reclaim policy (only for "stop" operation with Kubernetes)',
    )
    parser.set_defaults(deleteRetPerVol=True)
    parser.add_argument(
        '--auth',
        dest='cmdAuthSetup',
        type=str2bool,
        nargs='?',
        const=True,
        default=False,
        help="Configure Malcolm authentication",
    )
    parser.add_argument(
        '--status',
        dest='cmdStatus',
        type=str2bool,
        nargs='?',
        const=True,
        default=False,
        help="Display status of Malcolm components",
    )
    parser.add_argument(
        '--urls',
        dest='cmdPrintURLs',
        type=str2bool,
        nargs='?',
        const=True,
        default=False,
        help="Display Malcolm URLs",
    )

    try:
        parser.error = parser.exit
        args = parser.parse_args()
    except SystemExit:
        parser.print_help()
        exit(2)

    if args.debug:
        eprint(os.path.join(ScriptPath, ScriptName))
        eprint(f"Arguments: {sys.argv[1:]}")
        eprint(f"Arguments: {args}")
        eprint("Malcolm path:", MalcolmPath)
    else:
        sys.tracebacklimit = 0

    # handle sigint and sigterm for graceful shutdown
    signal.signal(signal.SIGINT, shutdown_handler)
    signal.signal(signal.SIGTERM, shutdown_handler)

    yamlImported = YAMLDynamic(debug=args.debug)
    if args.debug:
        eprint(f"Imported yaml: {yamlImported}")
    if not yamlImported:
        exit(2)

    dotenvImported = DotEnvDynamic(debug=args.debug)
    if args.debug:
        eprint(f"Imported dotenv: {dotenvImported}")
    if not dotenvImported:
        exit(2)

    if not ((orchMode := DetermineYamlFileFormat(args.composeFile)) and (orchMode in OrchestrationFrameworksSupported)):
        raise Exception(f'{args.composeFile} must be a docker-compose or kubeconfig YAML file')

    with pushd(MalcolmPath):
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
                        args.configDir = os.path.join(MalcolmPath, 'config')
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
        osEnv['TMPDIR'] = MalcolmTmpPath

        if orchMode is OrchestrationFramework.DOCKER_COMPOSE:
            # make sure docker/docker-compose is available
            dockerBin = 'docker.exe' if ((pyPlatform == PLATFORM_WINDOWS) and which('docker.exe')) else 'docker'
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
            err, out = run_process([dockerBin, 'info'], debug=args.debug)
            if err != 0:
                raise Exception(f'{ScriptName} requires docker, please run install.py')
            err, out = run_process([dockerComposeBin, '-f', args.composeFile, 'version'], env=osEnv, debug=args.debug)
            if err != 0:
                raise Exception(f'{ScriptName} requires docker-compose, please run install.py')

            # load compose file YAML (used to find some volume bind mount locations)
            with open(args.composeFile, 'r') as cf:
                dockerComposeYaml = yamlImported.safe_load(cf)

        elif orchMode is OrchestrationFramework.KUBERNETES:
            kubeImported = KubernetesDynamic(debug=args.debug)
            if args.debug:
                eprint(f"Imported kubernetes: {kubeImported}")
            if kubeImported:
                kubeImported.config.load_kube_config(args.composeFile)
            else:
                raise Exception(
                    f'{ScriptName} requires the official Python client library for kubernetes for {orchMode} mode'
                )

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
        checkEnvFilesExist()

        # stop Malcolm (and wipe data if requestsed)
        if args.cmdRestart or args.cmdStop or args.cmdWipe:
            stop(wipe=args.cmdWipe)

        # configure Malcolm authentication
        if args.cmdAuthSetup:
            authSetup()

        # start Malcolm
        if args.cmdStart or args.cmdRestart:
            start()

        # tail Malcolm logs
        if args.cmdStart or args.cmdRestart or args.cmdLogs:
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
