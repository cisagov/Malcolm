#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2023 Battelle Energy Alliance, LLC.  All rights reserved.

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
import stat
import string
import sys
import tarfile
import time

from malcolm_common import *
from base64 import b64encode
from collections import defaultdict, namedtuple
from subprocess import PIPE, DEVNULL, Popen, TimeoutExpired
from urllib.parse import urlparse

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
opensslBin = None
yamlImported = None
dockerComposeYaml = None

###################################################################################################
try:
    from colorama import init as ColoramaInit, Fore, Back, Style

    ColoramaInit()
    coloramaImported = True
except:
    coloramaImported = False


###################################################################################################
# perform a service-keystore operation in a Docker container
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

    err = -1
    results = []

    # the opensearch containers all follow the same naming pattern for these executables
    keystoreBinProc = f"/usr/share/{service}/bin/{service}-keystore"

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
    volumeKeystore = None
    volumeKeystoreDir = None
    uidGidDict = None

    try:
        uidGidDict = GetUidGidFromComposeFile(args.composeFile)

        composeFileLines = list()
        with open(args.composeFile, 'r') as f:
            allLines = f.readlines()
            composeFileLines = [x for x in allLines if re.search(fr'-.*?{service}.keystore\s*:.*{service}.keystore', x)]

        if (len(composeFileLines) == 1) and (len(composeFileLines[0]) > 0):
            matches = re.search(
                fr'-\s*(?P<localKeystore>.*?{service}.keystore)\s*:\s*(?P<volumeKeystore>.*?{service}.keystore)',
                composeFileLines[0],
            )
            if matches:
                localKeystore = os.path.realpath(matches.group('localKeystore'))
                localKeystoreDir = os.path.dirname(localKeystore)
                volumeKeystore = matches.group('volumeKeystore')
                volumeKeystoreDir = os.path.dirname(volumeKeystore)

        if (localKeystore is not None) and (volumeKeystore is not None) and os.path.isdir(localKeystoreDir):
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
                    composeFileLines = [x for x in f.readlines() if f'image: ghcr.io/idaholab/malcolm/{service}' in x]
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
            raise Exception(f'Unable to identify a unique keystore file bind mount for {service} in {args.composeFile}')

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

    # success = (error == 0)
    return (err == 0), results


###################################################################################################
def status():
    global args
    global dockerComposeBin

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
        exit(err)


###################################################################################################
def netboxBackup(backupFileName=None):
    global args
    global dockerComposeBin

    # docker-compose use local temporary path
    osEnv = os.environ.copy()
    osEnv['TMPDIR'] = MalcolmTmpPath

    uidGidDict = GetUidGidFromComposeFile(args.composeFile)

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
        raise Exception(f'Error creating NetBox configuration database backup')

    if (backupFileName is None) or (len(backupFileName) == 0):
        backupFileName = f"malcolm_netbox_backup_{time.strftime('%Y%m%d-%H%M%S')}.gz"

    with gzip.GzipFile(backupFileName, "wb") as f:
        f.write(bytes('\n'.join(results), 'utf-8'))

    backupFileParts = os.path.splitext(backupFileName)
    backupMediaFileName = backupFileParts[0] + ".media.tar.gz"
    with tarfile.open(backupMediaFileName, 'w:gz') as t:
        t.add(os.path.join(os.path.join(MalcolmPath, 'netbox'), 'media'), arcname='.')

    return backupFileName, backupMediaFileName


###################################################################################################
def netboxRestore(backupFileName=None):
    global args
    global dockerComposeBin

    if backupFileName and os.path.isfile(backupFileName):
        # docker-compose use local temporary path
        osEnv = os.environ.copy()
        osEnv['TMPDIR'] = MalcolmTmpPath

        uidGidDict = GetUidGidFromComposeFile(args.composeFile)

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
        dockerCmd = dockerCmdBase + ['netbox', 'bash', '-c', 'pgrep -f /usr/local/bin/netbox_init.py | xargs -r kill']
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
            raise Exception(f'Error creating new NetBox database')

        # load the backed-up psql dump
        dockerCmd = dockerCmdBase + ['netbox-postgres', 'psql', '-U', 'netbox']
        with gzip.open(backupFileName, 'rt') as f:
            err, results = run_process(dockerCmd, env=osEnv, debug=args.debug, stdin=f.read())
        if (err != 0) or (len(results) == 0):
            raise Exception(f'Error loading NetBox database')

        # migrations if needed
        dockerCmd = dockerCmdBase + ['netbox', '/opt/netbox/netbox/manage.py', 'migrate']
        err, results = run_process(dockerCmd, env=osEnv, debug=args.debug)
        if (err != 0) or (len(results) == 0):
            raise Exception(f'Error performing NetBox migration')

        # restore media directory
        backupFileParts = os.path.splitext(backupFileName)
        backupMediaFileName = backupFileParts[0] + ".media.tar.gz"
        mediaPath = os.path.join(os.path.join(MalcolmPath, 'netbox'), 'media')
        if os.path.isfile(backupMediaFileName) and os.path.isdir(mediaPath):
            RemoveEmptyFolders(mediaPath, removeRoot=False)
            with tarfile.open(backupMediaFileName) as t:
                t.extractall(mediaPath)


###################################################################################################
def logs():
    global args
    global dockerBin
    global dockerComposeBin

    urlUserPassRegEx = re.compile(r'(\w+://[^/]+?:)[^/]+?(@[^/]+)')

    # noisy logs (a lot of it is NGINX logs from health checks)
    ignoreRegEx = re.compile(
        r"""
    .+(
        deprecated
      | "GET\s+/\s+HTTP/1\.\d+"\s+200\s+-
      | \bGET.+\b302\s+30\b
      | (async|output)\.go.+(reset\s+by\s+peer|Connecting\s+to\s+backoff|backoff.+established$)
      | /(opensearch-dashboards|dashboards|kibana)/(api/ui_metric/report|internal/search/(es|opensearch))
      | (Error\s+during\s+file\s+comparison|File\s+was\s+renamed):\s+/zeek/live/logs/
      | /_ns_/nstest\.html
      | /usr/share/logstash/x-pack/lib/filters/geoip/database_manager
      | \b(d|es)?stats\.json
      | \b1.+GET\s+/\s+.+401.+curl
      | _cat/indices
      | branding.*config\s+is\s+not\s+found\s+or\s+invalid
      | but\s+there\s+are\s+no\s+living\s+connections
      | Connecting\s+to\s+backoff
      | curl.+localhost.+GET\s+/api/status\s+200
      | DEPRECATION
      | descheduling\s+job\s*id
      | eshealth
      | esindices/list
      | executing\s+attempt_(transition|set_replica_count)\s+for
      | GET\s+/(netbox/api|_cat/health|api/status|sessions2-|arkime_\w+).+HTTP/[\d\.].+\b200\b
      | loaded\s+config\s+'/etc/netbox/config/
      | "netbox"\s+application\s+started
      | \[notice\].+app\s+process\s+\d+\s+exited\s+with\s+code\s+0\b
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
    dupeRegEx = re.compile(
        r"""
    .+(
        Maybe the destination pipeline is down or stopping
    )
  """,
        re.VERBOSE | re.IGNORECASE,
    )

    serviceRegEx = re.compile(r'^(?P<service>.+?\|)\s*(?P<message>.*)$')
    iso8601TimeRegEx = re.compile(
        r'^(-?(?:[1-9][0-9]*)?[0-9]{4})-(1[0-2]|0[1-9])-(3[01]|0[1-9]|[12][0-9])T(2[0-3]|[01][0-9]):([0-5][0-9]):([0-5][0-9])(\.[0-9]+)?(Z|[+-](?:2[0-3]|[01][0-9]):[0-5][0-9])?$'
    )

    finishedStartingRegEx = re.compile(r'.+Pipelines\s+running\s+\{.*:non_running_pipelines=>\[\]\}')
    finishedStarting = False

    # increase COMPOSE_HTTP_TIMEOUT to be ridiculously large so docker-compose never times out the TTY doing debug output
    osEnv = os.environ.copy()
    osEnv['COMPOSE_HTTP_TIMEOUT'] = '100000000'
    # docker-compose use local temporary path
    osEnv['TMPDIR'] = MalcolmTmpPath

    err, out = run_process(
        [dockerComposeBin, '-f', args.composeFile, 'ps', args.service][: 5 if args.service is not None else -1],
        env=osEnv,
        debug=args.debug,
    )
    print("\n".join(out))

    if args.logLineCount is None:
        args.logLineCount = 'all'

    process = Popen(
        [
            dockerComposeBin,
            '-f',
            args.composeFile,
            'logs',
            '--tail',
            str(args.logLineCount),
            '-f',
            args.service,
        ][: 8 if args.service is not None else -1],
        env=osEnv,
        stdout=PIPE,
        stderr=None if args.debug else DEVNULL,
    )
    while True:
        output = process.stdout.readline()
        if (len(output) == 0) and (process.poll() is not None):
            break
        if output:
            outputStr = urlUserPassRegEx.sub(r"\1xxxxxxxx\2", output.decode().strip())
            outputStrEscaped = EscapeAnsi(outputStr)
            if ignoreRegEx.match(outputStrEscaped):
                pass  ### print(f'!!!!!!!: {outputStr}')
            elif (
                (args.cmdStart or args.cmdRestart)
                and (not args.cmdLogs)
                and finishedStartingRegEx.match(outputStrEscaped)
            ):
                finishedStarting = True
            else:
                serviceMatch = serviceRegEx.search(outputStrEscaped)
                serviceMatchFmt = serviceRegEx.search(outputStr) if coloramaImported else serviceMatch
                serviceStr = serviceMatchFmt.group('service') if (serviceMatchFmt is not None) else ''

                messageStr = serviceMatch.group('message') if (serviceMatch is not None) else ''
                messageStrSplit = messageStr.split(' ')
                messageTimeMatch = iso8601TimeRegEx.match(messageStrSplit[0])
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

                    if (
                        ('job.schedule' in outputJson)
                        and ('job.position' in outputJson)
                        and ('job.command' in outputJson)
                    ):
                        # this is a status output line from supercronic, let's format and clean it up so it fits in better with the rest of the logs

                        # remove some clutter for the display
                        for noisyKey in ['level', 'channel', 'iteration', 'job.position', 'job.schedule']:
                            outputJson.pop(noisyKey, None)

                        # if it's just command and message, format those NOT as JSON
                        jobCmd = outputJson['job.command']
                        jobStatus = outputJson['msg']
                        if (len(outputJson.keys()) == 2) and ('job.command' in outputJson) and ('msg' in outputJson):
                            # if it's the most common status (starting or job succeeded) then don't print unless debug mode
                            if args.debug or ((jobStatus != 'starting') and (jobStatus != 'job succeeded')):
                                print(
                                    f"{serviceStr}{Style.RESET_ALL if coloramaImported else ''} {timeStr} {jobCmd}: {jobStatus}"
                                )
                            else:
                                pass

                        else:
                            # standardize and print the JSON output
                            print(
                                f"{serviceStr}{Style.RESET_ALL if coloramaImported else ''} {timeStr}{json.dumps(outputJson)}"
                            )

                    elif 'dashboards' in serviceStr:
                        # this is an output line from dashboards, let's clean it up a bit: remove some clutter for the display
                        for noisyKey in ['type', 'tags', 'pid', 'method', 'prevState', 'prevMsg']:
                            outputJson.pop(noisyKey, None)

                        # standardize and print the JSON output
                        print(
                            f"{serviceStr}{Style.RESET_ALL if coloramaImported else ''} {timeStr}{json.dumps(outputJson)}"
                        )

                    elif 'filebeat' in serviceStr:
                        # this is an output line from filebeat, let's clean it up a bit: remove some clutter for the display
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
                            print(
                                f"{serviceStr}{Style.RESET_ALL if coloramaImported else ''} {timeStr}{outputJson['message'].rstrip('.')}: {outputJson['source_file']}"
                            )

                        elif len(outputJson.keys()) == 1:
                            outputKey = next(iter(outputJson))
                            print(
                                f"{serviceStr}{Style.RESET_ALL if coloramaImported else ''} {timeStr}{outputKey + ': ' if outputKey != 'message' else ''}{outputJson[outputKey]}"
                            )
                        else:
                            # standardize and print the JSON output
                            print(
                                f"{serviceStr}{Style.RESET_ALL if coloramaImported else ''} {timeStr}{json.dumps(outputJson)}"
                            )

                    else:
                        # standardize and print the JSON output
                        print(
                            f"{serviceStr}{Style.RESET_ALL if coloramaImported else ''} {timeStr}{json.dumps(outputJson)}"
                        )

                else:
                    # just a regular non-JSON string, print as-is
                    print(outputStr if coloramaImported else outputStrEscaped)

        else:
            time.sleep(0.5)

        if finishedStarting:
            process.terminate()
            try:
                process.wait(timeout=5.0)
            except TimeoutExpired:
                process.kill()
            # # TODO: Replace 'localhost' with an outwards-facing IP since I doubt anybody is
            # accessing these from the Malcolm server.
            print("\nStarted Malcolm\n\n")
            print("Malcolm services can be accessed via the following URLs:")
            print("------------------------------------------------------------------------------")
            print("  - Arkime: https://localhost/")
            print("  - OpenSearch Dashboards: https://localhost/dashboards/")
            print("  - PCAP upload (web): https://localhost/upload/")
            print("  - PCAP upload (sftp): sftp://username@127.0.0.1:8022/files/")
            print("  - Host and subnet name mapping editor: https://localhost/name-map-ui/")
            print("  - NetBox: https://localhost/netbox/\n")
            print("  - Account management: https://localhost:488/\n")
            print("  - Documentation: https://localhost/readme/\n")

    process.poll()


###################################################################################################
def stop(wipe=False):
    global args
    global dockerBin
    global dockerComposeBin
    global dockerComposeYaml

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
            BoundPath("upload", "/var/www/upload/server/php/chroot/files", True, None, None),
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
                            if (os.path.isfile(fileSpec) or os.path.islink(fileSpec)) and (not file.startswith('.git')):
                                try:
                                    os.remove(fileSpec)
                                except:
                                    pass
                # delete whole directories
                if boundPath.relative_dirs:
                    for relDir in GetIterable(boundPath.relative_dirs):
                        tmpPath = os.path.join(localPath, relDir)
                        if os.path.isdir(tmpPath):
                            if args.debug:
                                eprint(f'Performing rmtree on "{tmpPath}"')
                            shutil.rmtree(tmpPath, ignore_errors=True)
                # cleanup empty directories
                if boundPath.clean_empty_dirs:
                    for cleanDir in GetIterable(boundPath.clean_empty_dirs):
                        tmpPath = os.path.join(localPath, cleanDir)
                        if os.path.isdir(tmpPath):
                            if args.debug:
                                eprint(f'Performing RemoveEmptyFolders on "{tmpPath}"')
                            RemoveEmptyFolders(tmpPath, removeRoot=False)

        eprint("Malcolm has been stopped and its data cleared\n")


###################################################################################################
def start():
    global args
    global dockerBin
    global dockerComposeBin

    # touch the htadmin metadata file and .opensearch.*.curlrc files
    open(os.path.join(MalcolmPath, os.path.join('htadmin', 'metadata')), 'a').close()
    open(os.path.join(MalcolmPath, '.opensearch.primary.curlrc'), 'a').close()
    open(os.path.join(MalcolmPath, '.opensearch.secondary.curlrc'), 'a').close()

    # make sure the auth files exist. if we are in an interactive shell and we're
    # missing any of the auth files, prompt to create them now
    if sys.__stdin__.isatty() and (not MalcolmAuthFilesExist()):
        authSetup()

    # still missing? sorry charlie
    if not MalcolmAuthFilesExist():
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
        os.path.join(MalcolmPath, os.path.join('netbox', os.path.join('env', 'netbox.env'))),
        os.path.join(MalcolmPath, os.path.join('netbox', os.path.join('env', 'postgres.env'))),
        os.path.join(MalcolmPath, os.path.join('netbox', os.path.join('env', 'redis-cache.env'))),
        os.path.join(MalcolmPath, os.path.join('netbox', os.path.join('env', 'redis.env'))),
    ]:
        # chmod 600 authFile
        os.chmod(authFile, stat.S_IRUSR | stat.S_IWUSR)

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
        BoundPath("upload", "/var/www/upload/server/php/chroot/files", False, None, None),
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
                for relDir in GetIterable(boundPath.relative_dirs):
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

    # touch the zeek intel file
    open(os.path.join(MalcolmPath, os.path.join('zeek', os.path.join('intel', '__load__.zeek'))), 'a').close()

    # clean up any leftover intel update locks
    shutil.rmtree(os.path.join(MalcolmPath, os.path.join('zeek', os.path.join('intel', 'lock'))), ignore_errors=True)

    # increase COMPOSE_HTTP_TIMEOUT to be ridiculously large so docker-compose never times out the TTY doing debug output
    osEnv = os.environ.copy()
    osEnv['COMPOSE_HTTP_TIMEOUT'] = '100000000'
    # docker-compose use local temporary path
    osEnv['TMPDIR'] = MalcolmTmpPath

    # start docker
    err, out = run_process([dockerComposeBin, '-f', args.composeFile, 'up', '--detach'], env=osEnv, debug=args.debug)
    if err != 0:
        eprint("Malcolm failed to start\n")
        eprint("\n".join(out))
        exit(err)


###################################################################################################
def authSetup(wipe=False):
    global args
    global dockerBin
    global dockerComposeBin
    global opensslBin

    # for beats/logstash self-signed certificates
    logstashPath = os.path.join(MalcolmPath, os.path.join('logstash', 'certs'))
    filebeatPath = os.path.join(MalcolmPath, os.path.join('filebeat', 'certs'))

    txRxScript = None
    if (pyPlatform != PLATFORM_WINDOWS) and Which("croc"):
        txRxScript = 'tx-rx-secure.sh' if Which('tx-rx-secure.sh') else None
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
            not os.path.isfile(os.path.join(MalcolmPath, os.path.join('netbox', os.path.join('env', 'netbox.env')))),
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
                authEnvFile = os.path.join(MalcolmPath, 'auth.env')
                if os.path.isfile(authEnvFile):
                    prevAuthInfo = defaultdict(str)
                    with open(authEnvFile, 'r') as f:
                        for line in f:
                            try:
                                k, v = line.rstrip().split("=")
                                prevAuthInfo[k] = v.strip('"')
                            except:
                                pass
                    if len(prevAuthInfo['MALCOLM_USERNAME']) > 0:
                        usernamePrevious = prevAuthInfo['MALCOLM_USERNAME']

                # get openssl hash of password
                err, out = run_process(
                    [opensslBin, 'passwd', '-1', '-stdin'], stdin=password, stderr=False, debug=args.debug
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
                                except:
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
                    f.write('secure_path  = ./config/htpasswd\n')
                    f.write('; metadata file\n')
                    f.write('metadata_path  = ./config/metadata\n\n')
                    f.write('; administrator user/password (htpasswd -b -c -B ...)\n')
                    f.write(f'admin_user = {username}\n\n')
                    f.write('; username field quality checks\n')
                    f.write(';\n')
                    f.write('min_username_len = 4\n')
                    f.write('max_username_len = 12\n\n')
                    f.write('; Password field quality checks\n')
                    f.write(';\n')
                    f.write('min_password_len = 6\n')
                    f.write('max_password_len = 20\n\n')

                # touch the metadata file
                open(os.path.join(MalcolmPath, os.path.join('htadmin', 'metadata')), 'a').close()

                DisplayMessage(
                    f'Additional local accounts can be created at https://localhost:488/ when Malcolm is running',
                )

            # generate HTTPS self-signed certificates
            elif authItem[0] == 'webcerts':
                with pushd(os.path.join(MalcolmPath, os.path.join('nginx', 'certs'))):
                    # remove previous files
                    for oldfile in glob.glob("*.pem"):
                        os.remove(oldfile)

                    # generate dhparam -------------------------------
                    err, out = run_process(
                        [opensslBin, 'dhparam', '-out', 'dhparam.pem', '2048'], stderr=True, debug=args.debug
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
                        [opensslBin, 'genrsa', '-out', 'ca.key', '2048'], stderr=True, debug=args.debug
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
                        [opensslBin, 'genrsa', '-out', 'server.key', '2048'], stderr=True, debug=args.debug
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
                        [opensslBin, 'genrsa', '-out', 'client.key', '2048'], stderr=True, debug=args.debug
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
                            f'Require SSL certificate validation for OpenSearch communication?',
                            default=(not (('k' in prevCurlContents) or ('insecure' in prevCurlContents))),
                        )

                        with open(openSearchCredFileName, 'w') as f:
                            f.write(f'user: "{EscapeForCurl(esUsername)}:{EscapeForCurl(esPassword)}"\n')
                            if not esSslVerify:
                                f.write('insecure\n')

                    else:
                        try:
                            os.remove(openSearchCredFileName)
                        except:
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
                with pushd(os.path.join(MalcolmPath, os.path.join('netbox', 'env'))):
                    netboxPwAlphabet = string.ascii_letters + string.digits + '_'
                    netboxKeyAlphabet = string.ascii_letters + string.digits + '%@<=>?~^_-'
                    netboxPostGresPassword = ''.join(secrets.choice(netboxPwAlphabet) for i in range(24))
                    netboxRedisPassword = ''.join(secrets.choice(netboxPwAlphabet) for i in range(24))
                    netboxRedisCachePassword = ''.join(secrets.choice(netboxPwAlphabet) for i in range(24))
                    netboxSuPassword = ''.join(secrets.choice(netboxPwAlphabet) for i in range(24))
                    netboxSuToken = ''.join(secrets.choice(netboxPwAlphabet) for i in range(40))
                    netboxSecretKey = ''.join(secrets.choice(netboxKeyAlphabet) for i in range(50))

                    with open('postgres.env', 'w') as f:
                        f.write('POSTGRES_DB=netbox\n')
                        f.write(f'POSTGRES_PASSWORD={netboxPostGresPassword}\n')
                        f.write('POSTGRES_USER=netbox\n')
                    os.chmod('postgres.env', stat.S_IRUSR | stat.S_IWUSR)

                    with open('redis-cache.env', 'w') as f:
                        f.write(f'REDIS_PASSWORD={netboxRedisCachePassword}\n')
                    os.chmod('redis-cache.env', stat.S_IRUSR | stat.S_IWUSR)

                    with open('redis.env', 'w') as f:
                        f.write(f'REDIS_PASSWORD={netboxRedisPassword}\n')
                    os.chmod('redis.env', stat.S_IRUSR | stat.S_IWUSR)

                    if (not os.path.isfile('netbox.env')) and (os.path.isfile('netbox.env.example')):
                        shutil.copy2('netbox.env.example', 'netbox.env')

                    with fileinput.FileInput('netbox.env', inplace=True, backup=None) as envFile:
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

                            print(line)

                    os.chmod('netbox.env', stat.S_IRUSR | stat.S_IWUSR)

            elif authItem[0] == 'txfwcerts':
                DisplayMessage(
                    f'Run configure-capture on the remote log forwarder, select "Configure Forwarding," then "Receive client SSL files..."',
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
    global opensslBin
    global yamlImported
    global dockerComposeYaml

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
        help='docker-compose YML file',
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
        '-n',
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

    yamlImported = YAMLDynamic(debug=args.debug)
    if args.debug:
        eprint(f"Imported yaml: {yamlImported}")
    if not yamlImported:
        exit(2)

    with pushd(MalcolmPath):
        # don't run this as root
        if (pyPlatform != PLATFORM_WINDOWS) and (
            (os.getuid() == 0) or (os.geteuid() == 0) or (getpass.getuser() == 'root')
        ):
            raise Exception(f'{ScriptName} should not be run as root')

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

        # make sure docker/docker-compose is available
        dockerBin = 'docker.exe' if ((pyPlatform == PLATFORM_WINDOWS) and Which('docker.exe')) else 'docker'
        if (pyPlatform == PLATFORM_WINDOWS) and Which('docker-compose.exe'):
            dockerComposeBin = 'docker-compose.exe'
        elif Which('docker-compose'):
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

        # identify openssl binary
        opensslBin = 'openssl.exe' if ((pyPlatform == PLATFORM_WINDOWS) and Which('openssl.exe')) else 'openssl'

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
                raise Exception(f'NetBox configuration database file must be specified with --netbox-restore')

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
