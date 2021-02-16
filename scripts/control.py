#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2021 Battelle Energy Alliance, LLC.  All rights reserved.

import argparse
import errno
import getpass
import glob
import json
import os
import platform
import re
import shutil
import stat
import sys

from malcolm_common import *
from contextlib import nullcontext
from collections import defaultdict, namedtuple
from subprocess import (PIPE, STDOUT, Popen, check_call, CalledProcessError)

###################################################################################################
ScriptName = os.path.basename(__file__)

pyPlatform = platform.system()

args = None
dockerBin = None
dockerComposeBin = None
opensslBin = None

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

  # the elastic containers all follow the same naming pattern for these executables
  keystoreBinProc = f"/usr/share/{service}/bin/{service}-keystore"

  # if we're using docker-uid-gid-setup.sh to drop privileges as we spin up a container
  dockerUidGuidSetup = "/usr/local/bin/docker-uid-gid-setup.sh"

  # open up the docker-compose file and "grep" for the line where the keystore file
  # is bind-mounted into the service container (once and only once). the bind
  # mount needs to exist in the YML file and the local directory containing the
  # keystore file needs to exist (although the file itself might not yet)
  localKeystore = None
  localKeystoreDir = None
  localKeystorePreExists = False
  volumeKeystore = None
  volumeKeystoreDir = None

  try:

    composeFileLines = list()
    with open(args.composeFile, 'r') as f:
      composeFileLines = [x for x in f.readlines() if re.search(fr'-.*?{service}.keystore\s*:.*{service}.keystore', x)]
    if (len(composeFileLines) == 1) and (len(composeFileLines[0]) > 0):
      matches = re.search(fr'-\s*(?P<localKeystore>.*?{service}.keystore)\s*:\s*(?P<volumeKeystore>.*?{service}.keystore)', composeFileLines[0])
      if matches:
        localKeystore = os.path.realpath(matches.group('localKeystore'))
        localKeystoreDir = os.path.dirname(localKeystore)
        volumeKeystore = matches.group('volumeKeystore')
        volumeKeystoreDir = os.path.dirname(volumeKeystore)

    if (localKeystore is not None) and (volumeKeystore is not None) and os.path.isdir(localKeystoreDir):
      localKeystorePreExists = os.path.isfile(localKeystore)

      dockerCmd = None

      # determine if Malcolm is running; if so, we'll use docker-compose exec, other wise we'll use docker run
      err, out = run_process([dockerComposeBin, '-f', args.composeFile, 'ps', '-q', service], debug=args.debug)
      out[:] = [x for x in out if x]
      if (err == 0) and (len(out) > 0):
        # Malcolm is running, we can use an existing container

        # assemble the service-keystore command
        dockerCmd = [dockerComposeBin, 'exec',

                     # if using stdin, indicate the container is "interactive", else noop (duplicate --rm)
                     '-T' if ('stdin' in run_process_kwargs and run_process_kwargs['stdin']) else '',

                     # execute as current UID:GID, as we're assuming this would match docker-compose YML PUID/PGID already running
                     # todo: alternately grep PUID/PGID out of docker-compose YML
                     '-u', f'{os.getuid()}:{os.getgid()}' if (pyPlatform != PLATFORM_WINDOWS) else '1000:1000',

                     # the work directory in the container is the directory to contain the keystore file
                     '-w', volumeKeystoreDir,

                     # the service name
                     service,

                     # the executable filespec
                     keystoreBinProc]

      else:
        # Malcolm isn't running, do 'docker run' to spin up a temporary container to run the ocmmand

        # "grep" the docker image out of the service's image: value from the docker-compose YML file
        serviceImage = None
        composeFileLines = list()
        with open(args.composeFile, 'r') as f:
          composeFileLines = [x for x in f.readlines() if f'image: malcolmnetsec/{service}' in x]
        if (len(composeFileLines) > 0) and (len(composeFileLines[0]) > 0):
          imageLineValues = composeFileLines[0].split()
          if (len(imageLineValues) > 1):
            serviceImage = imageLineValues[1]

        if serviceImage is not None:
          # assemble the service-keystore command
          dockerCmd = [dockerBin, 'run',

                       # remove the container when complete
                       '--rm',

                       # if using stdin, indicate the container is "interactive", else noop
                       '-i' if ('stdin' in run_process_kwargs and run_process_kwargs['stdin']) else '',

                       # if     dropPriv, dockerUidGuidSetup will take care of dropping privileges for the correct UID/GID
                       # if NOT dropPriv, enter with the keystore executable directly
                       '--entrypoint', dockerUidGuidSetup if dropPriv else keystoreBinProc,
                       '--env', f'DEFAULT_UID={os.getuid() if (pyPlatform != PLATFORM_WINDOWS) else 1000}',
                       '--env', f'DEFAULT_GID={os.getgid() if (pyPlatform != PLATFORM_WINDOWS) else 1000}',

                       # rw bind mount the local directory to contain the keystore file to the container directory
                       '-v', f'{localKeystoreDir}:{volumeKeystoreDir}:rw',

                       # the work directory in the container is the directory to contain the keystore file
                       '-w', volumeKeystoreDir,

                       # if     dropPriv, execute as root, as docker-uid-gid-setup.sh will drop privileges for us
                       # if NOT dropPriv, execute as 1000:1000; this should be the right thing to do as this is how the images were built
                       #                  todo: alternately:
                       #                    '-u', 'root' if dropPriv else f'{os.getuid() if (pyPlatform != PLATFORM_WINDOWS) else 1000}:{os.getgid() if (pyPlatform != PLATFORM_WINDOWS) else 1000}'
                       '-u', 'root' if dropPriv else '1000:1000',

                       # the service image name grepped from the YML file
                       serviceImage]

          if dropPriv:
            # the keystore executable filespec (as we used dockerUidGuidSetup as the entrypoint)
            dockerCmd.append(keystoreBinProc)

        else:
          raise Exception(f'Unable to identify docker image for {service} in {args.composeFile}')

      if (dockerCmd is not None):

        # append whatever other arguments to pass to the executable filespec
        if keystore_args:
          dockerCmd.extend(list(keystore_args))

        dockerCmd[:] = [x for x in dockerCmd if x]

        # execute the command, passing through run_process_kwargs to run_process as expanded keyword arguments
        err, results = run_process(dockerCmd, debug=args.debug, **run_process_kwargs)
        if (err != 0) or (not os.path.isfile(localKeystore)):
          raise Exception(f'Error processing command {service} keystore: {results}')

      else:
        raise Exception(f'Unable formulate keystore command for {service} in {args.composeFile}')

    else:
      raise Exception(f'Unable to identify a unique keystore file bind mount for {service} in {args.composeFile}')

  except Exception as e:
    if (err == 0):
      err = -1

    # don't be so whiny if the "create" failed just because it already existed or a 'remove' failed on a nonexistant item
    if ((not args.debug) and
        list(keystore_args) and
        (len(list(keystore_args)) > 0) and
        (list(keystore_args)[0].lower() in ('create', 'remove')) and
        localKeystorePreExists):
      pass
    else:
      eprint(e)

  # success = (error == 0)
  return (err == 0), results

###################################################################################################
def status():
  global args
  global dockerComposeBin

  err, out = run_process([dockerComposeBin, '-f', args.composeFile, 'ps'], debug=args.debug)
  if (err == 0):
    print("\n".join(out))
  else:
    eprint("Failed to display Malcolm status\n")
    eprint("\n".join(out))
    exit(err)

###################################################################################################
def logs():
  global args
  global dockerBin
  global dockerComposeBin

  # noisy logs (a lot of it is NGINX logs from health checks)
  ignoreRegEx = re.compile(r"""
    .+(
        deprecated
      | eshealth
      | remov(ed|ing)\s+(old\s+file|dead\s+symlink|empty\s+directory)
      | update_mapping
      | throttling\s+index
      | but\s+there\s+are\s+no\s+living\s+connections
      | saved_objects
      | retry\.go.+(send\s+unwait|done$)
      | (async|output)\.go.+(reset\s+by\s+peer|Connecting\s+to\s+backoff|backoff.+established$)
      | \b(d|es)?stats\.json
      | /_ns_/nstest\.html
      | esindices/list
      | _cat/indices
      | use_field_mapping
      | reaped\s+unknown\s+pid
      | Successfully\s+handled\s+GET\s+request\s+for\s+'/'
      | GET\s+/(_cat/health|api/status|sessions2-).+HTTP/[\d\.].+\b200\b
      | POST\s+/(d?stats/(d?stat|_doc|_search)|_bulk|fields/(field/)?_search).+HTTP/[\d\.].+\b20[01]\b
      | POST\s+HTTP/[\d\.].+\b200\b
      | POST\s+/server/php/\s+HTTP/\d+\.\d+"\s+\d+\s+\d+.*:8443/
      | curl.+localhost.+GET\s+/api/status\s+200
      | \b1.+GET\s+/\s+.+401.+curl
    )
  """, re.VERBOSE | re.IGNORECASE)

  serviceRegEx = re.compile(r'^(?P<service>.+?\|)\s*(?P<message>.*)$')

  err, out = run_process([dockerComposeBin, '-f', args.composeFile, 'ps'], debug=args.debug)
  print("\n".join(out))

  # increase COMPOSE_HTTP_TIMEOUT to be ridiculously large so docker-compose never times out the TTY doing debug output
  osEnv = os.environ.copy()
  osEnv['COMPOSE_HTTP_TIMEOUT'] = '100000000'

  process = Popen([dockerComposeBin, '-f', args.composeFile, 'logs', '-f'], env=osEnv, stdout=PIPE)
  while True:
    output = process.stdout.readline()
    if (len(output) == 0) and (process.poll() is not None):
      break
    if output:
      outputStr = output.decode().strip()
      outputStrEscaped = EscapeAnsi(outputStr)
      if ignoreRegEx.match(outputStrEscaped):
        pass  ### print(f'!!!!!!!: {outputStr}')
      else:
        serviceMatch = serviceRegEx.search(outputStrEscaped)
        serviceMatchFmt = serviceRegEx.search(outputStr) if coloramaImported else serviceMatch
        serviceStr = serviceMatchFmt.group('service') if (serviceMatchFmt is not None) else ''
        messageStr = serviceMatch.group('message') if (serviceMatch is not None) else ''
        outputJson = LoadStrIfJson(messageStr)
        if (outputJson is not None):

          # if there's a timestamp in the JSON, move it outside of the JSON to the beginning of the log string
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

          if ('job.schedule' in outputJson) and ('job.position' in outputJson) and ('job.command' in outputJson):

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
                print(f"{serviceStr}{Style.RESET_ALL if coloramaImported else ''} {timeStr} {jobCmd}: {jobStatus}")
              else:
                pass

            else:
              # standardize and print the JSON output
              print(f"{serviceStr}{Style.RESET_ALL if coloramaImported else ''} {timeStr}{json.dumps(outputJson)}")

          elif ('kibana' in serviceStr):
            # this is an output line from kibana, let's clean it up a bit: remove some clutter for the display
            for noisyKey in ['type', 'tags', 'pid', 'method', 'prevState', 'prevMsg']:
              outputJson.pop(noisyKey, None)

            # standardize and print the JSON output
            print(f"{serviceStr}{Style.RESET_ALL if coloramaImported else ''} {timeStr}{json.dumps(outputJson)}")

          else:
            # standardize and print the JSON output
            print(f"{serviceStr}{Style.RESET_ALL if coloramaImported else ''} {timeStr}{json.dumps(outputJson)}")

        else:
          # just a regular non-JSON string, print as-is
          print(outputStr if coloramaImported else outputStrEscaped)

    else:
      time.sleep(0.5)
  process.poll()

###################################################################################################
def stop(wipe=False):
  global args
  global dockerBin
  global dockerComposeBin

  if wipe:
    # attempt to DELETE _template/zeek_template in Elasticsearch
    err, out = run_process([dockerComposeBin, '-f', args.composeFile, 'exec', 'arkime', 'bash', '-c', 'curl -fs --output /dev/null -H"Content-Type: application/json" -XDELETE "http://$ES_HOST:$ES_PORT/_template/zeek_template"'], debug=args.debug)

  # if stop.sh is being called with wipe.sh (after the docker-compose file)
  # then also remove named and anonymous volumes (not external volumes, of course)
  err, out = run_process([dockerComposeBin, '-f', args.composeFile, 'down', '--volumes'][:5 if wipe else -1], debug=args.debug)
  if (err == 0):
    eprint("Stopped Malcolm\n")
  else:
    eprint("Malcolm failed to stop\n")
    eprint("\n".join(out))
    exit(err)

  if wipe:
    # delete elasticsearch database
    shutil.rmtree(os.path.join(MalcolmPath, 'elasticsearch/nodes'), ignore_errors=True)

    # delete data files (backups, zeek logs, arkime logs, PCAP files, captured PCAP files)
    for dataDir in ['elasticsearch-backup', 'zeek-logs', 'moloch-logs', 'pcap', 'moloch-raw']:
      for root, dirnames, filenames in os.walk(os.path.join(MalcolmPath, dataDir), topdown=True, onerror=None):
        for file in filenames:
          fileSpec = os.path.join(root, file)
          if (os.path.isfile(fileSpec) or os.path.islink(fileSpec)) and (not file.startswith('.git')):
            try:
              os.remove(fileSpec)
            except:
              pass

    # clean up empty directories
    for dataDir in [os.path.join('elasticsearch-backup', 'logs'), os.path.join('zeek-logs', 'processed'), os.path.join('zeek-logs', 'current')]:
      RemoveEmptyFolders(dataDir, removeRoot=False)

    eprint("Malcolm has been stopped and its data cleared\n")

###################################################################################################
def start():
  global args
  global dockerBin
  global dockerComposeBin

  # make sure the auth files exist. if we are in an interactive shell and we're
  # missing any of the auth files, prompt to create them now
  if sys.__stdin__.isatty() and (not MalcolmAuthFilesExist()):
    authSetup()

  # still missing? sorry charlie
  if (not MalcolmAuthFilesExist()):
    raise Exception('Malcolm administrator account authentication files are missing, please run ./scripts/auth_setup to generate them')

  # touch the metadata file
  open(os.path.join(MalcolmPath, os.path.join('htadmin', 'metadata')), 'a').close()

  # if the elasticsearch and logstash keystore don't exist exist, create empty ones
  if not os.path.isfile(os.path.join(MalcolmPath, os.path.join('elasticsearch', 'elasticsearch.keystore'))):
    keystore_op('elasticsearch', True, 'create')
  if not os.path.isfile(os.path.join(MalcolmPath, os.path.join('logstash', os.path.join('certs', 'logstash.keystore')))):
    keystore_op('logstash', False, 'create')

  # make sure permissions are set correctly for the nginx worker processes
  for authFile in [os.path.join(MalcolmPath, os.path.join('nginx', 'htpasswd')),
                   os.path.join(MalcolmPath, os.path.join('nginx', 'nginx_ldap.conf')),
                   os.path.join(MalcolmPath, os.path.join('htadmin', 'config.ini')),
                   os.path.join(MalcolmPath, os.path.join('htadmin', 'metadata'))]:
    # chmod 644 authFile
    os.chmod(authFile, stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH)

  # make sure some directories exist before we start
  for path in [os.path.join(MalcolmPath, 'elasticsearch'),
               os.path.join(MalcolmPath, 'elasticsearch-backup'),
               os.path.join(MalcolmPath, os.path.join('nginx', 'ca-trust')),
               os.path.join(MalcolmPath, os.path.join('pcap', 'upload')),
               os.path.join(MalcolmPath, os.path.join('pcap', 'processed')),
               os.path.join(MalcolmPath, os.path.join('zeek-logs', 'current')),
               os.path.join(MalcolmPath, os.path.join('zeek-logs', 'upload')),
               os.path.join(MalcolmPath, os.path.join('zeek-logs', 'processed')),
               os.path.join(MalcolmPath, os.path.join('zeek-logs', 'extract_files'))]:
    try:
      os.makedirs(path)
    except OSError as exc:
      if (exc.errno == errno.EEXIST) and os.path.isdir(path):
        pass
      else:
        raise

  # increase COMPOSE_HTTP_TIMEOUT to be ridiculously large so docker-compose never times out the TTY doing debug output
  osEnv = os.environ.copy()
  osEnv['COMPOSE_HTTP_TIMEOUT'] = '100000000'

  # start docker
  err, out = run_process([dockerComposeBin, '-f', args.composeFile, 'up', '--detach'], env=osEnv, debug=args.debug)
  if (err == 0):
    eprint("Started Malcolm\n\n")
    eprint("In a few minutes, Malcolm services will be accessible via the following URLs:")
    eprint("------------------------------------------------------------------------------")
    eprint("  - Arkime: https://localhost/")
    eprint("  - Kibana: https://localhost/kibana/")
    eprint("  - PCAP upload (web): https://localhost/upload/")
    eprint("  - PCAP upload (sftp): sftp://username@127.0.0.1:8022/files/")
    eprint("  - Host and subnet name mapping editor: https://localhost/name-map-ui/\n")
    eprint("  - Account management: https://localhost:488/\n")
  else:
    eprint("Malcolm failed to start\n")
    eprint("\n".join(out))
    exit(err)

###################################################################################################
def authSetup(wipe=False):
  global args
  global dockerBin
  global dockerComposeBin
  global opensslBin

  if YesOrNo('Store administrator username/password for local Malcolm access?', default=True):

    # prompt username and password
    usernamePrevious = None
    password = None
    passwordConfirm = None
    passwordEncrypted = ''
    username = AskForString("Administrator username")

    while True:
      password = AskForPassword(f"{username} password: ")
      passwordConfirm = AskForPassword(f"{username} password (again): ")
      if (password == passwordConfirm):
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
      if (len(prevAuthInfo['MALCOLM_USERNAME']) > 0):
        usernamePrevious = prevAuthInfo['MALCOLM_USERNAME']

    # get openssl hash of password
    err, out = run_process([opensslBin, 'passwd', '-1', '-stdin'], stdin=password, stderr=False, debug=args.debug)
    if (err == 0) and (len(out) > 0) and (len(out[0]) > 0):
      passwordEncrypted = out[0]
    else:
      raise Exception('Unable to generate password hash with openssl')

    # write auth.env (used by htadmin and file-upload containers)
    with open(authEnvFile, 'w') as f:
      f.write("# Malcolm Administrator username and encrypted password for nginx reverse proxy (and upload server's SFTP access)\n")
      f.write(f'MALCOLM_USERNAME={username}\n')
      f.write(f'MALCOLM_PASSWORD={passwordEncrypted}\n')
    os.chmod(authEnvFile, stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH)

    # create or update the htpasswd file
    htpasswdFile = os.path.join(MalcolmPath, os.path.join('nginx', 'htpasswd'))
    htpasswdCmd = ['htpasswd',
                   '-i',
                   '-B',
                   htpasswdFile,
                   username]
    if not os.path.isfile(htpasswdFile):
      htpasswdCmd.insert(1, '-c')
    err, out = run_process(htpasswdCmd, stdin=password, stderr=True, debug=args.debug)
    if (err != 0):
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
      if (ldapType == "openldap"):
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
        f.write('# See https://github.com/kvspb/nginx-auth-ldap#available-config-parameters for options.\n\n')
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

  # generate HTTPS self-signed certificates
  if YesOrNo('(Re)generate self-signed certificates for HTTPS access', default=True):
    with pushd(os.path.join(MalcolmPath, os.path.join('nginx', 'certs'))):
      # remove previous files
      for oldfile in glob.glob("*.pem"):
        os.remove(oldfile)

      # generate dhparam -------------------------------
      err, out = run_process([opensslBin, 'dhparam', '-out', 'dhparam.pem', '2048'], stderr=True, debug=args.debug)
      if (err != 0):
        raise Exception(f'Unable to generate dhparam.pem file: {out}')

      # generate key/cert -------------------------------
      err, out = run_process([opensslBin, 'req', '-subj', '/CN=localhost', '-x509', '-newkey', 'rsa:4096', '-nodes', '-keyout', 'key.pem', '-out', 'cert.pem', '-days', '3650'], stderr=True, debug=args.debug)
      if (err != 0):
        raise Exception(f'Unable to generate key.pem/cert.pem file(s): {out}')

  # generate beats/logstash self-signed certificates
  logstashPath = os.path.join(MalcolmPath, os.path.join('logstash', 'certs'))
  filebeatPath = os.path.join(MalcolmPath, os.path.join('filebeat', 'certs'))
  if YesOrNo('(Re)generate self-signed certificates for a remote log forwarder', default=True):
    with pushd(logstashPath):

      # make clean to clean previous files
      for pat in ['*.srl', '*.csr', '*.key', '*.crt', '*.pem']:
        for oldfile in glob.glob(pat):
          os.remove(oldfile)

      # -----------------------------------------------
      # generate new ca/server/client certificates/keys
      # ca -------------------------------
      err, out = run_process([opensslBin, 'genrsa', '-out', 'ca.key', '2048'], stderr=True, debug=args.debug)
      if (err != 0): raise Exception(f'Unable to generate ca.key: {out}')

      err, out = run_process([opensslBin, 'req', '-x509', '-new', '-nodes', '-key', 'ca.key', '-sha256', '-days', '9999', '-subj', '/C=US/ST=ID/O=sensor/OU=ca', '-out', 'ca.crt'], stderr=True, debug=args.debug)
      if (err != 0): raise Exception(f'Unable to generate ca.crt: {out}')

      # server -------------------------------
      err, out = run_process([opensslBin, 'genrsa', '-out', 'server.key', '2048'], stderr=True, debug=args.debug)
      if (err != 0): raise Exception(f'Unable to generate server.key: {out}')

      err, out = run_process([opensslBin, 'req', '-sha512', '-new', '-key', 'server.key', '-out', 'server.csr', '-config', 'server.conf'], stderr=True, debug=args.debug)
      if (err != 0): raise Exception(f'Unable to generate server.csr: {out}')

      err, out = run_process([opensslBin, 'x509', '-days', '3650', '-req', '-sha512', '-in', 'server.csr', '-CAcreateserial', '-CA', 'ca.crt', '-CAkey', 'ca.key', '-out', 'server.crt', '-extensions', 'v3_req', '-extfile', 'server.conf'], stderr=True, debug=args.debug)
      if (err != 0): raise Exception(f'Unable to generate server.crt: {out}')

      shutil.move("server.key", "server.key.pem")
      err, out = run_process([opensslBin, 'pkcs8', '-in', 'server.key.pem', '-topk8', '-nocrypt', '-out', 'server.key'], stderr=True, debug=args.debug)
      if (err != 0): raise Exception(f'Unable to generate server.key: {out}')

      # client -------------------------------
      err, out = run_process([opensslBin, 'genrsa', '-out', 'client.key', '2048'], stderr=True, debug=args.debug)
      if (err != 0): raise Exception(f'Unable to generate client.key: {out}')

      err, out = run_process([opensslBin, 'req', '-sha512', '-new', '-key', 'client.key', '-out', 'client.csr', '-config', 'client.conf'], stderr=True, debug=args.debug)
      if (err != 0): raise Exception(f'Unable to generate client.csr: {out}')

      err, out = run_process([opensslBin, 'x509', '-days', '3650', '-req', '-sha512', '-in', 'client.csr', '-CAcreateserial', '-CA', 'ca.crt', '-CAkey', 'ca.key', '-out', 'client.crt', '-extensions', 'v3_req', '-extensions', 'usr_cert', '-extfile', 'client.conf'], stderr=True, debug=args.debug)
      if (err != 0): raise Exception(f'Unable to generate client.crt: {out}')
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

  # create and populate keystore for remote
  if YesOrNo('Store username/password for forwarding Logstash events to a secondary, external Elasticsearch instance', default=False):

    # prompt username and password
    esPassword = None
    esPasswordConfirm = None
    esUsername = AskForString("External Elasticsearch username")

    while True:
      esPassword = AskForPassword(f"{esUsername} password: ")
      esPasswordConfirm = AskForPassword(f"{esUsername} password (again): ")
      if (esPassword == esPasswordConfirm):
        break
      eprint("Passwords do not match")

    # create logstash keystore file, don't complain if it already exists, and set the keystore items
    keystore_op('logstash', False, 'create', stdin='N')
    keystore_op('logstash', False, 'remove', 'ES_EXTERNAL_USER', '--force')
    keystore_op('logstash', False, 'add', 'ES_EXTERNAL_USER', '--stdin', '--force', stdin=esUsername)
    keystore_op('logstash', False, 'remove', 'ES_EXTERNAL_PASSWORD', '--force')
    keystore_op('logstash', False, 'add', 'ES_EXTERNAL_PASSWORD', '--stdin', '--force', stdin=esPassword)
    success, results = keystore_op('logstash', False, 'list')
    results = [x.upper() for x in results if x and (not x.upper().startswith('WARNING')) and (not x.upper().startswith('KEYSTORE')) and (not x.upper().startswith('USING BUNDLED JDK'))]
    if success and ('ES_EXTERNAL_USER' in results) and ('ES_EXTERNAL_PASSWORD' in results):
      eprint(f"External Elasticsearch instance variables stored: {', '.join(results)}")
    else:
      eprint("Failed to store external Elasticsearch instance variables:\n")
      eprint("\n".join(results))


  # Open Distro for Elasticsearch authenticate sender account credentials
  # https://opendistro.github.io/for-elasticsearch-docs/docs/alerting/monitors/#authenticate-sender-account
  if YesOrNo('Store username/password for email alert sender account (see https://opendistro.github.io/for-elasticsearch-docs/docs/alerting/monitors/#authenticate-sender-account)', default=False):

    # prompt username and password
    emailPassword = None
    emailPasswordConfirm = None
    emailSender = AskForString("Open Distro alerting email sender name")
    emailUsername = AskForString("Email account username")

    while True:
      emailPassword = AskForPassword(f"{emailUsername} password: ")
      emailPasswordConfirm = AskForPassword(f"{emailUsername} password (again): ")
      if (emailPassword == emailPasswordConfirm):
        break
      eprint("Passwords do not match")

    # create elasticsearch keystore file, don't complain if it already exists, and set the keystore items
    usernameKey = f'opendistro.alerting.destination.email.{emailSender}.username'
    passwordKey = f'opendistro.alerting.destination.email.{emailSender}.password'

    keystore_op('elasticsearch', True, 'create', stdin='N')
    keystore_op('elasticsearch', True, 'remove', usernameKey)
    keystore_op('elasticsearch', True, 'add', usernameKey, '--stdin', stdin=emailUsername)
    keystore_op('elasticsearch', True, 'remove', passwordKey)
    keystore_op('elasticsearch', True, 'add', passwordKey, '--stdin', stdin=emailPassword)
    success, results = keystore_op('elasticsearch', True, 'list')
    results = [x for x in results if x and (not x.upper().startswith('WARNING')) and (not x.upper().startswith('KEYSTORE'))]
    if success and (usernameKey in results) and (passwordKey in results):
      eprint(f"Email alert sender account variables stored: {', '.join(results)}")
    else:
      eprint("Failed to store email alert sender account variables:\n")
      eprint("\n".join(results))

###################################################################################################
# main
def main():
  global args
  global dockerBin
  global dockerComposeBin
  global opensslBin

  # extract arguments from the command line
  # print (sys.argv[1:]);
  parser = argparse.ArgumentParser(description='Malcolm control script', add_help=False, usage=f'{ScriptName} <arguments>')
  parser.add_argument('-v', '--verbose', dest='debug', type=str2bool, nargs='?', const=True, default=False, help="Verbose output")
  parser.add_argument('-f', '--file', required=False, dest='composeFile', metavar='<STR>', type=str, default='docker-compose.yml', help='docker-compose YML file')
  parser.add_argument('-l', '--logs', dest='cmdLogs', type=str2bool, nargs='?', const=True, default=False, help="Tail Malcolm logs")
  parser.add_argument('--start', dest='cmdStart', type=str2bool, nargs='?', const=True, default=False, help="Start Malcolm")
  parser.add_argument('--restart', dest='cmdRestart', type=str2bool, nargs='?', const=True, default=False, help="Stop and restart Malcolm")
  parser.add_argument('--stop', dest='cmdStop', type=str2bool, nargs='?', const=True, default=False, help="Stop Malcolm")
  parser.add_argument('--wipe', dest='cmdWipe', type=str2bool, nargs='?', const=True, default=False, help="Stop Malcolm and delete all data")
  parser.add_argument('--auth', dest='cmdAuthSetup', type=str2bool, nargs='?', const=True, default=False, help="Configure Malcolm authentication")
  parser.add_argument('--status', dest='cmdStatus', type=str2bool, nargs='?', const=True, default=False, help="Display status of Malcolm components")

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

  with pushd(MalcolmPath):

    # don't run this as root
    if (pyPlatform != PLATFORM_WINDOWS) and ((os.getuid() == 0) or (os.geteuid() == 0) or (getpass.getuser() == 'root')):
      raise Exception(f'{ScriptName} should not be run as root')

    # make sure docker/docker-compose is available
    dockerBin = 'docker.exe' if ((pyPlatform == PLATFORM_WINDOWS) and Which('docker.exe')) else 'docker'
    dockerComposeBin = 'docker-compose.exe' if ((pyPlatform == PLATFORM_WINDOWS) and Which('docker-compose.exe')) else 'docker-compose'
    err, out = run_process([dockerBin, 'info'], debug=args.debug)
    if (err != 0):
      raise Exception(f'{ScriptName} requires docker, please run install.py')
    err, out = run_process([dockerComposeBin, '-f', args.composeFile, 'version'], debug=args.debug)
    if (err != 0):
      raise Exception(f'{ScriptName} requires docker-compose, please run install.py')

    # identify openssl binary
    opensslBin = 'openssl.exe' if ((pyPlatform == PLATFORM_WINDOWS) and Which('openssl.exe')) else 'openssl'

    # if executed via a symlink, figure out what was intended via the symlink name
    if os.path.islink(os.path.join(ScriptPath, ScriptName)):
      if (ScriptName == "logs"):
        args.cmdLogs = True
      elif (ScriptName == "status"):
        args.cmdStatus = True
      elif (ScriptName == "start"):
        args.cmdStart = True
      elif (ScriptName == "restart"):
        args.cmdRestart = True
      elif (ScriptName == "stop"):
        args.cmdStop = True
      elif (ScriptName == "wipe"):
        args.cmdWipe = True
      elif (ScriptName.startswith("auth")):
        args.cmdAuthSetup = True

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

if __name__ == '__main__':
  main()
  if coloramaImported:
    print(Style.RESET_ALL)

