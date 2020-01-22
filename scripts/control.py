#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (c) 2019 Battelle Energy Alliance, LLC.  All rights reserved.

from __future__ import print_function

import argparse
import errno
import glob
import os
import platform
import re
import shutil
import stat
import sys

from malcolm_common import *

from subprocess import (PIPE, STDOUT, Popen, check_call, CalledProcessError)

###################################################################################################
ScriptName = os.path.basename(__file__)

PY3 = (sys.version_info.major >= 3)
pyPlatform = platform.system()

ansiEscape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')

args = None
dockerCmd = None
dockerComposeCmd = None

###################################################################################################
try:
  FileNotFoundError
except NameError:
  FileNotFoundError = IOError

try:
  from colorama import init as ColoramaInit, Fore, Back, Style
  ColoramaInit()
  coloramaImported = True
except:
  coloramaImported = False

###################################################################################################
def logs():
  global args
  global dockerBin
  global dockerComposeBin

  # noisy logs
  ignoreRegEx = re.compile(r"""
    .+(
        deprecated
      | elastalert-server:\s+Routes:
      | eshealth
      | update_mapping
      | throttling\s+index
      | but\s+there\s+are\s+no\s+living\s+connections
      | saved_objects
      | \b(d|es)?stats\.json
      | /_ns_/nstest\.html
      | esindices/list
      | _cat/indices
      | use_field_mapping
      | reaped\s+unknown\s+pid
      | Successfully\s+handled\s+GET\s+request\s+for\s+'/'
      | GET\s+/(_cat/health|api/status|sessions2-).+HTTP/[\d\.].+\b200\b
      | POST\s+/(d?stats/d?stat|_bulk|fields/field/_search).+HTTP/[\d\.].+\b20[01]\b
      | POST\s+HTTP/[\d\.].+\b200\b
      | POST\s+/server/php/\s+HTTP/\d+\.\d+"\s+\d+\s+\d+.*:8443/
      | curl.+localhost.+GET\s+/api/status\s+200
    )
  """, re.VERBOSE | re.IGNORECASE)

  err, out = run_process([dockerComposeBin, '-f', args.composeFile, 'ps'], debug=args.debug)
  print("\n".join(out))

  process = Popen([dockerComposeBin, '-f', args.composeFile, 'logs', '-f'], stdout=PIPE)
  while True:
    output = process.stdout.readline()
    if (output == '') and process.poll() is not None:
      break
    if output:
      outputStr = output.decode().strip()
      outputStrEscaped = EscapeAnsi(outputStr)
      if not ignoreRegEx.match(outputStrEscaped):
        print(outputStr if coloramaImported else outputStrEscaped)
      else:
        pass
        # print('!!!!!!!: {}'.format(outputStr))
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
    err, out = run_process([dockerComposeBin, '-f', args.composeFile, 'exec', 'moloch', 'bash', '-c', 'curl -fs --output /dev/null -H"Content-Type: application/json" -XDELETE "http://$ES_HOST:$ES_PORT/_template/zeek_template"'], debug=args.debug)

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

    # delete data files (backups, zeek logs, moloch logs, PCAP files, captured PCAP files)
    for dataDir in ['elasticsearch-backup', 'zeek-logs', 'moloch-logs', 'pcap', 'moloch-raw']:
      for root, dirnames, filenames in os.walk(os.path.join(MalcolmPath, dataDir), topdown=True, onerror=None):
        for file in filenames:
          fileSpec = os.path.join(root, file)
          if os.path.isfile(fileSpec) and (not file.startswith('.git')):
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
    check_call(['bash', os.path.join(ScriptPath, 'auth_setup.sh')])

  # still missing? sorry charlie
  if (not MalcolmAuthFilesExist()):
    raise Exception('Malcolm administrator account authentication files are missing, please run ./scripts/auth_setup.sh to generate them')

  # touch the metadata file
  open(os.path.join(MalcolmPath, os.path.join('htadmin', 'metadata')), 'a').close()

  smtpAuthFile = os.path.join(MalcolmPath, os.path.join('elastalert', os.path.join('config', 'smtp-auth.yaml')))
  if (not os.path.isfile(smtpAuthFile)):
    # create a sample smtp-auth.yaml for if/when we want to do elastalert email
    with open(smtpAuthFile, 'w') as f:
      f.write('user: "user@gmail.com"')
      f.write('password: "abcdefg1234567"')
    os.chmod(smtpAuthFile, stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IWGRP)

  # make sure permissions are set correctly for the nginx worker processes
  for authFile in [os.path.join(MalcolmPath, os.path.join('nginx', 'htpasswd')),
                   os.path.join(MalcolmPath, os.path.join('nginx', 'nginx_ldap.conf')),
                   os.path.join(MalcolmPath, os.path.join('htadmin', 'config.ini')),
                   os.path.join(MalcolmPath, os.path.join('htadmin', 'metadata'))]:
    # chmod 644 authFile
    os.chmod(authFile, stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IWGRP | stat.S_IROTH)

  # make sure some directories exist before we start
  for path in [os.path.join(MalcolmPath, 'elasticsearch'),
               os.path.join(MalcolmPath, 'elasticsearch-backup'),
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

  # start docker
  err, out = run_process([dockerComposeBin, '-f', args.composeFile, 'up', '--detach'], debug=args.debug)
  if (err == 0):
    eprint("Started Malcolm\n\n")
    eprint("In a few minutes, Malcolm services will be accessible via the following URLs:")
    eprint("------------------------------------------------------------------------------")
    eprint("  - Moloch: https://localhost/")
    eprint("  - Kibana: https://localhost/kibana/")
    eprint("  - PCAP Upload (web): https://localhost/upload/")
    eprint("  - PCAP Upload (sftp): sftp://username@127.0.0.1:8022/files/")
    eprint("  - Account management: https://localhost:488/\n")
  else:
    eprint("Malcolm failed to start\n")
    eprint("\n".join(out))
    exit(err)

###################################################################################################
# main
def main():
  global args
  global dockerBin
  global dockerComposeBin

  # extract arguments from the command line
  # print (sys.argv[1:]);
  parser = argparse.ArgumentParser(description='Malcolm control script', add_help=False, usage='{} <arguments>'.format(ScriptName))
  parser.add_argument('-v', '--verbose', dest='debug', type=str2bool, nargs='?', const=True, default=False, help="Verbose output")
  parser.add_argument('-f', '--file', required=False, dest='composeFile', metavar='<STR>', type=str, default='docker-compose.yml', help='docker-compose YML file')
  parser.add_argument('-l', '--logs', dest='cmdLogs', type=str2bool, nargs='?', const=True, default=False, help="Tail Malcolm logs")
  parser.add_argument('--start', dest='cmdStart', type=str2bool, nargs='?', const=True, default=False, help="Start Malcolm")
  parser.add_argument('--restart', dest='cmdRestart', type=str2bool, nargs='?', const=True, default=False, help="Stop and restart Malcolm")
  parser.add_argument('--stop', dest='cmdStop', type=str2bool, nargs='?', const=True, default=False, help="Stop Malcolm")
  parser.add_argument('--wipe', dest='cmdWipe', type=str2bool, nargs='?', const=True, default=False, help="Stop Malcolm and delete all data")

  try:
    parser.error = parser.exit
    args = parser.parse_args()
  except SystemExit:
    parser.print_help()
    exit(2)

  if args.debug:
    eprint(os.path.join(ScriptPath, ScriptName))
    eprint("Arguments: {}".format(sys.argv[1:]))
    eprint("Arguments: {}".format(args))
    eprint("Malcolm path:", MalcolmPath)
  else:
    sys.tracebacklimit = 0

  os.chdir(MalcolmPath)

  # make sure docker/docker-compose is available
  dockerBin = 'docker.exe' if ((pyPlatform == PLATFORM_WINDOWS) and Which('docker.exe')) else 'docker'
  dockerComposeBin = 'docker-compose.exe' if ((pyPlatform == PLATFORM_WINDOWS) and Which('docker-compose.exe')) else 'docker-compose'
  err, out = run_process([dockerBin, 'info'], debug=args.debug)
  if (err != 0):
    raise Exception('{} requires docker, please run install.py'.format(ScriptName))
  err, out = run_process([dockerComposeBin, '-f', args.composeFile, 'version'], debug=args.debug)
  if (err != 0):
    raise Exception('{} requires docker-compose, please run install.py'.format(ScriptName))

  # if executed via a symlink, figure out what was intended via the symlink name
  if os.path.islink(os.path.join(ScriptPath, ScriptName)):
    if (ScriptName == "logs"):
      args.cmdLogs = True
    elif (ScriptName == "start"):
      args.cmdStart = True
    elif (ScriptName == "restart"):
      args.cmdRestart = True
    elif (ScriptName == "stop"):
      args.cmdStop = True
    elif (ScriptName == "wipe"):
      args.cmdWipe = True

  # stop Malcolm (and wipe data if requestsed)
  if args.cmdRestart or args.cmdStop or args.cmdWipe:
    stop(wipe=args.cmdWipe)

  # start Malcolm
  if args.cmdStart or args.cmdRestart:
    start()

  # tail Malcolm logs
  if args.cmdStart or args.cmdRestart or args.cmdLogs:
    logs()

if __name__ == '__main__':
  main()
  if coloramaImported:
    print(Style.RESET_ALL)

