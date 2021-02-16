#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2021 Battelle Energy Alliance, LLC.  All rights reserved.

import contextlib
import getpass
import json
import os
import platform
import re
import sys
import time

from collections import defaultdict
try:
  from pwd import getpwuid
except ImportError:
  getpwuid = None
from subprocess import (PIPE, STDOUT, Popen, CalledProcessError)

###################################################################################################
ScriptPath = os.path.dirname(os.path.realpath(__file__))
MalcolmPath = os.path.abspath(os.path.join(ScriptPath, os.pardir))

###################################################################################################

# attempt to import requests, will cover failure later
try:
  import requests
  RequestsImported = True
except ImportError:
  RequestsImported = False

###################################################################################################
PLATFORM_WINDOWS = "Windows"
PLATFORM_MAC = "Darwin"
PLATFORM_LINUX = "Linux"
PLATFORM_LINUX_CENTOS = 'centos'
PLATFORM_LINUX_DEBIAN = 'debian'
PLATFORM_LINUX_FEDORA = 'fedora'
PLATFORM_LINUX_UBUNTU = 'ubuntu'

# URLS for figuring things out if something goes wrong
DOCKER_INSTALL_URLS = defaultdict(lambda: 'https://docs.docker.com/install/')
DOCKER_INSTALL_URLS[PLATFORM_WINDOWS] = ['https://stefanscherer.github.io/how-to-install-docker-the-chocolatey-way/',
                                           'https://docs.docker.com/docker-for-windows/install/']
DOCKER_INSTALL_URLS[PLATFORM_LINUX_UBUNTU] = 'https://docs.docker.com/install/linux/docker-ce/ubuntu/'
DOCKER_INSTALL_URLS[PLATFORM_LINUX_DEBIAN] = 'https://docs.docker.com/install/linux/docker-ce/debian/'
DOCKER_INSTALL_URLS[PLATFORM_LINUX_CENTOS] = 'https://docs.docker.com/install/linux/docker-ce/centos/'
DOCKER_INSTALL_URLS[PLATFORM_LINUX_FEDORA] = 'https://docs.docker.com/install/linux/docker-ce/fedora/'
DOCKER_INSTALL_URLS[PLATFORM_MAC] =  ['https://www.code2bits.com/how-to-install-docker-on-macos-using-homebrew/',
                                        'https://docs.docker.com/docker-for-mac/install/']
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
# get interactive user response to Y/N question
def YesOrNo(question, default=None, forceInteraction=False, acceptDefault=False):

  if default == True:
    questionStr = f"\n{question} (Y/n): "
  elif default == False:
    questionStr = f"\n{question} (y/N): "
  else:
    questionStr = f"\n{question} (y/n): "

  if acceptDefault and (default is not None) and (not forceInteraction):
    reply = ''
  else:
    while True:
      reply = str(input(questionStr)).lower().strip()
      if (len(reply) > 0) or (default is not None):
        break

  if (len(reply) == 0):
    reply = 'y' if default else 'n'

  if reply[0] == 'y':
    return True
  elif reply[0] == 'n':
    return False
  else:
    return YesOrNo(question, default=default)

###################################################################################################
# get interactive user response
def AskForString(question, default=None, forceInteraction=False, acceptDefault=False):

  if acceptDefault and (default is not None) and (not forceInteraction):
    reply = default
  else:
    reply = str(input(f'\n{question}: ')).strip()

  return reply

###################################################################################################
# get interactive password (without echoing)
def AskForPassword(prompt):
  reply = getpass.getpass(prompt=prompt)
  return reply

###################################################################################################
# convenient boolean argument parsing
def str2bool(v):
  if v.lower() in ('yes', 'true', 't', 'y', '1'):
    return True
  elif v.lower() in ('no', 'false', 'f', 'n', '0'):
    return False
  else:
    raise ValueError('Boolean value expected')

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
  for unit in ['','Ki','Mi','Gi','Ti','Pi','Ei','Zi']:
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
def run_process(command, stdout=True, stderr=True, stdin=None, retry=0, retrySleepSec=5, cwd=None, env=None, debug=False):

  retcode = -1
  output = []

  try:
    # run the command
    retcode, cmdout, cmderr = check_output_input(command, input=stdin.encode() if stdin else stdin, cwd=cwd, env=env)

    # split the output on newlines to return a list
    if stderr and (len(cmderr) > 0): output.extend(cmderr.decode(sys.getdefaultencoding()).split('\n'))
    if stdout and (len(cmdout) > 0): output.extend(cmdout.decode(sys.getdefaultencoding()).split('\n'))

  except (FileNotFoundError, OSError, IOError) as e:
    if stderr:
      output.append(f"Command {command} not found or unable to execute")

  if debug:
    eprint(f"{command}({stdin[:80] + bool(stdin[80:]) * '...' if stdin else ''}) returned {retcode}: {output}")

  if (retcode != 0) and retry and (retry > 0):
    # sleep then retry
    time.sleep(retrySleepSec)
    return run_process(command, stdout, stderr, stdin, retry-1, retrySleepSec, cwd, env, debug)
  else:
    return retcode, output

###################################################################################################
# make sure we can import requests properly and take care of it automatically if possible
def ImportRequests(debug=False):
  global RequestsImported

  if not RequestsImported:
    # see if we can help out by installing the requests module

    pyPlatform = platform.system()
    pyExec = sys.executable
    pipCmd = 'pip3'
    if not Which(pipCmd, debug=debug): pipCmd = 'pip'

    eprint(f'The requests module is required under Python {platform.python_version()} ({pyExec})')

    if Which(pipCmd, debug=debug):
      if YesOrNo(f'Importing the requests module failed. Attempt to install via {pipCmd}?'):
        installCmd = None

        if (pyPlatform == PLATFORM_LINUX) or (pyPlatform == PLATFORM_MAC):
          # for linux/mac, we're going to try to figure out if this python is owned by root or the script user
          if (getpass.getuser() == getpwuid(os.stat(pyExec).st_uid).pw_name):
            # we're running a user-owned python, regular pip should work
            installCmd = [pipCmd, 'install', 'requests']
          else:
            # python is owned by system, so make sure to pass the --user flag
            installCmd = [pipCmd, 'install', '--user', 'requests']
        else:
          # on windows (or whatever other platform this is) I don't know any other way other than pip
          installCmd = [pipCmd, 'install', 'requests']

        err, out = run_process(installCmd, debug=debug)
        if err == 0:
          eprint("Installation of requests module apparently succeeded")
          try:
            import requests
            RequestsImported = True
          except ImportError as e:
            eprint(f"Importing the requests module still failed: {e}")
        else:
          eprint(f"Installation of requests module failed: {out}")

  if not RequestsImported:
    eprint("System-wide installation varies by platform and Python configuration. Please consult platform-specific documentation for installing Python modules.")
    if (platform.system() == PLATFORM_MAC):
      eprint('You *may* be able to install pip and requests manually via: sudo sh -c "easy_install pip && pip install requests"')
    elif (pyPlatform == PLATFORM_LINUX):
      if Which('apt-get', debug=debug):
        eprint("You *may* be able to install requests manually via: sudo apt-get install python3-requests")
      elif Which('apt', debug=debug):
        eprint("You *may* be able to install requests manually via: sudo apt install python3-requests")
      elif Which('dnf', debug=debug):
        eprint("You *may* be able to install requests manually via: sudo dnf install python3-requests")
      elif Which('yum', debug=debug):
        eprint("You *may* be able to install requests manually via: sudo yum install python-requests")

  return RequestsImported

###################################################################################################
# do the required auth files for Malcolm exist?
def MalcolmAuthFilesExist():
  return os.path.isfile(os.path.join(MalcolmPath, os.path.join('nginx', 'htpasswd'))) and \
         os.path.isfile(os.path.join(MalcolmPath, os.path.join('nginx', 'nginx_ldap.conf'))) and \
         os.path.isfile(os.path.join(MalcolmPath, os.path.join('nginx', os.path.join('certs', 'cert.pem')))) and \
         os.path.isfile(os.path.join(MalcolmPath, os.path.join('nginx', os.path.join('certs', 'key.pem')))) and \
         os.path.isfile(os.path.join(MalcolmPath, os.path.join('htadmin', 'config.ini'))) and \
         os.path.isfile(os.path.join(MalcolmPath, 'auth.env'))

###################################################################################################
# download to file
def DownloadToFile(url, local_filename, debug=False):
  r = requests.get(url, stream=True, allow_redirects=True)
  with open(local_filename, 'wb') as f:
    for chunk in r.iter_content(chunk_size=1024):
      if chunk: f.write(chunk)
  fExists = os.path.isfile(local_filename)
  fSize = os.path.getsize(local_filename)
  if debug:
    eprint(f"Download of {url} to {local_filename} {'succeeded' if fExists else 'failed'} ({SizeHumanFormat(fSize)})")
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