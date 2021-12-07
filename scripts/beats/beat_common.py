#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (c) 2022 Battelle Energy Alliance, LLC.  All rights reserved.

from __future__ import print_function

import getpass
import inspect
import os
import platform
import re
import sys
import time

from collections import defaultdict

from subprocess import (PIPE, STDOUT, Popen, CalledProcessError)

###################################################################################################
ScriptPath = os.path.dirname(os.path.realpath(__file__))

###################################################################################################
# python 2/3 portability
PY3 = (sys.version_info.major >= 3)

# bind raw_input to input in older versions of python
try:
  input = raw_input
except NameError:
  pass

try:
  FileNotFoundError
except NameError:
  FileNotFoundError = IOError

###################################################################################################
PLATFORM_WINDOWS = "Windows"
PLATFORM_MAC = "Darwin"
PLATFORM_LINUX = "Linux"
PLATFORM_LINUX_CENTOS = 'centos'
PLATFORM_LINUX_DEBIAN = 'debian'
PLATFORM_LINUX_FEDORA = 'fedora'
PLATFORM_LINUX_UBUNTU = 'ubuntu'

OPERATION_RUN = 'run'
OPERATION_CONFIGURE = 'config'

BEAT_OS_HOST = "BEAT_OS_HOST"
BEAT_OS_PROTOCOL = "BEAT_OS_PROTOCOL"
BEAT_OS_SSL_VERIFY = "BEAT_OS_SSL_VERIFY"
BEAT_HTTP_PASSWORD = "BEAT_HTTP_PASSWORD"
BEAT_HTTP_USERNAME = "BEAT_HTTP_USERNAME"
BEAT_DASHBOARDS_ENABLED = "BEAT_DASHBOARDS_ENABLED"
BEAT_DASHBOARDS_PATH = "BEAT_DASHBOARDS_PATH"
BEAT_DASHBOARDS_HOST = "BEAT_DASHBOARDS_HOST"
BEAT_DASHBOARDS_PROTOCOL = "BEAT_DASHBOARDS_PROTOCOL"
BEAT_DASHBOARDS_SSL_VERIFY = "BEAT_DASHBOARDS_SSL_VERIFY"

BEAT_YML_TEMPLATE = """
#================================ General ======================================
fields_under_root: true

#================================ Outputs ======================================

#-------------------------- Elasticsearch output -------------------------------
output.elasticsearch:
  enabled: true
  hosts: ["${BEAT_OS_HOST}"]
  protocol: "${BEAT_OS_PROTOCOL}"
  username: "${BEAT_HTTP_USERNAME}"
  password: "${BEAT_HTTP_PASSWORD}"
  ssl.verification_mode: "${BEAT_OS_SSL_VERIFY}"

setup.template.enabled: true
setup.template.overwrite: false
setup.template.settings:
  index.number_of_shards: 1
  index.number_of_replicas: 0

#============================== Dashboards =====================================
# setup.dashboards.enabled: "${BEAT_DASHBOARDS_ENABLED}"
# "setup.dashboards.enabled: false" now because Beats won't import dashboards
# into OpenSearch dashboards (see opensearch-project/OpenSearch-Dashboards#656
# and opensearch-project/OpenSearch-Dashboards#831). setup.template.enabled
# seems to be okay, however.
setup.dashboards.enabled: false
setup.dashboards.directory: "${BEAT_DASHBOARDS_PATH}"

#============================== Kibana =====================================
setup.kibana:
  host: "${BEAT_DASHBOARDS_HOST}"
  protocol: "${BEAT_DASHBOARDS_PROTOCOL}"
  username: "${BEAT_HTTP_USERNAME}"
  password: "${BEAT_HTTP_PASSWORD}"
  ssl.verification_mode: "${BEAT_DASHBOARDS_SSL_VERIFY}"

#================================ Logging ======================================
logging.metrics.enabled: false
"""

###################################################################################################
# print to stderr
def eprint(*args, **kwargs):
  print(*args, file=sys.stderr, **kwargs)

###################################################################################################
# get interactive user response to Y/N question
def YesOrNo(question, default=None, forceInteraction=False, acceptDefault=False):

  if default == True:
    questionStr = "\n{} (Y/n): ".format(question)
  elif default == False:
    questionStr = "\n{} (y/N): ".format(question)
  else:
    questionStr = "\n{} (y/n): ".format(question)

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
    reply = str(input('\n{}: '.format(question))).strip()

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
  if (not result) and (platform.system() == PLATFORM_WINDOWS):
    result = os.access(os.path.join(os.getcwd(), cmd), os.X_OK)
  if debug:
    eprint("Which {} returned {}".format(cmd, result))
  return result

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
    retcode, cmdout, cmderr = check_output_input(command, input=stdin.encode() if (PY3 and stdin) else stdin, cwd=cwd, env=env)

    # split the output on newlines to return a list
    if PY3:
      if stderr and (len(cmderr) > 0): output.extend(cmderr.decode(sys.getdefaultencoding()).split('\n'))
      if stdout and (len(cmdout) > 0): output.extend(cmdout.decode(sys.getdefaultencoding()).split('\n'))
    else:
      if stderr and (len(cmderr) > 0): output.extend(cmderr.split('\n'))
      if stdout and (len(cmdout) > 0): output.extend(cmdout.split('\n'))

  except (FileNotFoundError, OSError, IOError) as e:
    if stderr:
      output.append("Command {} not found or unable to execute".format(command))

  if debug:
    eprint("{}{} returned {}: {}".format(command, "({})".format(stdin[:80] + bool(stdin[80:]) * '...' if stdin else ""), retcode, output))

  if (retcode != 0) and retry and (retry > 0):
    # sleep then retry
    time.sleep(retrySleepSec)
    return run_process(command, stdout, stderr, stdin, retry-1, retrySleepSec, cwd, env, debug)
  else:
    return retcode, output

###################################################################################################
class Beatbox(object):

  #~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  def __init__(self, debug=False, ymlFileSpec=None, beatName=None, acceptDefaults=False):
    self.debug = debug
    self.acceptDefaults = acceptDefaults
    self.platform = platform.system()
    self.ymlFileSpec = ymlFileSpec
    self.ymlFilePath = os.path.dirname(ymlFileSpec)
    self.beatName = beatName
    self.beatExe = beatName
    self.beatInstallDir = None
    self.defaultKibanaDashboardDir = None
    self.keystoreItems = defaultdict(str)
    for initItem in [BEAT_OS_HOST,
                     BEAT_OS_PROTOCOL,
                     BEAT_OS_SSL_VERIFY,
                     BEAT_HTTP_PASSWORD,
                     BEAT_HTTP_USERNAME,
                     BEAT_DASHBOARDS_ENABLED,
                     BEAT_DASHBOARDS_PATH,
                     BEAT_DASHBOARDS_HOST,
                     BEAT_DASHBOARDS_PROTOCOL,
                     BEAT_DASHBOARDS_SSL_VERIFY]:
      self.keystoreItems[initItem] = ''
      self.keystorePath = None

  #~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  def __del__(self):
    # nothing for now
    pass

  #~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  def run_process(self, command, stdout=True, stderr=True, stdin=None, retry=0, retrySleepSec=5):
    return run_process(command, stdout=stdout, stderr=stderr, stdin=stdin, retry=retry, retrySleepSec=retrySleepSec, debug=self.debug)

  #~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  def build_beat_command(self, command):
    if not Which(self.beatExe, debug=self.debug):
      raise Exception("Beat executable {} does not exist".format(self.beatExe))

    if not os.path.isfile(self.ymlFileSpec):
      raise Exception("Beat configuration {} does not exist".format(self.ymlFileSpec))

    # convert paths to absolutes
    ymlFileSpec = os.path.abspath(self.ymlFileSpec)
    ymlFilePath = os.path.dirname(ymlFileSpec)

    beatCmd = [self.beatExe, '--path.home', ymlFilePath, '--path.config', ymlFilePath, '--path.data', ymlFilePath if (self.platform == PLATFORM_WINDOWS) else os.path.join(ymlFilePath, 'data'), '--path.logs', os.path.join(ymlFilePath, 'logs'), '-c', ymlFileSpec, '-E', "keystore.path='{}'".format(self.keystorePath)]

    return beatCmd + command if isinstance(command, list) else beatCmd + [ command ]

  #~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  def run_beat_command(self, command, stdout=True, stderr=True, stdin=None, retry=0, retrySleepSec=5):
    return self.run_process(self.build_beat_command(command), stdout=stdout, stderr=stderr, stdin=stdin, retry=retry, retrySleepSec=retrySleepSec)

  #~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  def configure_beat_yml(self):
    if self.debug:
      eprint("{}: {}".format(self.__class__.__name__, inspect.currentframe().f_code.co_name))

    if (self.ymlFileSpec is not None):

      if os.path.isfile(self.ymlFileSpec):
        # if it doesn't look like connectivity stuff (at last BEAT_OS_PROTOCOL) is in the YML file, offer to append it
        if ((len(list(filter(lambda x: BEAT_OS_PROTOCOL in x, [line.rstrip('\n') for line in open(self.ymlFileSpec)]))) == 0) and
            YesOrNo("Append connectivity boilerplate to {}?".format(self.ymlFileSpec), default=False, acceptDefault=self.acceptDefaults)):
          with open(self.ymlFileSpec, 'a') as ymlFile:
            ymlFile.write(BEAT_YML_TEMPLATE)

      else:
        # generate a boilerplate spec file (output configured, no modules) if the YML file doesn't exist
        with open(self.ymlFileSpec, 'w') as ymlFile:
          ymlFile.write(BEAT_YML_TEMPLATE)

  #~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  def configure_keystore(self):
    if self.debug:
      eprint("{}: {}".format(self.__class__.__name__, inspect.currentframe().f_code.co_name))

    # check if keystore already exists
    err, out = self.run_beat_command(['keystore', 'list'])
    if (err == 0) and (len(out) > 0):
      if not YesOrNo("{} keystore already exists, overwrite?".format(self.beatName), default=False, acceptDefault=self.acceptDefaults):
        raise Exception("Configuration cancelled by user")

    # create keystore
    err, out = self.run_beat_command(['keystore', 'create', '--force'])
    if (err == 0):
      eprint('\n'.join(out))
    else:
      raise Exception("Keystore creation failed: {}".format(out))

    # prompt for and store configuration items
    for destination in ['Elasticsearch', 'Kibana']:

      if YesOrNo("Configure {} {} connectivity?".format(self.beatName, destination), default=True, acceptDefault=self.acceptDefaults):

        # protocol
        tmpVal, tmpDefault = '', 'https'
        while tmpVal not in ['http', 'https']:
          tmpVal = AskForString("Enter {} connection protocol (http or https) [{}]".format(destination, tmpDefault), default=tmpDefault, acceptDefault=self.acceptDefaults).lower()
          if (len(tmpVal) == 0): tmpVal = tmpDefault
        self.keystoreItems[BEAT_OS_PROTOCOL.replace('_OS_', '_KIBANA_' if (destination == 'Kibana') else '_OS_')] = tmpVal

        # SSL verification
        tmpVal, tmpDefault = '', 'none'
        while tmpVal not in ['none', 'full']:
          tmpVal = AskForString("Enter {} SSL verification (none (for self-signed certificates) or full) [{}]".format(destination, tmpDefault), default=tmpDefault, acceptDefault=self.acceptDefaults).lower()
          if (len(tmpVal) == 0): tmpVal = tmpDefault
        self.keystoreItems[BEAT_OS_SSL_VERIFY.replace('_OS_', '_KIBANA_' if (destination == 'Kibana') else '_OS_')] = tmpVal

        # host
        tmpVal, tmpDefault = '', ''
        while (len(tmpVal) == 0):
          tmpVal = AskForString("Enter {} connection host".format(destination), default=tmpDefault, acceptDefault=self.acceptDefaults)
        self.keystoreItems[BEAT_OS_HOST.replace('_OS_', '_KIBANA_' if (destination == 'Kibana') else '_OS_')] = tmpVal

    if (BEAT_DASHBOARDS_HOST in self.keystoreItems):

      #  configure kibana dashboards
      if YesOrNo("Configure {} Kibana dashboards?".format(self.beatName), default=True, acceptDefault=self.acceptDefaults):
        self.keystoreItems[BEAT_DASHBOARDS_ENABLED] = 'true'

        # kibana dashboards
        tmpVal, tmpDefault = '', self.defaultKibanaDashboardDir
        while (len(tmpVal) == 0):
          tmpVal = AskForString("Enter directory containing Kibana dashboards [{}]".format(tmpDefault), default=tmpDefault, acceptDefault=self.acceptDefaults)
          if (len(tmpVal) == 0): tmpVal = tmpDefault
        self.keystoreItems[BEAT_DASHBOARDS_PATH] = tmpVal

    # username
    tmpVal, tmpDefault = '', ''
    while (len(tmpVal) == 0):
      tmpVal = AskForString("Enter HTTP/HTTPS server username", default=tmpDefault, acceptDefault=self.acceptDefaults)
    self.keystoreItems[BEAT_HTTP_USERNAME] = tmpVal

    # password
    tmpVal, tmpValConfirm = '', 'xxxx'
    while (len(tmpVal) == 0) and (tmpVal != tmpValConfirm):
      tmpVal = AskForPassword("Enter password for {}: ".format(self.keystoreItems[BEAT_HTTP_USERNAME]))
      tmpValConfirm = AskForPassword("Enter password for {} (again): ".format(self.keystoreItems[BEAT_HTTP_USERNAME]))
      if (tmpVal != tmpValConfirm):
        eprint('Passwords do not match')
        tmpVal, tmpValConfirm = '', 'xxxx'
    self.keystoreItems[BEAT_HTTP_PASSWORD] = tmpVal

    # write values to keystore
    for key, value in self.keystoreItems.items():
      err, out = self.run_beat_command(['keystore', 'add', key, '--stdin', '--force'], stdin=value)
      if (err != 0):
        raise Exception("Failed to add {} to {} keystore: {}".format(key, self.beatName, out))

    # list keystore
    err, out = self.run_beat_command(['keystore', 'list'])
    if (err == 0):
      eprint('Generated keystore for {}'.format(self.beatName))
      eprint('\n'.join(out))
    else:
      raise Exception("Failed to enumerate keystore: {}".format(out))

  #~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  def beat_run(self):
    if self.debug:
      eprint("{}: {}".format(self.__class__.__name__, inspect.currentframe().f_code.co_name))

    process = Popen(self.build_beat_command(['run', '-e']), stdout=PIPE)
    while True:
      output = process.stdout.readline()
      if (len(output) == 0) and (process.poll() is not None):
        break
      if output:
        print(output.decode().strip())
      else:
        time.sleep(0.5)
    process.poll()

###################################################################################################
class LinuxBeatbox(Beatbox):

  #~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  def __init__(self, debug=False, ymlFileSpec=None, beatName=None):
    if PY3:
      super().__init__(debug=debug, ymlFileSpec=ymlFileSpec, beatName=beatName)
    else:
      super(LinuxBeatbox, self).__init__(debug=debug, ymlFileSpec=ymlFileSpec, beatName=beatName)

    if not Which(self.beatExe, debug=self.debug):
      self.beatExe = self.beatExe.lower() if (self.beatExe is not None) else self.beatName.lower()

    self.beatInstallDir = "/usr/share/{}".format(self.beatName)
    self.defaultKibanaDashboardDir = os.path.join(self.beatInstallDir, 'kibana')
    self.keystorePath = os.path.join(os.path.join(os.path.dirname(os.path.abspath(self.ymlFileSpec)), 'data'), "{}.keystore".format(self.beatName))

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
          except:
            pass

      if ('NAME' in osInfo) and (len(osInfo['NAME']) > 0):
        distro = osInfo['NAME'].lower().split()[0]

      if ('VERSION_CODENAME' in osInfo) and (len(osInfo['VERSION_CODENAME']) > 0):
        codename = osInfo['VERSION_CODENAME'].lower().split()[0]

      if ('VERSION_ID' in osInfo) and (len(osInfo['VERSION_ID']) > 0):
        release = osInfo['VERSION_ID'].lower().split()[0]

    # try lsb_release next
    if (self.distro is None):
      err, out = self.run_process(['lsb_release', '-is'], stderr=False)
      if (err == 0) and (len(out) > 0):
        self.distro = out[0].lower()

    if (self.codename is None):
      err, out = self.run_process(['lsb_release', '-cs'], stderr=False)
      if (err == 0) and (len(out) > 0):
        self.codename = out[0].lower()

    if (self.release is None):
      err, out = self.run_process(['lsb_release', '-rs'], stderr=False)
      if (err == 0) and (len(out) > 0):
        self.release = out[0].lower()

    # try release-specific files
    if (self.distro is None):
      if os.path.isfile('/etc/centos-release'):
        distroFile = '/etc/centos-release'
      if os.path.isfile('/etc/redhat-release'):
        distroFile = '/etc/redhat-release'
      elif os.path.isfile('/etc/issue'):
        distroFile = '/etc/issue'
      else:
        distroFile = None
      if (distroFile is not None):
        with open(distroFile, 'r') as f:
          distroVals = f.read().lower().split()
          distroNums = [x for x in distroVals if x[0].isdigit()]
          self.distro = distroVals[0]
          if (self.release is None) and (len(distroNums) > 0):
            self.release = distroNums[0]

    if (self.distro is None):
      self.distro = "linux"

    if self.debug:
      eprint("distro: {}{}{}".format(self.distro,
                                     " {}".format(self.codename) if self.codename else "",
                                     " {}".format(self.release) if self.release else ""))

    if not self.codename: self.codename = self.distro

  #~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  def configure_beat_yml(self):
    if PY3:
      super().configure_beat_yml()
    else:
      super(LinuxBeatbox, self).configure_beat_yml()

    localModulePath = os.path.join(os.path.abspath(self.ymlFilePath), 'module')
    installedModulePath = os.path.join(self.beatInstallDir, 'module')
    if ((not os.path.exists(localModulePath)) and
        (os.path.isdir(installedModulePath)) and
        YesOrNo("Create symlink to module path {} as {}?".format(installedModulePath, localModulePath), default=True, acceptDefault=self.acceptDefaults)):
      os.symlink(installedModulePath, localModulePath)

  #~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  def configure_keystore(self):
    if PY3:
      super().configure_keystore()
    else:
      super(LinuxBeatbox, self).configure_keystore()

    pass

  #~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  def beat_run(self):
    if PY3:
      super().beat_run()
    else:
      super(LinuxBeatbox, self).beat_run()

    pass

###################################################################################################
class WindowsBeatbox(Beatbox):

  #~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  def __init__(self, debug=False, ymlFileSpec=None, beatName=None):
    if PY3:
      super().__init__(debug=debug, ymlFileSpec=ymlFileSpec, beatName=beatName)
    else:
      super(WindowsBeatbox, self).__init__(debug=debug, ymlFileSpec=ymlFileSpec, beatName=beatName)

    if not Which(self.beatExe, debug=self.debug):
      self.beatExe = self.beatExe + '.exe' if (self.beatExe is not None) else self.beatName + '.exe'

    self.beatInstallDir = os.path.abspath(self.ymlFilePath)
    self.defaultKibanaDashboardDir = os.path.join(self.beatInstallDir, 'kibana')
    self.keystorePath = os.path.join(os.path.dirname(os.path.abspath(self.ymlFileSpec)), "{}.keystore".format(self.beatName))

  #~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  def configure_beat_yml(self):
    if PY3:
      super().configure_beat_yml()
    else:
      super(WindowsBeatbox, self).configure_beat_yml()

    pass

  #~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  def configure_keystore(self):
    if PY3:
      super().configure_keystore()
    else:
      super(WindowsBeatbox, self).configure_keystore()

    pass

  #~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  def beat_run(self):
    if PY3:
      super().beat_run()
    else:
      super(WindowsBeatbox, self).beat_run()

    pass

###################################################################################################
class MacBeatbox(Beatbox):

  #~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  def __init__(self, debug=False, ymlFileSpec=None, beatName=None):
    if PY3:
      super().__init__(debug=debug, ymlFileSpec=ymlFileSpec, beatName=beatName)
    else:
      super(MacBeatbox, self).__init__(debug=debug, ymlFileSpec=ymlFileSpec, beatName=beatName)

    if not Which(self.beatExe, debug=self.debug):
      self.beatExe = self.beatExe.lower() if (self.beatExe is not None) else self.beatName.lower()

    self.beatInstallDir = "/Library/Application Support/elastic/{}".format(self.beatName)
    self.defaultKibanaDashboardDir = os.path.join(self.beatInstallDir, 'kibana')
    self.keystorePath = os.path.join(os.path.join(os.path.dirname(os.path.abspath(self.ymlFileSpec)), 'data'), "{}.keystore".format(self.beatName))

  #~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  def configure_beat_yml(self):
    if PY3:
      super().configure_beat_yml()
    else:
      super(MacBeatbox, self).configure_beat_yml()

    localModulePath = os.path.join(os.path.abspath(self.ymlFilePath), 'module')
    installedModulePath = os.path.join(self.beatInstallDir, 'module')
    if ((not os.path.exists(localModulePath)) and
        (os.path.isdir(installedModulePath)) and
        YesOrNo("Create symlink to module path {} as {}?".format(installedModulePath, localModulePath), default=True, acceptDefault=self.acceptDefaults)):
      os.symlink(installedModulePath, localModulePath)

  #~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  def configure_keystore(self):
    if PY3:
      super().configure_keystore()
    else:
      super(MacBeatbox, self).configure_keystore()

    pass

  #~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  def beat_run(self):
    if PY3:
      super().beat_run()
    else:
      super(MacBeatbox, self).beat_run()

    pass