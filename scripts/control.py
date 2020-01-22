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
from collections import defaultdict, namedtuple
from subprocess import (PIPE, STDOUT, Popen, check_call, CalledProcessError)

###################################################################################################
ScriptName = os.path.basename(__file__)

PY3 = (sys.version_info.major >= 3)
pyPlatform = platform.system()

ansiEscape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')

args = None
dockerBin = None
dockerComposeBin = None

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
    check_call(['bash', os.path.join(ScriptPath, 'auth_setup')])

  # still missing? sorry charlie
  if (not MalcolmAuthFilesExist()):
    raise Exception('Malcolm administrator account authentication files are missing, please run ./scripts/auth_setup to generate them')

  # touch the metadata file
  open(os.path.join(MalcolmPath, os.path.join('htadmin', 'metadata')), 'a').close()

  smtpAuthFile = os.path.join(MalcolmPath, os.path.join('elastalert', os.path.join('config', 'smtp-auth.yaml')))
  if (not os.path.isfile(smtpAuthFile)):
    # create a sample smtp-auth.yaml for if/when we want to do elastalert email
    with open(smtpAuthFile, 'w') as f:
      f.write('user: "user@gmail.com"\n')
      f.write('password: "abcdefg1234567"\n')
    os.chmod(smtpAuthFile, stat.S_IRUSR | stat.S_IWUSR)

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
def authSetup(wipe=False):
  global args
  global dockerBin
  global dockerComposeBin

  # prompt usernamd and password
  usernamePrevious = None
  password = None
  passwordConfirm = None
  passwordEncrypted = ''
  username = AskForString("Administrator username")

  while True:
    password = AskForPassword("{} password: ".format(username))
    passwordConfirm = AskForPassword("{} password (again): ".format(username))
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
  err, out = run_process(['openssl', 'passwd', '-1', '-stdin'], stdin=password, stderr=False, debug=args.debug)
  if (err == 0) and (len(out) > 0) and (len(out[0]) > 0):
    passwordEncrypted = out[0]
  else:
    raise Exception('Unable to generate password hash with openssl')

  # write auth.env (used by htadmin and file-upload containers)
  with open(authEnvFile, 'w') as f:
    f.write("# Malcolm Administrator username and encrypted password for nginx reverse proxy (and upload server's SFTP access)\n")
    f.write('MALCOLM_USERNAME={}\n'.format(username))
    f.write('MALCOLM_PASSWORD={}\n'.format(passwordEncrypted))
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
    raise Exception('Unable to generate htpasswd file: {}'.format(out))

  # if the admininstrator username has changed, remove the previous administrator username from htpasswd
  if (usernamePrevious is not None) and (usernamePrevious != username):
    htpasswdLines = list()
    with open(htpasswdFile, 'r') as f:
      htpasswdLines = f.readlines()
    with open(htpasswdFile, 'w') as f:
      for line in htpasswdLines:
        if not line.startswith("{}:".format(usernamePrevious)):
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
            ldapDefaults[k] = v.strip('"')
          except:
            pass
    ldapProto = ldapDefaults.get("LDAP_PROTO", "ldap://")
    ldapHost = ldapDefaults.get("LDAP_HOST", "ds.example.com")
    ldapPort = ldapDefaults.get("LDAP_PORT", "3268")
    ldapType = ldapDefaults.get("LDAP_SERVER_TYPE", "winldap")
    if (ldapType == "openldap"):
      ldapUri = 'DC=example,DC=com?uid?sub?(objectClass=posixAccount)'
      ldapGroupAttr = "memberuid"
    else:
      ldapUri = 'DC=example,DC=com?sAMAccountName?sub?(objectClass=person)'
      ldapGroupAttr = "member"
    with open(ldapConfFile, 'w') as f:
      f.write('# This is a sample configuration for the ldap_server section of nginx.conf.\n')
      f.write('# Yours will vary depending on how your Active Directory/LDAP server is configured.\n')
      f.write('# See https://github.com/kvspb/nginx-auth-ldap#available-config-parameters for options.\n\n')
      f.write('ldap_server ad_server {\n')
      f.write('  url "{}{}:{}/{}";\n\n'.format(ldapProto, ldapHost, ldapPort, ldapUri))
      f.write('  binddn "bind_dn";\n')
      f.write('  binddn_passwd "bind_dn_password";\n\n')
      f.write('  group_attribute {};\n'.format(ldapGroupAttr))
      f.write('  group_attribute_is_dn on;\n')
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
    f.write('admin_user = {}\n\n'.format(username))
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

  # create a sample smtp-auth.yaml for if/when we want to do elastalert email
  smtpAuthFile = os.path.join(MalcolmPath, os.path.join('elastalert', os.path.join('config', 'smtp-auth.yaml')))
  if not os.path.isfile(smtpAuthFile):
    with open(smtpAuthFile, 'w') as f:
      f.write('user: "user@gmail.com"\n')
      f.write('password: "abcdefg1234567"\n')
    os.chmod(smtpAuthFile, stat.S_IRUSR | stat.S_IWUSR)

  # generate HTTPS self-signed certificates
  if YesOrNo('(Re)generate self-signed certificates for HTTPS access', default=True):
    os.chdir(os.path.join(MalcolmPath, os.path.join('nginx', 'certs')))
    try:

      # remove previous files
      for oldfile in glob.glob("*.pem"):
        os.remove(oldfile)

      # generate dhparam
      err, out = run_process(['openssl', 'dhparam', '-out', 'dhparam.pem', '2048'], stderr=True, debug=args.debug)
      if (err != 0):
        raise Exception('Unable to generate dhparam.pem file: {}'.format(out))

      # generate key/cert
      err, out = run_process(['openssl', 'req', '-subj', '/CN=localhost', '-x509', '-newkey', 'rsa:4096', '-nodes', '-keyout', 'key.pem', '-out', 'cert.pem', '-days', '3650'], stderr=True, debug=args.debug)
      if (err != 0):
        raise Exception('Unable to generate key.pem/cert.pem file(s): {}'.format(out))

    finally:
      os.chdir(MalcolmPath)

  # generate beats/logstash self-signed certificates
  logstashPath = os.path.join(MalcolmPath, os.path.join('logstash', 'certs'))
  filebeatPath = os.path.join(MalcolmPath, os.path.join('filebeat', 'certs'))
  if YesOrNo('(Re)generate self-signed certificates for a remote log forwarder', default=True):
    os.chdir(logstashPath)
    try:

      # make clean to clean previous files
      err, out = run_process(['make', 'clean'], stderr=True, debug=args.debug)
      if (err != 0):
        raise Exception('Unable to generate clean remote log forwarder certificates: {}'.format(out))

      # make to generate new files
      err, out = run_process(['make'], stderr=True, debug=args.debug)
      if (err != 0):
        raise Exception('Unable to generate remote log forwarder certificates: {}'.format(out))

      # generate filebeat/certs if it doesn't exist
      try:
        os.makedirs(filebeatPath)
      except OSError as exc:
        if (exc.errno == errno.EEXIST) and os.path.isdir(filebeatPath):
          pass
        else:
          raise

      # remove any leftover files in filebeat/certs
      for oldfile in glob.glob(os.path.join(filebeatPath, "*")):
        os.remove(oldfile)

      # copy the ca so logstasn and filebeat both have it
      shutil.copy2(os.path.join(logstashPath, "ca.crt"), filebeatPath)

      # move the client certs for filebeat
      for f in ['client.key', 'client.crt']:
        shutil.move(os.path.join(logstashPath, f), filebeatPath)

      # remove leftovers
      for pat in ['*.srl', '*.csr', '*.pem']:
        for f in glob.glob(pat):
          os.remove(f)

    finally:
      os.chdir(MalcolmPath)

  # create and populate keystore for remote
  if YesOrNo('Store username/password for forwarding Logstash events to a secondary, external Elasticsearch instance', default=True):

    # prompt usernamd and password
    esPassword = None
    esPasswordConfirm = None
    esUsername = AskForString("External Elasticsearch username")

    while True:
      esPassword = AskForPassword("{} password: ".format(esUsername))
      esPasswordConfirm = AskForPassword("{} password (again): ".format(esUsername))
      if (esPassword == esPasswordConfirm):
        break
      eprint("Passwords do not match")

    # use the logstash image to run set_es_external_keystore to generate the keystore

    logstashImage = None
    composeFileLines = list()
    with open(args.composeFile, 'r') as f:
      composeFileLines = [x for x in f.readlines() if 'image: malcolmnetsec/logstash' in x]
    if (len(composeFileLines) > 0) and (len(composeFileLines[0]) > 0):
      imageLineValues = composeFileLines[0].split()
      if (len(imageLineValues) > 1):
        logstashImage = imageLineValues[1]

    if logstashImage is not None:
      os.chdir(logstashPath)
      try:
        if os.path.isfile('logstash.keystore'):
          os.remove('logstash.keystore')

        dockerCmd = [dockerBin,
                     'run',
                     '--rm',
                     '--entrypoint',
                     '/bin/bash',
                     '-v', '{}:/usr/share/logstash/config:rw'.format(logstashPath),
                     '-w', '/usr/share/logstash/config',
                     '-u', 'logstash',
                     '-e', 'EXT_USERNAME={}'.format(esUsername),
                     '-e', 'EXT_PASSWORD={}'.format(esPassword),
                     logstashImage,
                     '/usr/local/bin/set_es_external_keystore.sh']

        err, out = run_process(dockerCmd, stderr=True, debug=args.debug)
        if (err != 0) or not os.path.isfile('logstash.keystore'):
          raise Exception('Unable to generate logstash keystore: {}'.format(out))

      finally:
        os.chdir(MalcolmPath)
    else:
      raise Exception('Failed to determine logstash image from {}'.format(args.composeFile))


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
  parser.add_argument('--auth', dest='cmdAuthSetup', type=str2bool, nargs='?', const=True, default=False, help="Configure Malcolm authentication")

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

  if not os.path.isabs(args.composeFile):
    args.composeFile = os.path.join(MalcolmPath, args.composeFile)

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

if __name__ == '__main__':
  main()
  if coloramaImported:
    print(Style.RESET_ALL)

