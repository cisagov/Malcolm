#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2019 Battelle Energy Alliance, LLC.  All rights reserved.

import sys
import os
import re
import shutil
import subprocess
import time
import tempfile
import tarfile

ZEEK_EXTRACTOR_MODE_ENV_VAR = 'ZEEK_EXTRACTOR_MODE'
ZEEK_EXTRACTOR_MODE_INTERESTING = 'interesting'
ZEEK_EXTRACTOR_MODE_MAPPED = 'mapped'
ZEEK_EXTRACTOR_MODE_NONE = 'none'
ZEEK_EXTRACTOR_SCRIPT = "extractor.zeek"
ZEEK_EXTRACTOR_SCRIPT_INTERESTING = "extractor_override.interesting.zeek"
ZEEK_LOCAL_SCRIPT = 'local'
ZEEK_STATE_DIR = '.state'
ZEEK_UPLOAD_DIR_DEFAULT = '/data/zeek/upload'
ZEEK_UPLOAD_DIR_ENV_VAR = 'ZEEK_UPLOAD_DIR'
ZEEK_INSTALL_DIR_ENV_VAR = 'ZEEK_DIR'
ZEEK_AUTOZEEK_TAG = 'AUTOZEEK'
ZEEK_AUTOCARVE_TAG_PREFIX = 'AUTOCARVE'

###################################################################################################
# print to stderr
def eprint(*args, **kwargs):
  print(*args, file=sys.stderr, **kwargs)

###################################################################################################
# main
def main():
  errCode = os.EX_SOFTWARE

  if (len(sys.argv) >= 2):
    processTimeUsec = int(round(time.time() * 1000000))
    uploadDir = os.getenv(ZEEK_UPLOAD_DIR_ENV_VAR, ZEEK_UPLOAD_DIR_DEFAULT)
    extractFileMode = os.getenv(ZEEK_EXTRACTOR_MODE_ENV_VAR, ZEEK_EXTRACTOR_MODE_NONE)
    pcapFile = os.path.realpath(sys.argv[1])
    tags = list(sorted(set(sys.argv[2:])))

    # if autozeek was specified as a tag, remove it now as we no longer need it
    if (ZEEK_AUTOZEEK_TAG in tags):
      tags.remove(ZEEK_AUTOZEEK_TAG)

    # if file carving was specified via tag, make note of it (updating the environment
    # variable) and remove it from the list of tags
    for autocarveTag in filter(lambda x: x.startswith(ZEEK_AUTOCARVE_TAG_PREFIX), tags):
      tags.remove(autocarveTag)
      extractFileMode = autocarveTag[len(ZEEK_AUTOCARVE_TAG_PREFIX):]
    os.environ[ZEEK_EXTRACTOR_MODE_ENV_VAR] = extractFileMode

    # create an chdir to a temporary work directory
    with tempfile.TemporaryDirectory() as tmpLogDir:
      if (os.path.isdir(uploadDir) and
          os.path.isdir(tmpLogDir) and
          os.path.isfile(pcapFile)):
        os.chdir(tmpLogDir)

        # use Zeek to process the pcap
        broCmd = [os.path.join(os.getenv(ZEEK_INSTALL_DIR_ENV_VAR, "/opt/zeek"), "bin/zeek"), "-r", pcapFile, ZEEK_LOCAL_SCRIPT]

        # set file extraction parameters if required
        if (extractFileMode != ZEEK_EXTRACTOR_MODE_NONE):
          broCmd.append(ZEEK_EXTRACTOR_SCRIPT)
          if (extractFileMode == ZEEK_EXTRACTOR_MODE_INTERESTING):
            broCmd.append(ZEEK_EXTRACTOR_SCRIPT_INTERESTING)
            os.environ[ZEEK_EXTRACTOR_MODE_ENV_VAR] = ZEEK_EXTRACTOR_MODE_MAPPED

        # execute zeek
        try:
          output = subprocess.check_output(broCmd, stderr=subprocess.STDOUT, universal_newlines=True)
        except Exception as e:
          output = []

        # clean up the .state directory we don't care to keep
        if os.path.isdir(ZEEK_STATE_DIR): shutil.rmtree(ZEEK_STATE_DIR)

        # make sure log files were generated
        logFiles = [logFile for logFile in os.listdir(tmpLogDir) if logFile.endswith('.log')]
        if (len(logFiles) > 0):

          # tar up the results
          tgzFileName = "{}-{}-{}.tar.gz".format(os.path.basename(pcapFile), '_'.join(tags), processTimeUsec)
          with tarfile.open(tgzFileName, "w:gz") as tar:
            tar.add(tmpLogDir, arcname=os.path.basename('.'))

          # relocate the tarball to the upload directory
          shutil.move(tgzFileName, uploadDir)
          errCode = os.EX_OK

        else:
          # zeek returned no log files (or an error)
          eprint('Zeek failed to process {} (or no log files were generated)'.format(os.path.basename(pcapFile)))
          errCode = os.EX_DATAERR

      else:
        # pcap, log dir, or temp dir doesn't exist
        eprint('Specified file or directory does not exist')
        errCode = os.EX_DATAERR
  else:
    # invalid command-line arguments
    eprint("{} file.pcap [tags]".format(sys.argv[0]))
    errCode = os.EX_USAGE

  return errCode

if __name__ == '__main__':
  sys.exit(main())