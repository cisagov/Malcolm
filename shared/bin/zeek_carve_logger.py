#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2019 Battelle Energy Alliance, LLC.  All rights reserved.

###################################################################################################
# Monitor a directory for files extracted by zeek for processing
#
# Run the script with --help for options
###################################################################################################

import argparse
import datetime
import json
import os
import pathlib
import re
import signal
import sys
import time
import zmq

from datetime import datetime
from zeek_carve_utils import *

###################################################################################################
debug = False
verboseDebug = False
debugToggled = False
pdbFlagged = False
args = None
scriptName = os.path.basename(__file__)
scriptPath = os.path.dirname(os.path.realpath(__file__))
origPath = os.getcwd()
shuttingDown = False

###################################################################################################
# handle sigint/sigterm and set a global shutdown variable
def shutdown_handler(signum, frame):
  global shuttingDown
  shuttingDown = True

###################################################################################################
# handle sigusr1 for a pdb breakpoint
def pdb_handler(sig, frame):
  global pdbFlagged
  pdbFlagged = True

###################################################################################################
# handle sigusr2 for toggling debug
def debug_toggle_handler(signum, frame):
  global debug
  global debugToggled
  debug = not debug
  debugToggled = True

###################################################################################################
# main
def main():
  global args
  global debug
  global verboseDebug
  global debugToggled
  global pdbFlagged
  global shuttingDown

  parser = argparse.ArgumentParser(description=scriptName, add_help=False, usage='{} <arguments>'.format(scriptName))
  parser.add_argument('-v', '--verbose', dest='debug', help="Verbose output", metavar='true|false', type=str2bool, nargs='?', const=True, default=False, required=False)
  parser.add_argument('--extra-verbose', dest='verboseDebug', help="Super verbose output", metavar='true|false', type=str2bool, nargs='?', const=True, default=False, required=False)
  parser.add_argument('--start-sleep', dest='startSleepSec', help="Sleep for this many seconds before starting", metavar='<seconds>', type=int, default=0, required=False)
  parser.add_argument('--preserve', dest='preserveMode', help=f"File preservation mode (default: {PRESERVE_QUARANTINED})", metavar=f'[{PRESERVE_QUARANTINED}|{PRESERVE_ALL}|{PRESERVE_NONE}]', type=str, default=PRESERVE_QUARANTINED, required=False)
  parser.add_argument('--zeek-log', dest='broSigLogSpec', help="Filespec to write Zeek signature log", metavar='<filespec>', type=str, required=False)
  requiredNamed = parser.add_argument_group('required arguments')
  requiredNamed.add_argument('-d', '--directory', dest='baseDir', help='Directory being monitored', metavar='<directory>', type=str, required=True)

  try:
    parser.error = parser.exit
    args = parser.parse_args()
  except SystemExit:
    parser.print_help()
    exit(2)

  verboseDebug = args.verboseDebug
  debug = args.debug or verboseDebug
  if debug:
    eprint(os.path.join(scriptPath, scriptName))
    eprint("{} arguments: {}".format(scriptName, sys.argv[1:]))
    eprint("{} arguments: {}".format(scriptName, args))
  else:
    sys.tracebacklimit = 0

  # determine what to do with scanned files (preserve only "hits", preserve all, preserve none)
  args.preserveMode = args.preserveMode.lower()
  if (len(args.preserveMode) == 0):
    args.preserveMode = PRESERVE_QUARANTINED
  elif (args.preserveMode not in [PRESERVE_QUARANTINED, PRESERVE_ALL, PRESERVE_NONE]):
    eprint(f'Invalid file preservation mode "{args.preserveMode}"')
    sys.exit(1)

  # handle sigint and sigterm for graceful shutdown
  signal.signal(signal.SIGINT, shutdown_handler)
  signal.signal(signal.SIGTERM, shutdown_handler)
  signal.signal(signal.SIGUSR1, pdb_handler)
  signal.signal(signal.SIGUSR2, debug_toggle_handler)

  # sleep for a bit if requested
  sleepCount = 0
  while (not shuttingDown) and (sleepCount < args.startSleepSec):
    time.sleep(1)
    sleepCount += 1

  # where will the fake zeek log file be written to?
  broSigLogSpec = args.broSigLogSpec
  if broSigLogSpec is not None:
    if os.path.isdir(broSigLogSpec):
      # _carved tag will be recognized by 11_zeek_logs.conf in logstash
      broSigLogSpec = os.path.join(broSigLogSpec, "signatures(_carved).log")
    else:
      # make sure path to write to zeek signatures log file exists before we start writing
      pathlib.Path(os.path.dirname(os.path.realpath(broSigLogSpec))).mkdir(parents=True, exist_ok=True)

  # create quarantine/preserved directories for preserved files (see preserveMode)
  quarantineDir = os.path.join(args.baseDir, "quarantine")
  preserveDir = os.path.join(args.baseDir, "preserved")
  if (args.preserveMode != PRESERVE_NONE) and (not os.path.isdir(quarantineDir)):
    if debug: eprint(f'Creating "{quarantineDir}" for quarantined files')
    pathlib.Path(quarantineDir).mkdir(parents=False, exist_ok=True)
  if (args.preserveMode == PRESERVE_ALL) and (not os.path.isdir(preserveDir)):
    if debug: eprint(f'Creating "{preserveDir}" for other preserved files')
    pathlib.Path(preserveDir).mkdir(parents=False, exist_ok=True)

  # initialize ZeroMQ context and socket(s) to send messages to
  context = zmq.Context()

  # Socket to receive scan results on
  scanned_files_socket = context.socket(zmq.PULL)
  scanned_files_socket.bind(f"tcp://*:{SINK_PORT}")
  scanned_files_socket.SNDTIMEO = 5000
  scanned_files_socket.RCVTIMEO = 5000

  if debug: eprint(f"{scriptName}: bound sink port {SINK_PORT}")


  # open and write out header for our super legit zeek signature.log file
  with open(broSigLogSpec, 'w+', 1) if (broSigLogSpec is not None) else nullcontext() as broSigFile:
    if (broSigFile is not None):
      print('#separator \\x09', file=broSigFile, end='\n')
      print('#set_separator\t,', file=broSigFile, end='\n')
      print('#empty_field\t(empty)', file=broSigFile, end='\n')
      print('#unset_field\t-', file=broSigFile, end='\n')
      print('#path\tsignature', file=broSigFile, end='\n')
      print(f'#open\t{datetime.now().strftime("%Y-%m-%d-%H-%M-%S")}', file=broSigFile, end='\n')
      print(re.sub(r"\b((orig|resp)_[hp])\b", r"id.\1",
                   f"#fields\t{BroStringFormat}".replace('{', '').replace('}', '')),
            file=broSigFile, end='\n')
      print(f'#types\t{BroSignatureTypes}', file=broSigFile, end='\n')

    while (not shuttingDown):

      if pdbFlagged:
        pdbFlagged = False
        breakpoint()

      try:

        #
        scanResult = json.loads(scanned_files_socket.recv_string())
        if debug: eprint(f"{scriptName}:\t✉\t{scanResult}")

      except zmq.Again as timeout:
        if verboseDebug: eprint(f"{scriptName}:\t🕑 (recv)")

  # graceful shutdown
  if debug:
    eprint(f"{scriptName}: shutting down...")

if __name__ == '__main__':
  main()
