#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2020 Battelle Energy Alliance, LLC.  All rights reserved.

###################################################################################################
# Monitor a directory for files extracted by zeek for processing
#
# Run the script with --help for options
###################################################################################################

import argparse
import copy
import glob
import json
import magic
import os
import pathlib
import pyinotify
import signal
import sys
import time
import zmq

from zeek_carve_utils import *

###################################################################################################
MINIMUM_CHECKED_FILE_SIZE_DEFAULT = 64
MAXIMUM_CHECKED_FILE_SIZE_DEFAULT = 134217728

###################################################################################################
debug = False
verboseDebug = False
pdbFlagged = False
args = None
scriptName = os.path.basename(__file__)
scriptPath = os.path.dirname(os.path.realpath(__file__))
origPath = os.getcwd()
shuttingDown = False

###################################################################################################
# watch files written to and moved to this directory
class EventWatcher(pyinotify.ProcessEvent):

  # notify on files written in-place then closed (IN_CLOSE_WRITE), and moved into this directory (IN_MOVED_TO)
  _methods = ["IN_CLOSE_WRITE", "IN_MOVED_TO"]

  def __init__(self):
    global debug

    super().__init__()

    # initialize ZeroMQ context and socket(s) to send messages to
    self.context = zmq.Context()

    # Socket to send messages on
    if debug: eprint(f"{scriptName}:\tbinding ventilator port {VENTILATOR_PORT}")
    self.ventilator_socket = self.context.socket(zmq.PUB)
    self.ventilator_socket.bind(f"tcp://*:{VENTILATOR_PORT}")

    # todo: do I want to set this? probably not since this guy's whole job is to send
    # and if he can't then what's the point? just block
    # self.ventilator_socket.SNDTIMEO = 5000

    if debug: eprint(f"{scriptName}:\tEventWatcher initialized")

###################################################################################################
# set up event processor to append processed events from to the event queue
def event_process_generator(cls, method):

  # actual method called when we are notified of a file
  def _method_name(self, event):

    global args
    global debug
    global verboseDebug

    if debug: eprint(f"{scriptName}:\t👓\t{event.pathname}")

    if (not event.dir) and os.path.isfile(event.pathname):

      fileSize = os.path.getsize(event.pathname)
      if (args.minBytes <= fileSize <= args.maxBytes):

        fileType = magic.from_file(event.pathname, mime=True)
        if (pathlib.Path(event.pathname).suffix != CAPA_VIV_SUFFIX) and (fileType != CAPA_VIV_MIME):
          # the entity is a right-sized file, is not a capa .viv cache file, and it exists, so send it to get scanned

          fileInfo = json.dumps({ FILE_SCAN_RESULT_FILE : event.pathname,
                                  FILE_SCAN_RESULT_FILE_SIZE : fileSize,
                                  FILE_SCAN_RESULT_FILE_TYPE : fileType })
          if debug: eprint(f"{scriptName}:\t📩\t{fileInfo}")
          try:
            self.ventilator_socket.send_string(fileInfo)
            if debug: eprint(f"{scriptName}:\t📫\t{event.pathname}")
          except zmq.Again as timeout:
            if verboseDebug: eprint(f"{scriptName}:\t🕑\t{event.pathname}")

        else:
          # temporary capa .viv file, just ignore it as it will get cleaned up by the scanner when it's done
          if debug: eprint(f"{scriptName}:\t🚧\t{event.pathname}")

      else:
        # too small/big to care about, delete it
        os.remove(event.pathname)
        if debug: eprint(f"{scriptName}:\t🚫\t{event.pathname}")

  # assign process method to class
  _method_name.__name__ = "process_{}".format(method)
  setattr(cls, _method_name.__name__, _method_name)

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
  parser.add_argument('--ignore-existing', dest='ignoreExisting', help="Ignore preexisting files in the monitor directory", metavar='true|false', type=str2bool, nargs='?', const=True, default=False, required=False)
  parser.add_argument('--start-sleep', dest='startSleepSec', help="Sleep for this many seconds before starting", metavar='<seconds>', type=int, default=0, required=False)
  parser.add_argument('-r', '--recursive-directory', dest='recursiveDir', help="If specified, monitor all directories with this name underneath --directory", metavar='<name>', type=str, required=False)
  parser.add_argument('--min-bytes', dest='minBytes', help="Minimum size for checked files", metavar='<bytes>', type=int, default=MINIMUM_CHECKED_FILE_SIZE_DEFAULT, required=False)
  parser.add_argument('--max-bytes', dest='maxBytes', help="Maximum size for checked files", metavar='<bytes>', type=int, default=MAXIMUM_CHECKED_FILE_SIZE_DEFAULT, required=False)
  requiredNamed = parser.add_argument_group('required arguments')
  requiredNamed.add_argument('-d', '--directory', dest='baseDir', help='Directory to monitor', metavar='<directory>', type=str, required=True)

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

  # add events to watch to EventWatcher class
  for method in EventWatcher._methods:
    event_process_generator(EventWatcher, method)

  # if directory to monitor doesn't exist, create it now
  if os.path.isdir(args.baseDir):
    preexistingDir = True
  else:
    preexistingDir = False
    if debug: eprint(f'{scriptname}: creating "{args.baseDir}" to monitor')
    pathlib.Path(args.baseDir).mkdir(parents=False, exist_ok=True)

  # if recursion was requested, get list of directories to monitor
  watchDirs = []
  while (len(watchDirs) == 0):
    if args.recursiveDir is None:
      watchDirs = [args.baseDir]
    else:
      watchDirs = glob.glob(f'{args.baseDir}/**/{args.recursiveDir}', recursive=True)

  # begin threaded watch of path(s)
  time.sleep(1)
  watch_manager = pyinotify.WatchManager()
  event_notifier = pyinotify.ThreadedNotifier(watch_manager, EventWatcher())
  for watchDir in watchDirs:
    watch_manager.add_watch(os.path.abspath(watchDir), pyinotify.ALL_EVENTS)
  if debug: eprint(f"{scriptName}: monitoring {watchDirs}")
  time.sleep(2)
  event_notifier.start()

  # if there are any previously included files (and not ignoreExisting), "touch" them so that they will be notified on
  if preexistingDir and (not args.ignoreExisting):
    filesTouched = 0
    for watchDir in watchDirs:
      for preexistingFile in [os.path.join(watchDir, x) for x in pathlib.Path(watchDir).iterdir() if x.is_file()]:
        touch(preexistingFile)
        filesTouched += 1
    if debug and (filesTouched > 0):
      eprint(f"{scriptName}: found {filesTouched} preexisting files to check")

  # loop forever, or until we're told to shut down, whichever comes first
  while (not shuttingDown):
    if pdbFlagged:
      pdbFlagged = False
      breakpoint()
    time.sleep(0.2)

  # graceful shutdown
  if debug: eprint(f"{scriptName}: shutting down...")
  event_notifier.stop()
  time.sleep(1)

  if debug: eprint(f"{scriptName}: finished monitoring {watchDirs}")

if __name__ == '__main__':
  main()
