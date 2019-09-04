#!/usr/bin/env python3.7
# -*- coding: utf-8 -*-

# Copyright (c) 2019 Battelle Energy Alliance, LLC.  All rights reserved.

###################################################################################################
# Monitor a directory for files extracted by zeek for processing
#
# Run the script with --help for options
###################################################################################################

import argparse
import copy
import glob
import json
import os
import pathlib
import pyinotify
import random
import re
import shutil
import signal
import sys
import threading
import time

from carveutils import *

from cachetools import TTLCache
from collections import deque
from contextlib import nullcontext
from datetime import datetime
from multiprocessing.pool import ThreadPool

###################################################################################################
MAX_HASH_CACHE_SIZE = 10000
MAX_HASH_CACHE_TTL = 3600
HASH_THREADS = 4
SUBMIT_THREADS = 2
RESULT_THREADS = 1
MAX_PROCESSED_BATCH_SIZE = 250
MINIMUM_CHECKED_FILE_SIZE_DEFAULT = 64
MAXIMUM_CHECKED_FILE_SIZE_DEFAULT = 134217728

###################################################################################################
debug = False
debugToggled = False
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
  import pdb
  pdb.Pdb().set_trace(frame)

###################################################################################################
# handle sigusr2 for toggling debug
def debug_toggle_handler(signum, frame):
  global debug
  global debugToggled
  debug = not debug
  debugToggled = True

###################################################################################################
# worker thread for processing events from the inotify event queue and calculating the sha256 hash,
# upon which it's added to the hashed event queue
def hashFileWorker(queues):
  global args
  global shuttingDown

  fileQueue, hashedQueue = queues[0], queues[1]
  while not shuttingDown:
    try:
      # pull an item from the queue of files that need to be hashed
      fileEvent = fileQueue.popleft()
    except IndexError:
      time.sleep(1)
    else:
      if (not fileEvent.dir) and os.path.isfile(fileEvent.pathname):
        if (args.minBytes <= os.path.getsize(fileEvent.pathname) <= args.maxBytes):
          # the entity is a file, and it exists, so hash it and put it into the hashed file queue
          hashedQueue.append(HashedFileEvent(event=fileEvent, hash=sha256sum(fileEvent.pathname), request=None, result=None))
        else:
          # too small/big to care about, delete it
          os.remove(fileEvent.pathname)

###################################################################################################
# worker thread submitting files for analysis
def submitFileWorker(args):
  global shuttingDown

  toCheckQueue, checkingQueue, checkConnInfo = args[0], args[1], args[2]

  while not shuttingDown:

    submitted = False
    hashedFile = None

    try:
      # pull an item from the queue of hashed files to check
      hashedFile = toCheckQueue.popleft()
    except IndexError:
      time.sleep(1)
    else:
      if (hashedFile is not None) and os.path.isfile(hashedFile.event.pathname):

        if isinstance(checkConnInfo, FileScanProvider):
          scan = AnalyzerScan(provider=checkConnInfo, name=hashedFile.event.pathname, hash=hashedFile.hash,
                              submissionResponse=checkConnInfo.submit(fileName=hashedFile.event.pathname, fileHash=hashedFile.hash))

          if scan.submissionResponse is not None:
            # we submitted the file/hash for scanning/lookup
            hashedFile.request = scan
            submitted = True

          else:
            # we were denied (rate limiting, probably), so we'll need to re-queue the file and wait for a slot to clear up
            pass

        else:
          # there's no file scan provider, so nothing to do
          pass

        if submitted:
          # put the info needed to check the file status in the checking queue
          checkingQueue.append(hashedFile)
        else:
          # re-queue the file to wait for a slot to clear up
          toCheckQueue.appendleft(hashedFile)

###################################################################################################
# worker thread for checking finished resultants
def resultCheckWorker(args):
  global shuttingDown

  checkingQueue, finishedQueue, checkConnInfo = args[0], args[1], args[2]
  while not shuttingDown:
    completedCount = 0

    # pop all items from the checking queue, and check their status. if they
    # are finished, send it to the finished queue, otherwise put it back
    # in the checking queue
    checkingItems = []
    while True:
      try:
        checkingItems.append(checkingQueue.popleft())
      except IndexError:
        break

    for checkingItem in checkingItems:
      requestComplete = False

      if isinstance(checkingItem.request, AnalyzerScan):

        response = checkingItem.request.provider.check_result(checkingItem.request.submissionResponse)
        if isinstance(response, AnalyzerResult):

          requestComplete = response.finished
          if response.success:
            checkingItem.result = response.result
          elif isinstance(response.result, dict) and ("error" in response.result):
            checkingItem.result = response.result["error"]
          else:
            checkingItem.result = "Error checking results"

        else:
          # shouldn't be possible to get something that's not an AnalyzerResult from check_result,
          # abandon ship for this file
          requestComplete = True
          checkingItem.result = "Error checking results"

      elif checkingItem.request is None:
        # no request handler, nothing to look up
        requestComplete = True

      if requestComplete:
        # the file has been checked, decrement the global count of checking files
        finishedQueue.append(checkingItem)
        completedCount += 1

      else:
        # put it back into the checking queue; count remains unchanged for this object
        checkingQueue.append(checkingItem)

    if (completedCount == 0):
      time.sleep(1)

###################################################################################################
# main
def main():
  global args
  global debug
  global debugToggled
  global shuttingDown

  parser = argparse.ArgumentParser(description=scriptName, add_help=False, usage='{} <arguments>'.format(scriptName))
  parser.add_argument('-v', '--verbose', dest='debug', help="Verbose output", metavar='true|false', type=str2bool, nargs='?', const=True, default=False, required=False)
  parser.add_argument('--ignore-existing', dest='ignoreExisting', help="Ignore preexisting files in the monitor directory", metavar='true|false', type=str2bool, nargs='?', const=True, default=False, required=False)
  parser.add_argument('--preserve', dest='preserveMode', help=f"File preservation mode (default: {PRESERVE_QUARANTINED})", metavar=f'[{PRESERVE_QUARANTINED}|{PRESERVE_ALL}|{PRESERVE_NONE}]', type=str, default=PRESERVE_QUARANTINED, required=False)
  parser.add_argument('--min-bytes', dest='minBytes', help="Minimum size for checked files", metavar='<bytes>', type=int, default=MINIMUM_CHECKED_FILE_SIZE_DEFAULT, required=False)
  parser.add_argument('--max-bytes', dest='maxBytes', help="Maximum size for checked files", metavar='<bytes>', type=int, default=MAXIMUM_CHECKED_FILE_SIZE_DEFAULT, required=False)
  parser.add_argument('--malass-host', dest='malassHost', help="Malass host or IP address", metavar='<host>', type=str, required=False)
  parser.add_argument('--malass-port', dest='malassPort', help="Malass web interface port", metavar='<port>', type=int, default=80, required=False)
  parser.add_argument('--malass-limit', dest='malassLimit', help="Malass maximum concurrent scans", metavar='<limit>', type=int, default=MAL_MAX_REQS, required=False)
  parser.add_argument('--vtot-api', dest='vtotApi', help="VirusTotal API key", metavar='<API key>', type=str, required=False)
  parser.add_argument('--vtot-req-limit', dest='vtotReqLimit', help="VirusTotal requests per minute limit", metavar='<requests>', type=int, default=VTOT_MAX_REQS, required=False)
  parser.add_argument('--clamav', dest='enableClamAv', metavar='true|false', help="Enable ClamAV (if VirusTotal and Malass are unavailable)", type=str2bool, nargs='?', const=True, default=False, required=False)
  parser.add_argument('--start-sleep', dest='startSleepSec', help="Sleep for this many seconds before starting", metavar='<seconds>', type=int, default=0, required=False)
  parser.add_argument('--zeek-log', dest='broSigLogSpec', help="Filespec to write Zeek signature log", metavar='<filespec>', type=str, required=False)
  parser.add_argument('-r', '--recursive-directory', dest='recursiveDir', help="If specified, monitor all directories with this name underneath --directory", metavar='<name>', type=str, required=False)
  requiredNamed = parser.add_argument_group('required arguments')
  requiredNamed.add_argument('-d', '--directory', dest='baseDir', help='Directory to monitor', metavar='<directory>', type=str, required=True)

  try:
    parser.error = parser.exit
    args = parser.parse_args()
  except SystemExit:
    parser.print_help()
    exit(2)

  debug = args.debug
  if debug:
    eprint(os.path.join(scriptPath, scriptName))
    eprint("Arguments: {}".format(sys.argv[1:]))
    eprint("Arguments: {}".format(args))
  else:
    sys.tracebacklimit = 0

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

  broSigLogSpec = args.broSigLogSpec
  if broSigLogSpec is not None:
    if os.path.isdir(broSigLogSpec):
      # _carved tag will be recognized by 11_zeek_logs.conf in logstash
      broSigLogSpec = os.path.join(broSigLogSpec, "signatures(_carved).log")
    else:
      # make sure path to write to zeek signatures log file exists before we start writing
      pathlib.Path(os.path.dirname(os.path.realpath(broSigLogSpec))).mkdir(parents=True, exist_ok=True)

  # add events to watch to EventWatcher class
  for method in EventWatcher._methods:
    event_process_generator(EventWatcher, method)

  if os.path.isdir(args.baseDir):
    preexistingDir = True
  else:
    preexistingDir = False
    if debug: eprint(f'Creating "{args.baseDir}" to monitor')
    pathlib.Path(args.baseDir).mkdir(parents=False, exist_ok=True)

  quarantineDir = os.path.join(args.baseDir, "quarantine")
  preserveDir = os.path.join(args.baseDir, "preserved")
  if (args.preserveMode != PRESERVE_NONE) and (not os.path.isdir(quarantineDir)):
    if debug: eprint(f'Creating "{quarantineDir}" for quarantined files')
    pathlib.Path(quarantineDir).mkdir(parents=False, exist_ok=True)
  if (args.preserveMode == PRESERVE_ALL) and (not os.path.isdir(preserveDir)):
    if debug: eprint(f'Creating "{preserveDir}" for other preserved files')
    pathlib.Path(preserveDir).mkdir(parents=False, exist_ok=True)

  watchDirs = []
  while (len(watchDirs) == 0):
    if args.recursiveDir is None:
      watchDirs = [args.baseDir]
    else:
      watchDirs = glob.glob(f'{args.baseDir}/**/{args.recursiveDir}', recursive=True)

  newFileQueue = deque()
  hashedFileQueue = deque()
  toCheckFileQueue = deque()
  checkingFileQueue = deque()
  finishedFileQueue = deque()
  hashCache = TTLCache(maxsize=MAX_HASH_CACHE_SIZE, ttl=MAX_HASH_CACHE_TTL) # only used in the main thread

  if (isinstance(args.malassHost, str) and (len(args.malassHost) > 1)):
    checkConnInfo = MalassScan(args.malassHost, args.malassPort, reqLimit=args.malassLimit)
  elif (isinstance(args.vtotApi, str) and (len(args.vtotApi) > 1) and (args.vtotReqLimit > 0)):
    checkConnInfo = VirusTotalSearch(args.vtotApi, reqLimit=args.vtotReqLimit)
  elif args.enableClamAv:
    checkConnInfo = ClamAVScan(debug=debug)
  else:
    checkConnInfo = None

  # begin threaded watch of directory
  time.sleep(1)
  watch_manager = pyinotify.WatchManager()
  event_notifier = pyinotify.ThreadedNotifier(watch_manager, EventWatcher(newFileQueue))
  for watchDir in watchDirs:
    watch_manager.add_watch(os.path.abspath(watchDir), pyinotify.ALL_EVENTS)
  if debug:
    eprint(f"Monitoring {watchDirs}")
  event_notifier.start()

  # hash files as they are discovered
  fileHashWorkers = ThreadPool(HASH_THREADS, hashFileWorker,([newFileQueue,hashedFileQueue],))
  submitCheckWorkers = ThreadPool(SUBMIT_THREADS if not isinstance(checkConnInfo, ClamAVScan) else CLAM_MAX_REQS,
                                  submitFileWorker,([toCheckFileQueue,checkingFileQueue,checkConnInfo],))
  resultCheckWorkers = ThreadPool(RESULT_THREADS, resultCheckWorker,([checkingFileQueue,finishedFileQueue,checkConnInfo],))

  # if there are any previously included files, start with them
  if preexistingDir and (not args.ignoreExisting):
    filesTouched = 0
    for watchDir in watchDirs:
      for preexistingFile in [os.path.join(watchDir, x) for x in pathlib.Path(watchDir).iterdir() if x.is_file()]:
        open(preexistingFile, 'a').close()
        os.utime(preexistingFile, None)
        filesTouched += 1
    if debug and (filesTouched > 0):
      eprint(f"Found {filesTouched} preexisting files to check")

  with open(broSigLogSpec, 'w+', 1) if (broSigLogSpec is not None) else nullcontext() as broSigFile:

    # write out header for our super legit zeek signature.log file
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

    debugStats = []
    prevDebugStats = []

    while (not shuttingDown):

      processedEvents = 0

      # processed files for which checking is finished
      while (not shuttingDown) and (processedEvents < (MAX_PROCESSED_BATCH_SIZE // 2)):
        try:
          fileEvent = finishedFileQueue.popleft()
        except IndexError:
          break
        else:
          processedEvents += 1
          triggered = False
          debugStr = f"FIN: {fileEvent.event.pathname} is {fileEvent.hash[:8]} ({fileEvent.result})" if debug else ""

          if (broSigFile is not None):

            if isinstance(fileEvent.request, AnalyzerScan):
              scanResult = fileEvent.request.provider.format(fileEvent.result)
              triggered = (scanResult.hits > 0)

              if triggered:
                fileSpecFields = extracted_filespec_to_fields(fileEvent.event.pathname)
                broLine = BroSignatureLine(ts=f"{fileSpecFields.time}",
                                           uid=fileSpecFields.uid if fileSpecFields.uid is not None else '-',
                                           note=ZEEK_SIGNATURE_NOTICE,
                                           signature_id=scanResult.message,
                                           event_message=scanResult.description,
                                           sub_message=fileSpecFields.fid if fileSpecFields.fid is not None else os.path.basename(fileEvent.event.pathname),
                                           signature_count=scanResult.hits,
                                           host_count=scanResult.engines)
                broLineStr = BroStringFormat.format(**broLine._asdict())
                debugStr = broLineStr

                # write broLineStr event line out to zeek signature.log
                print(broLineStr, file=broSigFile, end='\n')

                # save BroSignatureLine-formatted result if it's found in the hash again later
                fileEvent.result = broLine

          if triggered and (args.preserveMode != PRESERVE_NONE):
            # move triggering file to quarantine
            try:
              shutil.move(fileEvent.event.pathname, quarantineDir)
            except:
              # hm move failed, delete it i guess?
              os.remove(fileEvent.event.pathname)

          elif (args.preserveMode == PRESERVE_ALL):
            # move non-triggering file to preserved directory
            try:
              shutil.move(fileEvent.event.pathname, preserveDir)
            except:
              # hm move failed, delete it i guess?
              os.remove(fileEvent.event.pathname)

          else:
            # delete the file
            os.remove(fileEvent.event.pathname)

          if debug: eprint(debugStr)

          # this file has been checked, update the hash cache with the final result
          hashCache[fileEvent.hash] = fileEvent

      # process new hashed files to be checked
      queuedDupes = deque()
      while (not shuttingDown) and (processedEvents < MAX_PROCESSED_BATCH_SIZE):
        try:
          fileEvent = hashedFileQueue.popleft()
        except IndexError:
          break
        else:
          processedEvents += 1
          debugStr = f"POP: {fileEvent.event.pathname} is {fileEvent.hash[:8]} ({fileEvent.result})" if debug else ""

          if fileEvent.hash in hashCache:
            triggered = False

            if hashCache[fileEvent.hash].result is not None:
              # the file has already been checked all the way through the pipeline and has a result
              debugStr = f"OLD: {fileEvent.event.pathname} is {fileEvent.hash[:8]} ({fileEvent.result})" if debug else ""

              triggered = isinstance(hashCache[fileEvent.hash].result, BroSignatureLine)
              if triggered:

                # this file triggered a previous signature match, so we don't need to bother processing it again

                # just update the new fields for the copy of the log
                fileSpecFields = extracted_filespec_to_fields(fileEvent.event.pathname)
                dupResultBroLine = copy.deepcopy(hashCache[fileEvent.hash].result)
                dupResultBroLine.ts=f"{fileSpecFields.time}"
                dupResultBroLine.uid = fileSpecFields.uid if fileSpecFields.uid is not None else '-'
                dupResultBroLine.sub_message = f"{fileSpecFields.fid if fileSpecFields.fid is not None else os.path.basename(fileEvent.event.pathname)},{hashCache[fileEvent.hash].result.sub_message}"

                broLineStr = BroStringFormat.format(**dupResultBroLine._asdict())
                debugStr = f"{broLineStr}"

                # write broLineStr event line out to zeek signature.log
                print(broLineStr, file=broSigFile, end='\n')

                # don't save the duplicate, since we've already saved the original and reference it in the log
                os.remove(fileEvent.event.pathname)

              else:
                # the file is in the pipeline to be checked, so we don't know the result, but we don't want to check it mulitple times...
                # debugStr = f"AOK: {fileEvent.event.pathname} is {fileEvent.hash[:8]} ({fileEvent.result})" if debug else ""
                debugStr = "" # too verbose, even for debug

                # seen before, but not triggered, so just delete this harmless file
                os.remove(fileEvent.event.pathname)

            else:
              # todo: BUG: if submission failed for everyone, then they're all just sitting in the queue but nobody ever retries

              # the file is in the pipeline to be checked, so we don't know the result, but we don't want to check it mulitple times...
              # debugStr = f"DUP: {fileEvent.event.pathname} is {fileEvent.hash[:8]} ({fileEvent.result})" if debug else ""
              debugStr = "" # too verbose, even for debug

              if checkConnInfo is not None:
                # as long as we have some kind of file checker registered (any(checkConnInfo)),
                # after the loop we will reinsert this into the back end of the queue for checking later
                queuedDupes.append(fileEvent)

              else:
                # no file checker created. don't save the duplicate, since we'd have already saved the original
                os.remove(fileEvent.event.pathname)

            if debug and (len(debugStr) > 0): eprint(debugStr)

          else:
            # this is a file we have not seen before
            if debug: eprint(f"NEW: {fileEvent.event.pathname} is {fileEvent.hash[:8]}")
            hashCache[fileEvent.hash] = fileEvent
            toCheckFileQueue.append(fileEvent)

      # put duplicated processing events back into the hashedFileQueue to check again in a bit
      dupeEvents = 0
      while (len(queuedDupes) > 0):
        dupeEvents += 1
        hashedFileQueue.append(queuedDupes.popleft())

      # if we didn't do anything, sleep for a bit before checking again
      if debug:
        debugStats = [len(finishedFileQueue),
                      len(checkingFileQueue),
                      len(toCheckFileQueue),
                      len(hashedFileQueue),
                      len(newFileQueue)]
        if any(x > 0 for x in debugStats) or any(x > 0 for x in prevDebugStats) or debugToggled:
          eprint(f"\t{debugStats[0]} finished, {debugStats[1]} checking, {debugStats[2]} to check, {debugStats[3]} hashed, {debugStats[4]} new")
          debugToggled = False
        prevDebugStats = debugStats

      # if we didn't do anything, sleep for a bit before checking again
      if ((processedEvents - dupeEvents) < MAX_PROCESSED_BATCH_SIZE):
        sleepCount = 0
        while (not shuttingDown) and (sleepCount < 5):
          time.sleep(1)
          sleepCount += 1

      # end main event processing while loop

  # graceful shutdown
  if debug:
    eprint("Shutting down...")
  event_notifier.stop()
  if debug:
    eprint(f"Finished monitoring {watchDirs}")

if __name__ == '__main__':
  main()
