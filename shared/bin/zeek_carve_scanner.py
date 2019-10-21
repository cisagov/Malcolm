#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2019 Battelle Energy Alliance, LLC.  All rights reserved.

###################################################################################################
# Process queued files reported by zeek_carve_watcher.py, scanning them with the specified
# virus scan engine and sending the results along to zeek_carve_logger.py
#
# Run the script with --help for options
###################################################################################################

import argparse
import os
import pathlib
import json
import signal
import sys
import threading
import time
import zmq

from zeek_carve_utils import *
from multiprocessing.pool import ThreadPool

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
scanWorkersCount = AtomicInt(value=0)

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
def scanFileWorker(checkConnInfo):
  global debug
  global verboseDebug
  global shuttingDown
  global scanWorkersCount

  scanWorkerId = scanWorkersCount.increment() # unique ID for this thread

  if debug: eprint(f"{scriptName}[{scanWorkerId}]:\tstarted")

  if isinstance(checkConnInfo, FileScanProvider):

    # initialize ZeroMQ context and socket(s) to receive filenames and send scan results
    context = zmq.Context()

    # Socket to receive messages on
    new_files_socket = context.socket(zmq.PULL)
    new_files_socket.connect(f"tcp://localhost:{VENTILATOR_PORT}")
    new_files_socket.RCVTIMEO = 5000
    if debug: eprint(f"{scriptName}[{scanWorkerId}]:\tbound to ventilator at {VENTILATOR_PORT}")

    # Socket to send messages to
    scanned_files_socket = context.socket(zmq.PUSH)
    scanned_files_socket.connect(f"tcp://localhost:{SINK_PORT}")
    # todo: do I want to set this? probably not, since what else would we do if we can't send? just block
    # scanned_files_socket.SNDTIMEO = 5000
    if debug: eprint(f"{scriptName}[{scanWorkerId}]:\tconnected to sink at {SINK_PORT}")

    fileName = None
    retrySubmitFile = False # todo: maximum file retry count?

    # loop forever, or until we're told to shut down
    while not shuttingDown:

      if retrySubmitFile and (fileName is not None) and os.path.isfile(fileName):
        # we were unable to submit the file for processing, so try again
        if debug: eprint(f"{scriptName}[{scanWorkerId}]:\t🔃\t{fileName}")

      else:
        retrySubmitFile = False

        # accept a filename from new_files_socket
        try:
          fileName = new_files_socket.recv_string()
        except zmq.Again as timeout:
          # no file received due to timeout, we'll go around and try again
          if verboseDebug: eprint(f"{scriptName}[{scanWorkerId}]:\t🕑\t(recv)")
          fileName = None

      if (fileName is not None) and os.path.isfile(fileName):

        # file exists, submit for scanning
        if debug: eprint(f"{scriptName}[{scanWorkerId}]:\t🔎\t{fileName}")
        requestComplete = False
        scanResult = None
        scan = AnalyzerScan(provider=checkConnInfo, name=fileName,
                            submissionResponse=checkConnInfo.submit(fileName=fileName, block=False))

        if scan.submissionResponse is not None:
          if debug: eprint(f"{scriptName}[{scanWorkerId}]:\t🔍\t{fileName}")

          # file was successfully submitted and is now being scanned
          retrySubmitFile = False
          requestComplete = False

          # todo: maximum time we wait for a single file to be scanned?
          while (not requestComplete) and (not shuttingDown):

            # wait a moment then check to see if the scan is complete
            time.sleep(scan.provider.check_interval())
            response = scan.provider.check_result(scan.submissionResponse)

            if isinstance(response, AnalyzerResult):

              # whether the scan has completed
              requestComplete = response.finished

              if response.success:
                # successful scan, report the scan results
                scanResult = response.result

              elif isinstance(response.result, dict) and ("error" in response.result):
                # scan errored out, report the error
                scanResult = response.result["error"]
                eprint(f"{scriptName}[{scanWorkerId}]:\t❗\t{fileName} {scanResult}")

              else:
                # result is unrecognizable
                scanResult = "Invalid scan result format"
                eprint(f"{scriptName}[{scanWorkerId}]:\t❗\t{fileName} {scanResult}")

            else:
              # impossibru! abandon ship for this file?
              # todo? what else? touch it?
              requestComplete = True
              scanResult = "Error checking results"
              eprint(f"{scriptName}[{scanWorkerId}]:\t❗{fileName} {scanResult}")

        else:
          # we were denied (rate limiting, probably), so we'll need wait for a slot to clear up
          retrySubmitFile = True

        if requestComplete and (scanResult is not None):
          try:
            # Send results to sink
            scanned_files_socket.send_string(json.dumps(scan.provider.format(fileName, scanResult)))
            if debug: eprint(f"{scriptName}[{scanWorkerId}]:\t✅\t{fileName}")

          except zmq.Again as timeout:
            # todo: what to do here?
            if verboseDebug: eprint(f"{scriptName}[{scanWorkerId}]:\t🕑\t{fileName}")

  else:
    eprint(f"{scriptName}[{scanWorkerId}]:\tinvalid scanner provider specified")

  if debug: eprint(f"{scriptName}[{scanWorkerId}]:\tfinished")

###################################################################################################
# main
def main():
  global args
  global debug
  global debugToggled
  global pdbFlagged
  global shuttingDown
  global verboseDebug

  parser = argparse.ArgumentParser(description=scriptName, add_help=False, usage='{} <arguments>'.format(scriptName))
  parser.add_argument('-v', '--verbose', dest='debug', help="Verbose output", metavar='true|false', type=str2bool, nargs='?', const=True, default=False, required=False)
  parser.add_argument('--extra-verbose', dest='verboseDebug', help="Super verbose output", metavar='true|false', type=str2bool, nargs='?', const=True, default=False, required=False)
  parser.add_argument('--start-sleep', dest='startSleepSec', help="Sleep for this many seconds before starting", metavar='<seconds>', type=int, default=0, required=False)
  parser.add_argument('--malass-host', dest='malassHost', help="Malass host or IP address", metavar='<host>', type=str, required=False)
  parser.add_argument('--malass-port', dest='malassPort', help="Malass web interface port", metavar='<port>', type=int, default=80, required=False)
  parser.add_argument('--malass-limit', dest='malassLimit', help="Malass maximum concurrent scans", metavar='<limit>', type=int, default=MAL_MAX_REQS, required=False)
  parser.add_argument('--vtot-api', dest='vtotApi', help="VirusTotal API key", metavar='<API key>', type=str, required=False)
  parser.add_argument('--vtot-req-limit', dest='vtotReqLimit', help="VirusTotal requests per minute limit", metavar='<requests>', type=int, default=VTOT_MAX_REQS, required=False)
  parser.add_argument('--clamav', dest='enableClamAv', metavar='true|false', help="Enable ClamAV (if VirusTotal and Malass are unavailable)", type=str2bool, nargs='?', const=True, default=False, required=False)
  parser.add_argument('--clamav-socket', dest='clamAvSocket', help="ClamAV socket filename", metavar='<filespec>', type=str, required=False, default=None)

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

  # intialize objects for virus scanning engines
  if (isinstance(args.malassHost, str) and (len(args.malassHost) > 1)):
    checkConnInfo = MalassScan(args.malassHost, args.malassPort, reqLimit=args.malassLimit)
  elif (isinstance(args.vtotApi, str) and (len(args.vtotApi) > 1) and (args.vtotReqLimit > 0)):
    checkConnInfo = VirusTotalSearch(args.vtotApi, reqLimit=args.vtotReqLimit)
  else:
    if not args.enableClamAv:
      eprint('No scanner specified, defaulting to ClamAV')
    checkConnInfo = ClamAVScan(debug=debug, verboseDebug=verboseDebug, socketFileName=args.clamAvSocket)

  # start scanner threads which will pull filenames to be scanned and send the results to the logger
  scannerThreads = ThreadPool(checkConnInfo.max_requests(), scanFileWorker, ([checkConnInfo]))
  while (not shuttingDown):
    if pdbFlagged:
      pdbFlagged = False
      breakpoint()
    time.sleep(0.2)

  # graceful shutdown
  if debug: eprint(f"{scriptName}: shutting down...")
  time.sleep(5)

if __name__ == '__main__':
  main()
