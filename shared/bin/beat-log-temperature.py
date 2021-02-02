#!/usr/bin/env python3.7
# -*- coding: utf-8 -*-

# Copyright (c) 2021 Battelle Energy Alliance, LLC.  All rights reserved.

import os
import re
import sys
import time
import argparse
from functools import reduce
from sensorcommon import *
from sensormetric import *
from collections import defaultdict

BEAT_PORT_DEFAULT=9515
BEAT_INTERFACE_IP="127.0.0.1"
BEAT_PROTOCOL="udp"
BEAT_FORMAT="json"

###################################################################################################
###################################################################################################
def main():

  # extract arguments from the command line
  # print (sys.argv[1:]);
  parser = argparse.ArgumentParser(description='beat-log-temperature.py', add_help=False, usage='temperature.py [options]')
  parser.add_argument('-p', '--port', dest='port', metavar='<INT>', type=int, nargs='?', default=BEAT_PORT_DEFAULT, help='UDP port monitored by protologbeat')
  parser.add_argument('-c', '--count', dest='loop', metavar='<INT>', type=int, nargs='?', default=1, help='Number of times to execute (default = 1, 0 = loop forever)')
  parser.add_argument('-s', '--sleep', dest='sleep', metavar='<INT>', type=int, nargs='?', default=10, help='Seconds between iterations if looping (default = 10)')
  parser.add_argument('-v', '--verbose', dest='debug', type=str2bool, nargs='?', const=True, default=False, help="Verbose output")
  try:
    parser.error = parser.exit
    args = parser.parse_args()
  except SystemExit:
    parser.print_help()
    exit(2)

  # set up destination beat
  eprint(f"Logging {BEAT_FORMAT} sensor statistics to {BEAT_INTERFACE_IP}:{args.port} over {BEAT_PROTOCOL}")
  beat = HeatBeatLogger(BEAT_INTERFACE_IP, args.port, BEAT_PROTOCOL, BEAT_FORMAT)

  loopCount = 0
  while (args.loop <= 0) or (loopCount < args.loop):

    if (loopCount >= 1):
      time.sleep(args.sleep)
    loopCount += 1

    metrics = get_metrics_list()
    metrics_dicts = [x.to_dictionary() for x in metrics]
    for d in metrics_dicts:
      d.pop('value_type', None)

    # get averages for each metric class
    metric_class_values = defaultdict(list)

    # put together a list for each class of metric for averaging
    for metrics in metrics_dicts:
      label_class = metrics["class"]
      if (len(label_class) > 0):
        metric_class_values[label_class].append(metrics["value"])

    # average each metric  class
    message = {}
    for k, v in metric_class_values.items():
      message[f"{k}_avg"] = reduce(lambda a, b: a + b, v) / len(v)

    # send the message
    message['sensors'] = metrics_dicts
    if args.debug:
      eprint(f"Message: {message}")
    beat.send_message(message)

if __name__ == '__main__':
  main()
