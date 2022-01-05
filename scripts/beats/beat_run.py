#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (c) 2022 Battelle Energy Alliance, LLC.  All rights reserved.

from __future__ import print_function

import argparse
import os
import platform
import sys
from beat_common import *

###################################################################################################
ScriptName = os.path.basename(__file__)

###################################################################################################
# main
def main():

    # extract arguments from the command line
    # print (sys.argv[1:]);
    parser = argparse.ArgumentParser(
        description='Beat local execution script', add_help=False, usage='{} <arguments>'.format(ScriptName)
    )
    parser.add_argument(
        '-v', '--verbose', dest='debug', type=str2bool, nargs='?', const=True, default=False, help="Verbose output"
    )
    parser.add_argument(
        '-b', '--beat', required=True, dest='beatName', metavar='<STR>', type=str, default=None, help='Beat name'
    )
    parser.add_argument(
        '-c',
        '--config-file',
        required=False,
        dest='configFile',
        metavar='<STR>',
        type=str,
        default=None,
        help='Beat YML config file',
    )

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
    else:
        sys.tracebacklimit = 0

    args.beatName = args.beatName.lower()
    if not args.beatName.endswith('beat'):
        args.beatName = args.beatName + 'beat'

    if args.configFile is None:
        args.configFile = args.beatName + '.yml'

    installerPlatform = platform.system()
    if installerPlatform == PLATFORM_LINUX:
        Beatbox = LinuxBeatbox(debug=args.debug, ymlFileSpec=args.configFile, beatName=args.beatName)
    elif installerPlatform == PLATFORM_MAC:
        Beatbox = MacBeatbox(debug=args.debug, ymlFileSpec=args.configFile, beatName=args.beatName)
    elif installerPlatform == PLATFORM_WINDOWS:
        Beatbox = WindowsBeatbox(debug=args.debug, ymlFileSpec=args.configFile, beatName=args.beatName)

    success = False
    if hasattr(Beatbox, 'beat_run'):
        success = Beatbox.beat_run()

    return success


if __name__ == '__main__':
    main()
