#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2024 Battelle Energy Alliance, LLC.  All rights reserved.

import argparse
import json
import logging
import os
import sys

from malcolm_utils import run_process

###################################################################################################
args = None
script_return_code = 0
script_name = os.path.basename(__file__)
script_path = os.path.dirname(os.path.realpath(__file__))
orig_path = os.getcwd()


###################################################################################################
def main():
    global args

    parser = argparse.ArgumentParser(
        description='\n'.join(
            [
                'Return sensors temperature values in JSON',
            ]
        ),
        formatter_class=argparse.RawTextHelpFormatter,
        add_help=False,
        usage='{} <arguments>'.format(script_name),
    )
    parser.add_argument(
        '--verbose',
        '-v',
        action='count',
        default=1,
        help='Increase verbosity (e.g., -v, -vv, etc.)',
    )
    try:
        parser.error = parser.exit
        args = parser.parse_args()
    except SystemExit:
        parser.print_help()
        exit(2)

    args.verbose = logging.CRITICAL - (10 * args.verbose) if args.verbose > 0 else 0
    logging.basicConfig(
        level=args.verbose, format='%(asctime)s %(levelname)s: %(message)s', datefmt='%Y-%m-%d %H:%M:%S'
    )
    logging.info(os.path.join(script_path, script_name))
    logging.info("Arguments: {}".format(sys.argv[1:]))
    logging.info("Arguments: {}".format(args))
    if args.verbose > logging.DEBUG:
        sys.tracebacklimit = 0

    retcode, output = run_process(
        ['sensors', '-j'],
        stderr=False,
        debug=args.verbose > logging.DEBUG,
        logger=logging,
    )
    if (retcode == 0) and output:
        temps = json.loads(''.join(output))

        # TODO: format like fluent-bit's output (https://docs.fluentbit.io/manual/pipeline/inputs/thermal)
        # e.g., {"name"=>"thermal_zone0", "type"=>"x86_pkg_temp", "temp"=>45.000000}
        print(json.dumps(temps))
    else:
        script_return_code = retcode if not retcode else 1


###################################################################################################
if __name__ == '__main__':
    main()
    sys.exit(script_return_code)
