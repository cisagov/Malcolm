#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2023 Battelle Energy Alliance, LLC.  All rights reserved.

# modify suricata's update.yaml according to many environment variables

#
# suricata-update: https://suricata-update.readthedocs.io/en/latest/update.html
#                  https://github.com/OISF/suricata-update/blob/master/suricata/update/configs/update.yaml
#
#

import argparse
import contextlib
import fnmatch
import logging
import os
import sys
import time
import tempfile

from collections import defaultdict, namedtuple
from collections.abc import Iterable
from io import StringIO
from ruamel.yaml import YAML
from shutil import move as MoveFile, copyfile as CopyFile
from subprocess import PIPE, Popen

from malcolm_utils import val2bool

###################################################################################################
args = None
script_return_code = 0
script_name = os.path.basename(__file__)
script_path = os.path.dirname(os.path.realpath(__file__))
orig_path = os.getcwd()

###################################################################################################
YAML_VERSION = (1, 1)
BACKUP_FILES_MAX = 10


###################################################################################################
# run command with arguments and return its exit code and output
class NullRepresenter:
    def __call__(self, repr, data):
        ret_val = repr.represent_scalar(u'tag:yaml.org,2002:null', u'')
        return ret_val


###################################################################################################
def ObjToYamlStrLines(obj, options=None):
    outputStr = None
    if options is None:
        options = {}

    yaml = YAML()
    yaml.preserve_quotes = False
    yaml.representer.ignore_aliases = lambda x: True
    yaml.representer.add_representer(type(None), NullRepresenter())
    yaml.boolean_representation = ['no', 'yes']
    yaml.version = YAML_VERSION

    with StringIO() as stringStream:
        yaml.dump(obj, stringStream, **options)
        outputStr = stringStream.getvalue()

    return outputStr.splitlines()


###################################################################################################

DEFAULT_VARS = defaultdict(lambda: None)
DEFAULT_VARS.update(
    {
        'REFRESH_ETOPEN': True,
    }
)
for varName, varVal in [
    (key.upper(), value)
    for key, value in os.environ.items()
    if key.upper().startswith('SURICATA') or key.upper() in ('SUPERVISOR_PATH')
]:
    tmpYaml = YAML(typ='safe')
    newVal = tmpYaml.load(varVal)
    if isinstance(newVal, str):
        if (newVal.lower() == 'yes') or (newVal.lower() == 'true'):
            newVal = True
        elif (newVal.lower() == 'no') or (newVal.lower() == 'false'):
            newVal = False
    DEFAULT_VARS[varName.removeprefix("SURICATA_")] = newVal


###################################################################################################
def main():
    global args
    global DEFAULT_VARS

    parser = argparse.ArgumentParser(
        description='\n'.join(
            [
                'modify suricata-update\'s update.yaml according to many environment variables',
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
    parser.add_argument(
        '--inplace',
        dest='inplace',
        action='store_true',
        help='Modify configuration file in-place',
    )
    parser.add_argument(
        '--no-inplace',
        dest='inplace',
        action='store_false',
        help='Do not modify configuration file in-place',
    )
    parser.set_defaults(inplace=True)
    parser.add_argument(
        '-i',
        '--input',
        dest='input',
        type=str,
        default=os.getenv(
            'SURICATA_UPDATE_CONFIG_FILE',
            os.path.join(os.path.join(os.getenv('SUPERVISOR_PATH', '/etc'), 'suricata'), 'update.yaml'),
        ),
        required=False,
        metavar='<string>',
        help="Input YAML file",
    )
    parser.add_argument(
        '-o',
        '--output',
        dest='output',
        type=str,
        default=None,
        required=False,
        metavar='<string>',
        help="Output YAML file (take precedence over --inplace)",
    )
    try:
        parser.error = parser.exit
        args = parser.parse_args()
    except SystemExit:
        parser.print_help()
        exit(2)

    inFileParts = os.path.splitext(args.input)
    args.output = (
        args.output if args.output else args.input if args.inplace else inFileParts[0] + "_new" + inFileParts[1]
    )

    args.verbose = logging.CRITICAL - (10 * args.verbose) if args.verbose > 0 else 0
    logging.basicConfig(
        level=args.verbose, format='%(asctime)s %(levelname)s: %(message)s', datefmt='%Y-%m-%d %H:%M:%S'
    )
    logging.info(os.path.join(script_path, script_name))
    logging.info("Arguments: {}".format(sys.argv[1:]))
    logging.info("Arguments: {}".format(args))
    if args.verbose > logging.DEBUG:
        sys.tracebacklimit = 0

    ##################################################################################################
    # back up the old YAML file if we need to first
    if os.path.isfile(args.output) and os.path.samefile(args.input, args.output):
        backupFile = inFileParts[0] + "_bak_" + str(int(round(time.time()))) + inFileParts[1]
        CopyFile(args.input, backupFile)
        backupFiles = sorted(fnmatch.filter(os.listdir(os.path.dirname(backupFile)), '*_bak_*'))
        while len(backupFiles) > BACKUP_FILES_MAX:
            toDeleteFileName = os.path.join(os.path.dirname(backupFile), backupFiles.pop(0))
            logging.debug(f'Removing old backup file "{toDeleteFileName}"')
            os.remove(toDeleteFileName)

    ##################################################################################################
    # load input YAML
    cfg = None
    if args.input and os.path.isfile(args.input):
        with open(args.input, 'r') as f:
            inYaml = YAML(typ='rt')
            inYaml.preserve_quotes = False
            inYaml.emitter.alt_null = None
            inYaml.representer.ignore_aliases = lambda x: True
            inYaml.boolean_representation = ['no', 'yes']
            cfg = inYaml.load(f)
    # logging.debug(cfg)

    ##################################################################################################

    # write the new YAML file
    with open(args.output, 'w') as outfile:
        outYaml = YAML(typ='rt')
        outYaml.preserve_quotes = False
        outYaml.representer.ignore_aliases = lambda x: True
        outYaml.representer.add_representer(type(None), NullRepresenter())
        outYaml.boolean_representation = ['no', 'yes']
        outYaml.version = YAML_VERSION
        outYaml.dump(cfg, outfile)

    ##################################################################################################


###################################################################################################
if __name__ == '__main__':
    main()
    sys.exit(script_return_code)
