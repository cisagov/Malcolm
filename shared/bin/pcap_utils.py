#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2022 Battelle Energy Alliance, LLC.  All rights reserved.

import os
import re
import sys

from subprocess import PIPE, Popen
from multiprocessing import RawValue
from threading import Lock

###################################################################################################
PCAP_TOPIC_PORT = 30441

PCAP_MIME_TYPES = ['application/vnd.tcpdump.pcap', 'application/x-pcapng']

FILE_INFO_DICT_NAME = "name"
FILE_INFO_DICT_TAGS = "tags"
FILE_INFO_DICT_SIZE = "size"
FILE_INFO_FILE_TYPE = "type"
FILE_INFO_FILE_MIME = "mime"
FILE_INFO_DICT_NODE = "node"

###################################################################################################
# print to stderr
def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)
    sys.stderr.flush()


###################################################################################################
# convenient boolean argument parsing
def str2bool(v):
    if v.lower() in ('yes', 'true', 't', 'y', '1'):
        return True
    elif v.lower() in ('no', 'false', 'f', 'n', '0'):
        return False
    else:
        raise argparse.ArgumentTypeError('Boolean value expected.')


###################################################################################################
# strip a prefix from the beginning of a string if needed
def remove_prefix(text, prefix):
    if (len(prefix) > 0) and text.startswith(prefix):
        return text[len(prefix) :]
    else:
        return text


###################################################################################################
# open a file and close it, updating its access time
def touch(filename):
    open(filename, 'a').close()
    os.utime(filename, None)


###################################################################################################
# run command with arguments and return its exit code, stdout, and stderr
def check_output_input(*popenargs, **kwargs):

    if 'stdout' in kwargs:
        raise ValueError('stdout argument not allowed, it will be overridden')

    if 'stderr' in kwargs:
        raise ValueError('stderr argument not allowed, it will be overridden')

    if 'input' in kwargs and kwargs['input']:
        if 'stdin' in kwargs:
            raise ValueError('stdin and input arguments may not both be used')
        inputdata = kwargs['input']
        kwargs['stdin'] = PIPE
    else:
        inputdata = None
    kwargs.pop('input', None)

    process = Popen(*popenargs, stdout=PIPE, stderr=PIPE, **kwargs)
    try:
        output, errput = process.communicate(inputdata)
    except:
        process.kill()
        process.wait()
        raise

    retcode = process.poll()

    return retcode, output, errput


###################################################################################################
# run command with arguments and return its exit code and output
def run_process(command, stdout=True, stderr=True, stdin=None, cwd=None, env=None, debug=False):

    retcode = -1
    output = []

    try:
        # run the command
        retcode, cmdout, cmderr = check_output_input(command, input=stdin.encode() if stdin else None, cwd=cwd, env=env)

        # split the output on newlines to return a list
        if stderr and (len(cmderr) > 0):
            output.extend(cmderr.decode(sys.getdefaultencoding()).split('\n'))
        if stdout and (len(cmdout) > 0):
            output.extend(cmdout.decode(sys.getdefaultencoding()).split('\n'))

    except (FileNotFoundError, OSError, IOError) as e:
        if stderr:
            output.append("Command {} not found or unable to execute".format(command))

    if debug:
        eprint(
            "{}{} returned {}: {}".format(
                command, "({})".format(stdin[:80] + bool(stdin[80:]) * '...' if stdin else ""), retcode, output
            )
        )

    return retcode, output


###################################################################################################
class AtomicInt:
    def __init__(self, value=0):
        self.val = RawValue('i', value)
        self.lock = Lock()

    def increment(self):
        with self.lock:
            self.val.value += 1
            return self.val.value

    def decrement(self):
        with self.lock:
            self.val.value -= 1
            return self.val.value

    def value(self):
        with self.lock:
            return self.val.value


###################################################################################################
# split a PCAP filename up into tags
def tags_from_filename(filespec):
    # split tags on these characters
    tagSplitterRe = "[,-/_.]+"
    # tags to ignore explicitly
    regex = re.compile(r'^(\d+|p?cap|dmp|log|bro|zeek|tcpdump|netsniff)$', re.IGNORECASE)
    return list(filter(lambda i: not regex.search(i), map(str.strip, filter(None, re.split(tagSplitterRe, filespec)))))
