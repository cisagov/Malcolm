#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2023 Battelle Energy Alliance, LLC.  All rights reserved.

import contextlib
import hashlib
import ipaddress
import json
import os
import re
import socket
import string
import subprocess
import sys
import tempfile
import time


from base64 import b64decode
from datetime import datetime
from multiprocessing import RawValue
from subprocess import PIPE, STDOUT, Popen, CalledProcessError
from tempfile import NamedTemporaryFile
from threading import Lock

try:
    from collections.abc import Iterable
except ImportError:
    from collections import Iterable
from collections import defaultdict, namedtuple, OrderedDict


###################################################################################################
# urlencode each character of a string
def aggressive_url_encode(val):
    return "".join("%{0:0>2}".format(format(ord(char), "x")) for char in val)


###################################################################################################
# atomic integer class and context manager
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

    def __enter__(self):
        return self.increment()

    def __exit__(self, type, value, traceback):
        return self.decrement()


###################################################################################################
# increment until we hit a limit, then raise an exception
class CountUntilException:
    def __init__(self, max=100, err=None):
        self.val = 0
        self.max = max
        self.err = err if err else 'Invalid value'

    def increment(self):
        self.val += 1
        if self.val >= self.max:
            raise ValueError(self.err)
        return True


###################################################################################################
# if a string starts with 'base64:', decode it, otherwise return it as-is
def base64_decode_if_prefixed(s: str):
    if s.startswith('base64:'):
        return b64decode(s[7:]).decode('utf-8')
    else:
        return s


###################################################################################################
# test if a remote port is open
def check_socket(host, port):
    with contextlib.closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
        sock.settimeout(10)
        if sock.connect_ex((host, port)) == 0:
            return True
        else:
            return False


###################################################################################################
def contains_whitespace(s):
    return True in [c in s for c in string.whitespace]


###################################################################################################
# an OrderedDict that locks itself and unlocks itself as a context manager
class ContextLockedOrderedDict(OrderedDict):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.lock = Lock()

    def __enter__(self):
        self.lock.acquire()
        return self

    def __exit__(self, type, value, traceback):
        self.lock.release()
        return self


###################################################################################################
def custom_make_translation(text, translation):
    regex = re.compile('|'.join(map(re.escape, translation)))
    return regex.sub(lambda match: translation[match.group(0)], text)


###################################################################################################
# safe deep get for a dictionary
#
# Example:
#   d = {'meta': {'status': 'OK', 'status_code': 200}}
#   DeepGet(d, ['meta', 'status_code'])          # => 200
#   DeepGet(d, ['garbage', 'status_code'])       # => None
#   DeepGet(d, ['meta', 'garbage'], default='-') # => '-'
def deep_get(d, keys, default=None):
    k = get_iterable(keys)
    if d is None:
        return default
    if not keys:
        return d
    return deep_get(d.get(k[0]), k[1:], default)


###################################################################################################
# convenience routine for setting-getting a value into a dictionary
def deep_set(d, keys, value, deleteIfNone=False):
    k = get_iterable(keys)
    for key in k[:-1]:
        if (key not in d) or (not isinstance(d[key], dict)):
            d[key] = dict()
        d = d[key]
    d[k[-1]] = value
    if deleteIfNone and (value is None):
        d.pop(k[-1], None)


###################################################################################################
# recursive dictionary key search
def dictsearch(d, target):
    val = filter(
        None, [[b] if a == target else dictsearch(b, target) if isinstance(b, dict) else None for a, b in d.items()]
    )
    return [i for b in val for i in b]


###################################################################################################
# print to stderr
def eprint(*args, **kwargs):
    filteredArgs = (
        {k: v for (k, v) in kwargs.items() if k not in ('timestamp', 'flush')} if isinstance(kwargs, dict) else {}
    )
    if "timestamp" in kwargs and kwargs["timestamp"]:
        print(
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            *args,
            file=sys.stderr,
            **filteredArgs,
        )
    else:
        print(*args, file=sys.stderr, **filteredArgs)
    if "flush" in kwargs and kwargs["flush"]:
        sys.stderr.flush()


###################################################################################################
def EscapeAnsi(line):
    ansiEscape = re.compile(r'(?:\x1B[@-_]|[\x80-\x9F])[0-?]*[ -/]*[@-~]')
    return ansiEscape.sub('', line)


###################################################################################################
def EscapeForCurl(s):
    return s.translate(
        str.maketrans(
            {
                '"': r'\"',
                "\\": r"\\",
                "\t": r"\t",
                "\n": r"\n",
                "\r": r"\r",
                "\v": r"\v",
            }
        )
    )


def UnescapeForCurl(s):
    return custom_make_translation(
        s,
        {
            r'\"': '"',
            r"\t": "\t",
            r"\n": "\n",
            r"\r": "\r",
            r"\v": "\v",
            r"\\": "\\",
        },
    )


###################################################################################################
# EVP_BytesToKey
#
# reference: https://github.com/openssl/openssl/blob/6f0ac0e2f27d9240516edb9a23b7863e7ad02898/crypto/evp/evp_key.c#L74
#            https://gist.github.com/chrono-meter/d122cbefc6f6248a0af554995f072460
EVP_KEY_SIZE = 32
OPENSSL_ENC_MAGIC = b'Salted__'
PKCS5_SALT_LEN = 8


def EVP_BytesToKey(key_length: int, iv_length: int, md, salt: bytes, data: bytes, count: int = 1) -> (bytes, bytes):
    assert data
    assert salt == b'' or len(salt) == PKCS5_SALT_LEN

    md_buf = b''
    key = b''
    iv = b''
    addmd = 0

    while key_length > len(key) or iv_length > len(iv):
        c = md()
        if addmd:
            c.update(md_buf)
        addmd += 1
        c.update(data)
        c.update(salt)
        md_buf = c.digest()
        for i in range(1, count):
            md_buf = md(md_buf)

        md_buf2 = md_buf

        if key_length > len(key):
            key, md_buf2 = key + md_buf2[: key_length - len(key)], md_buf2[key_length - len(key) :]

        if iv_length > len(iv):
            iv = iv + md_buf2[: iv_length - len(iv)]

    return key, iv


###################################################################################################
# if the object is an iterable, return it, otherwise return a tuple with it as a single element.
# useful if you want to user either a scalar or an array in a loop, etc.
def get_iterable(x):
    if isinstance(x, Iterable) and not isinstance(x, str):
        return x
    else:
        return (x,)


###################################################################################################
# will it float?
def isfloat(value):
    try:
        float(value)
        return True
    except ValueError:
        return False


###################################################################################################
# check a string or list to see if something is a valid IP address
def isipaddress(value):
    result = True
    try:
        if isinstance(value, list) or isinstance(value, tuple) or isinstance(value, set):
            for v in value:
                ipaddress.ip_address(v)
        else:
            ipaddress.ip_address(value)
    except Exception:
        result = False
    return result


###################################################################################################
# return the primary IP (the one with a default route) on the local box
def get_primary_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(0)
    try:
        # this IP doesn't have to be reachable
        s.connect(('10.254.254.254', 1))
        ip = s.getsockname()[0]
    except Exception:
        ip = '127.0.0.1'
    finally:
        s.close()
    return ip


###################################################################################################
# attempt to decode a string as JSON, returning the object if it decodes and None otherwise
def LoadStrIfJson(jsonStr):
    try:
        return json.loads(jsonStr)
    except ValueError:
        return None


###################################################################################################
# attempt to decode a file (given by handle) as JSON, returning the object if it decodes and
# None otherwise
def LoadFileIfJson(fileHandle):
    try:
        return json.load(fileHandle)
    except ValueError:
        return None


###################################################################################################
# parse a curl-formatted config file, with special handling for user:password and URL
# see https://everything.curl.dev/cmdline/configfile
# e.g.:
#
# given .opensearch.primary.curlrc containing:
# -
# user: "sikari:changethis"
# insecure
# -
#
# ParseCurlFile('.opensearch.primary.curlrc') returns:
#   {
#    'user': 'sikari',
#    'password': 'changethis',
#    'insecure': ''
#   }
def ParseCurlFile(curlCfgFileName):
    result = defaultdict(lambda: '')
    if os.path.isfile(curlCfgFileName):
        itemRegEx = re.compile(r'^([^\s:=]+)((\s*[:=]?\s*)(.*))?$')
        with open(curlCfgFileName, 'r') as f:
            allLines = [x.strip().lstrip('-') for x in f.readlines() if not x.startswith('#')]
        for line in allLines:
            found = itemRegEx.match(line)
            if found is not None:
                key = found.group(1)
                value = UnescapeForCurl(found.group(4).lstrip('"').rstrip('"'))
                if (key == 'user') and (':' in value):
                    splitVal = value.split(':', 1)
                    result[key] = splitVal[0]
                    if len(splitVal) > 1:
                        result['password'] = splitVal[1]
                else:
                    result[key] = value

    return result


###################################################################################################
# a context manager for entering a directory and leaving it upon leaving the context
@contextlib.contextmanager
def pushd(directory):
    prevDir = os.getcwd()
    os.chdir(directory)
    try:
        yield
    finally:
        os.chdir(prevDir)


###################################################################################################
# recursively remove empty subfolders
def RemoveEmptyFolders(path, removeRoot=True):
    if not os.path.isdir(path):
        return

    files = os.listdir(path)
    if len(files):
        for f in files:
            fullpath = os.path.join(path, f)
            if os.path.isdir(fullpath):
                RemoveEmptyFolders(fullpath)

    files = os.listdir(path)
    if len(files) == 0 and removeRoot:
        try:
            os.rmdir(path)
        except Exception:
            pass


###################################################################################################
# strip a prefix from the beginning of a string if needed
def remove_prefix(text, prefix):
    if (len(prefix) > 0) and text.startswith(prefix):
        return text[len(prefix) :]
    else:
        return text


###################################################################################################
# strip a suffix from the end of a string if needed
def remove_suffix(text, suffix):
    if (len(suffix) > 0) and text.endswith(suffix):
        return text[: len(text) - len(suffix)]
    else:
        return text


###################################################################################################
# return true if os.path.samefile, also False on exception
def same_file_or_dir(path1, path2):
    try:
        return os.path.samefile(path1, path2)
    except Exception:
        return False


###################################################################################################
# calculate a sha256 hash of a file
def sha256sum(filename):
    h = hashlib.sha256()
    b = bytearray(64 * 1024)
    mv = memoryview(b)
    with open(filename, 'rb', buffering=0) as f:
        for n in iter(lambda: f.readinto(mv), 0):
            h.update(mv[:n])
    return h.hexdigest()


###################################################################################################
# nice human-readable file sizes
def sizeof_fmt(num, suffix='B'):
    for unit in ['', 'Ki', 'Mi', 'Gi', 'Ti', 'Pi', 'Ei', 'Zi']:
        if abs(num) < 1024.0:
            return f"{num:3.1f}{unit}{suffix}"
        num /= 1024.0
    return f"{num:.1f}{'Yi'}{suffix}"


###################################################################################################
# convenient boolean argument parsing
def str2bool(v):
    if isinstance(v, bool):
        return v
    elif isinstance(v, str):
        if v.lower() in ("yes", "true", "t", "y", "1"):
            return True
        elif v.lower() in ("no", "false", "f", "n", "0"):
            return False
        else:
            raise ValueError("Boolean value expected")
    else:
        raise ValueError("Boolean value expected")


###################################################################################################
# tablify
def tablify(matrix, file=sys.stdout):
    colMaxLen = {i: max(map(len, inner)) for i, inner in enumerate(zip(*matrix))}
    for row in matrix:
        for col, data in enumerate(row):
            print(f"{data:{colMaxLen[col]}}", end=" | ", file=file)
        print(file=file)


###################################################################################################
# a context manager returning a temporary filename which is deleted upon leaving the context
@contextlib.contextmanager
def temporary_filename(suffix=None):
    try:
        f = tempfile.NamedTemporaryFile(suffix=suffix, delete=False)
        tmp_name = f.name
        f.close()
        yield tmp_name
    finally:
        os.unlink(tmp_name)


###################################################################################################
# open a file and close it, updating its access time
def touch(filename):
    open(filename, 'a').close()
    os.utime(filename, None)


###################################################################################################
# read the contents of a file, first assuming text (with encoding), optionally falling back to binary
def file_contents(filename, encoding='utf-8', binary_fallback=False):
    if os.path.isfile(filename):
        decodeErr = False

        try:
            with open(filename, 'r', encoding=encoding) as f:
                return f.read()
        except (UnicodeDecodeError, AttributeError):
            if binary_fallback:
                decodeErr = True
            else:
                raise

        if decodeErr and binary_fallback:
            with open(filename, 'rb') as f:
                return f.read()

    else:
        return None


###################################################################################################
def val2bool(v):
    try:
        if v is None:
            return False
        elif isinstance(v, bool):
            return v
        elif isinstance(v, str):
            if v.lower() in ("yes", "true", "t", "y"):
                return True
            elif v.lower() in ("no", "false", "f", "n"):
                return False
            else:
                raise ValueError(f'Boolean value expected (got {v})')
        else:
            raise ValueError(f'Boolean value expected (got {v})')
    except Exception:
        # just pitch it back and let the caller worry about it
        return v


###################################################################################################
# determine if a program/script exists and is executable in the system path
def which(cmd, debug=False):
    result = any(os.access(os.path.join(path, cmd), os.X_OK) for path in os.environ["PATH"].split(os.pathsep))
    if debug:
        eprint(f"which {cmd} returned {result}")
    return result


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
    except Exception:
        process.kill()
        process.wait()
        raise

    retcode = process.poll()

    return retcode, output, errput


###################################################################################################
# run command with arguments and return its exit code and output
def run_process(
    command,
    stdout=True,
    stderr=True,
    stdin=None,
    retry=0,
    retrySleepSec=5,
    cwd=None,
    env=None,
    debug=False,
    logger=None,
):
    retcode = -1
    output = []

    try:
        # run the command
        retcode, cmdout, cmderr = check_output_input(
            command,
            input=stdin.encode() if stdin else None,
            cwd=cwd,
            env=env,
        )

        # split the output on newlines to return a list
        if stderr and (len(cmderr) > 0):
            output.extend(cmderr.decode(sys.getdefaultencoding()).split('\n'))
        if stdout and (len(cmdout) > 0):
            output.extend(cmdout.decode(sys.getdefaultencoding()).split('\n'))

    except (FileNotFoundError, OSError, IOError):
        if stderr:
            output.append("Command {} not found or unable to execute".format(command))

    if debug:
        dbgStr = "{}{} returned {}: {}".format(
            command, "({})".format(stdin[:80] + bool(stdin[80:]) * '...' if stdin else ""), retcode, output
        )
        if logger is not None:
            logger.debug(dbgStr)
        else:
            eprint(dbgStr)

    if (retcode != 0) and retry and (retry > 0):
        # sleep then retry
        time.sleep(retrySleepSec)
        return run_process(command, stdout, stderr, stdin, retry - 1, retrySleepSec, cwd, env, debug, logger)
    else:
        return retcode, output


###################################################################################################
# execute a shell process returning its exit code and output
def run_subprocess(command, stdout=True, stderr=False, stdin=None, timeout=60):
    retcode = -1
    output = []
    p = subprocess.run(
        [command], input=stdin, universal_newlines=True, capture_output=True, shell=True, timeout=timeout
    )
    if p:
        retcode = p.returncode
        if stderr and p.stderr:
            output.extend(p.stderr.splitlines())
        if stdout and p.stdout:
            output.extend(p.stdout.splitlines())

    return retcode, output
