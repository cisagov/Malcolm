#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2025 Battelle Energy Alliance, LLC.  All rights reserved.

import contextlib
import enum
import fnmatch
import hashlib
import inspect
import ipaddress
import json
import logging
import mmap
import os
import re
import socket
import string
import subprocess
import sys
import tempfile
import time
from ruamel.yaml import YAML as yaml
import shutil

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

from scripts.malcolm_constants import (
    PGID_DEFAULT,
    PUID_DEFAULT,
    PLATFORM_LINUX,
    PLATFORM_MAC,
    PLATFORM_WINDOWS,
    DATABASE_MODE_ENUMS,
    DATABASE_MODE_LABELS,
)


def DatabaseModeEnumToStr(val):
    return DATABASE_MODE_LABELS[val]


def DatabaseModeStrToEnum(val):
    return DATABASE_MODE_ENUMS[val]


###################################################################################################
# urlencode each character of a string
def aggressive_url_encode(val):
    return "".join("%{0:0>2}".format(format(ord(char), "x")) for char in val)


###################################################################################################
# atomic integer class and context manager
class AtomicInt:
    def __init__(self, value=0):
        self.val = RawValue("i", value)
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
        self.err = err if err else "Invalid value"

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
def get_verbosity_env_var_count(var_name):
    if var_name:
        verbose_env_val = os.getenv(var_name, "")
        verbose_env_val = f"-{'v' * int(verbose_env_val)}" if verbose_env_val.isdigit() else verbose_env_val
        return (
            verbose_env_val.count("v") if verbose_env_val.startswith("-") and set(verbose_env_val[1:]) <= {"v"} else 0
        )
    else:
        return 0


def log_level_is_debug(log_level):
    return log_level <= logging.DEBUG


def set_logging(
    log_level_str,
    flag_level_count,
    logger=None,
    set_traceback_limit=False,
    logfmt='%(asctime)s %(levelname)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
):
    """
    Configures logging based on a log level string or verbosity count.

    Args:
        log_level_str (str): A string like 'debug', 'info', etc. May be None.
        flag_level_count (int): Number of -v flags passed (0–5).
        logger (logging.Logger, optional): If provided, configures this logger
                                           instead of the global root logger.

    Returns:
        int: The final effective logging level (e.g., logging.DEBUG).
    """

    # level-based logging verbosity
    cli_level = None
    if log_level_str:
        cli_level = {
            'CRITICAL': logging.CRITICAL,
            'ERROR': logging.ERROR,
            'WARNING': logging.WARNING,
            'INFO': logging.INFO,
            'DEBUG': logging.DEBUG,
        }.get(log_level_str.strip().upper(), logging.CRITICAL)

    # flag-based logging verbosity
    flag_level = max(logging.NOTSET, min(logging.CRITICAL - (10 * flag_level_count), logging.CRITICAL))

    # final log level: pick more verbose (lower number)
    log_level = min(flag_level, cli_level) if cli_level is not None else flag_level

    # Configure logging
    if logger is None:
        # Set global logging config (root logger)
        logging.basicConfig(
            level=log_level,
            format=logfmt,
            datefmt=datefmt,
        )
    else:
        # Configure a specific logger
        handler = logging.StreamHandler()
        handler.setFormatter(
            logging.Formatter(
                logfmt,
                datefmt=datefmt,
            )
        )
        logger.setLevel(log_level)
        logger.handlers.clear()
        logger.addHandler(handler)
        logger.propagate = False  # Don't double-log to the root logger

    if set_traceback_limit and (log_level > logging.DEBUG):
        sys.tracebacklimit = 0

    return log_level


###################################################################################################
# return the name of the calling function as a string
def get_function_name(depth=0):
    try:
        frame = inspect.currentframe()
        for _ in range(depth + 1):
            if frame is None:
                return None
            frame = frame.f_back
        return frame.f_code.co_name if frame else None
    except Exception:
        return None
    finally:
        del frame


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
    regex = re.compile("|".join(map(re.escape, translation)))
    return regex.sub(lambda match: translation[match.group(0)], text)


###################################################################################################
def decapitalize(s):
    if not s:
        return s
    return s[0].lower() + s[1:]


###################################################################################################
# safe deep get for a dictionary
#
# Example:
#   d = {'meta': {'status': 'OK', 'status_code': 200}}
#   deep_get(d, ['meta', 'status_code'])          # => 200
#   deep_get(d, ['garbage', 'status_code'])       # => None
#   deep_get(d, ['meta', 'garbage'], default='-') # => '-'
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
# Recursively merges 'source' dict into 'destination' dict. Values from 'source' override those
#    in 'destination' at the same path.
def deep_merge(source, destination):
    for key, value in source.items():
        if isinstance(value, dict) and isinstance(destination.get(key), dict):
            destination[key] = deep_merge(value, destination[key])
        else:
            destination[key] = value
    return destination


def deep_merge_in_place(source, destination):
    for key, value in source.items():
        if isinstance(value, dict) and isinstance(destination.get(key), dict):
            deep_merge(value, destination[key])
        else:
            destination[key] = value

###################################################################################################
# recursive dictionary key search
def dictsearch(d, target):
    val = filter(
        None,
        [
            (
                [b]
                if a == target
                else dictsearch(b, target) if isinstance(b, dict) else None
            )
            for a, b in d.items()
        ],
    )
    return [i for b in val for i in b]


###################################################################################################
# print to stderr
def eprint(*args, **kwargs):
    filteredArgs = (
        {k: v for (k, v) in kwargs.items() if k not in ("timestamp", "flush")}
        if isinstance(kwargs, dict)
        else {}
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
    ansiEscape = re.compile(r"(?:\x1B[@-_]|[\x80-\x9F])[0-?]*[ -/]*[@-~]")
    return ansiEscape.sub("", line)


###################################################################################################
def EscapeForCurl(s):
    return s.translate(
        str.maketrans(
            {
                '"': r"\"",
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
            r"\"": '"',
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
OPENSSL_ENC_MAGIC = b"Salted__"
PKCS5_SALT_LEN = 8


def EVP_BytesToKey(
    key_length: int, iv_length: int, md, salt: bytes, data: bytes, count: int = 1
) -> (bytes, bytes):
    assert data
    assert salt == b"" or len(salt) == PKCS5_SALT_LEN

    md_buf = b""
    key = b""
    iv = b""
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
            key, md_buf2 = (
                key + md_buf2[: key_length - len(key)],
                md_buf2[key_length - len(key) :],
            )

        if iv_length > len(iv):
            iv = iv + md_buf2[: iv_length - len(iv)]

    return key, iv


###################################################################################################
# flatten a collection, but don't split strings
def flatten(coll):
    for i in coll:
        if isinstance(i, Iterable) and not isinstance(i, str):
            for subc in flatten(i):
                yield subc
        else:
            yield i


###################################################################################################
# if the object is an iterable, return it, otherwise return a tuple with it as a single element.
# useful if you want to user either a scalar or an array in a loop, etc.
def get_iterable(x):
    if isinstance(x, Iterable) and not isinstance(x, str):
        return x
    else:
        return (x,)

# remove "empty" items from a collection
def remove_falsy(obj):
    if isinstance(obj, dict):
        return {k: v for k, v in ((k, remove_falsy(v)) for k, v in obj.items()) if v}
    elif isinstance(obj, list):
        return [v for v in (remove_falsy(i) for i in obj) if v]
    else:
        return obj if obj else None

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
        if (
            isinstance(value, list)
            or isinstance(value, tuple)
            or isinstance(value, set)
        ):
            for v in value:
                ipaddress.ip_address(v)
        else:
            ipaddress.ip_address(value)
    except Exception:
        result = False
    return result


###################################################################################################
# check a string or list to see if something is a private IP address or subnet
def isprivateip(value):
    result = True
    try:
        if (
            isinstance(value, list)
            or isinstance(value, tuple)
            or isinstance(value, set)
        ):
            for v in value:
                result = result and ipaddress.ip_network(value).is_private
                if not result:
                    break
        else:
            result = ipaddress.ip_network(value).is_private
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
        s.connect(("10.254.254.254", 1))
        ip = s.getsockname()[0]
    except Exception:
        ip = "127.0.0.1"
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
# None otherwise. Also, if attemptLines=True, attempt to handle cases of a file containing
# individual lines of valid JSON.
def LoadFileIfJson(fileHandle, attemptLines=False):
    if fileHandle is not None:

        try:
            result = json.load(fileHandle)
        except ValueError:
            result = None

        if (result is None) and attemptLines:
            fileHandle.seek(0)
            result = []
            for line in fileHandle:
                try:
                    result.append(json.loads(line))
                except ValueError:
                    pass
            if not result:
                result = None

    else:
        result = None

    return result


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
    result = defaultdict(lambda: "")
    if os.path.isfile(curlCfgFileName):
        itemRegEx = re.compile(r"^([^\s:=]+)((\s*[:=]?\s*)(.*))?$")
        with open(curlCfgFileName, "r") as f:
            allLines = [
                x.strip().lstrip("-") for x in f.readlines() if not x.startswith("#")
            ]
        for line in allLines:
            found = itemRegEx.match(line)
            if found is not None:
                key = found.group(1)
                value = UnescapeForCurl(found.group(4).lstrip('"').rstrip('"'))
                if (key == "user") and (":" in value):
                    splitVal = value.split(":", 1)
                    result[key] = splitVal[0]
                    if len(splitVal) > 1:
                        result["password"] = splitVal[1]
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
# "chown -R" a file or directory
def ChownRecursive(path, uid, gid):
    os.chown(path, int(uid), int(gid))
    if os.path.isdir(path):
        for dirpath, dirnames, filenames in os.walk(path, followlinks=False):
            for dname in dirnames:
                os.chown(os.path.join(dirpath, dname), int(uid), int(gid))
            for fname in filenames:
                os.chown(
                    os.path.join(dirpath, fname),
                    int(uid),
                    int(gid),
                    follow_symlinks=False,
                )

###################################################################################################
# recursively delete a directory tree while excluding specific files based on glob-style patterns
def rmtree_except(path, exclude_patterns=None, ignore_errors=False):
    if exclude_patterns is None:
        exclude_patterns = []

    for root, dirs, files in os.walk(path, topdown=False):
        for name in files:
            full_path = os.path.join(root, name)
            if not any(fnmatch.fnmatch(name, pattern) for pattern in exclude_patterns):
                try:
                    os.remove(full_path)
                except Exception:
                    if not ignore_errors:
                        raise

        for name in dirs:
            full_path = os.path.join(root, name)
            try:
                os.rmdir(full_path)
            except OSError:
                pass
            except Exception:
                if not ignore_errors:
                    raise

    try:
        os.rmdir(path)
    except OSError:
        pass
    except Exception:
        if not ignore_errors:
            raise

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
    with open(filename, "rb", buffering=0) as f:
        for n in iter(lambda: f.readinto(mv), 0):
            h.update(mv[:n])
    return h.hexdigest()


###################################################################################################
# nice human-readable file sizes
def sizeof_fmt(num, suffix="B"):
    for unit in ["", "Ki", "Mi", "Gi", "Ti", "Pi", "Ei", "Zi"]:
        if abs(num) < 1024.0:
            return f"{num:3.1f}{unit}{suffix}"
        num /= 1024.0
    return f"{num:.1f}{'Yi'}{suffix}"


##################################################################################################
def str2percent(val):
    """
    Convert a string (which may end with a '%') to an integer percent value.
    The result is clamped between 0 and 100. If val is empty or None, returns 0.
    """
    if not val:
        return 0
    # Remove a trailing '%' if present
    if val.endswith("%"):
        val = val[:-1]
    percent = int(val)
    # Clamp the value between 0 and 100
    return max(min(100, percent), 0)


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


def bool_to_str(v):
    if isinstance(v, bool):
        return "true" if v else "false"
    else:
        return str(v)


def true_or_false_no_quotes(v):
    if isinstance(v, bool):
        return "true" if v else "false"
    else:
        return str(v)


def true_or_false_quotes(v):
    if isinstance(v, bool):
        return "'true'" if v else "'false'"
    else:
        return str(v)


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
    open(filename, "a").close()
    os.utime(filename, None)


###################################################################################################
# append strings to a text file
def append_to_file(filename, value):
    with open(filename, "a") as f:
        if isinstance(value, Iterable) and not isinstance(value, str):
            f.write("\n".join(value))
        else:
            f.write(value)


###################################################################################################
# read the contents of a file, first assuming text (with encoding), optionally falling back to binary
def file_contents(filename, encoding="utf-8", binary_fallback=False):
    if os.path.isfile(filename):
        decodeErr = False

        try:
            with open(filename, "r", encoding=encoding) as f:
                return f.read()
        except (UnicodeDecodeError, AttributeError):
            if binary_fallback:
                decodeErr = True
            else:
                raise

        if decodeErr and binary_fallback:
            with open(filename, "rb") as f:
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
                raise ValueError(f"Boolean value expected (got {v})")
        else:
            raise ValueError(f"Boolean value expected (got {v})")
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
    flat_command = list(flatten(get_iterable(command)))

    try:
        # run the command
        retcode, cmdout, cmderr = check_output_input(
            flat_command,
            input=(stdin.encode() if isinstance(stdin, str) else stdin) if stdin else None,
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
            output.append("Command {} not found or unable to execute".format(flat_command))

    if debug:
        dbgStr = "{}{} returned {}: {}".format(
            flat_command,
            "({})".format(stdin[:80] + bool(stdin[80:]) * '...' if (stdin and isinstance(stdin, str)) else ""),
            retcode,
            output,
        )
        if logger is not None:
            logger.debug(dbgStr)
        else:
            eprint(dbgStr)

    if (retcode != 0) and retry and (retry > 0):
        # sleep then retry
        time.sleep(retrySleepSec)
        return run_process(flat_command, stdout, stderr, stdin, retry - 1, retrySleepSec, cwd, env, debug, logger)
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


# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
def package_is_installed(self, package):
    result = False
    for cmd in self.checkPackageCmds:
        ecode, out = self.run_process(cmd + [package])
        if ecode == 0:
            result = True
            break
    return result


# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
def install_package(self, packages):
    result = False
    pkgs = []

    for package in packages:
        if not self.package_is_installed(package):
            pkgs.append(package)

    if len(pkgs) > 0:
        for cmd in self.installPackageCmds:
            ecode, out = self.run_process(cmd + pkgs, privileged=True)
            if ecode == 0:
                result = True
                break
    else:
        result = True

    return result


def get_malcolm_dir():
    """
    Get the absolute path to the Malcolm installation directory.

    This function is designed to work robustly whether run:
    - directly from the Malcolm directory
    - from another directory
    - with sudo or other elevated privileges

    Returns:
        str: The absolute path to the Malcolm directory
    """
    # First, try using the location of this script
    try:
        # Start with the directory containing this script (malcolm_common.py)
        current_dir = os.path.dirname(os.path.abspath(__file__))

        # Go up one level to the Malcolm root directory if in scripts/
        if os.path.basename(current_dir) == "scripts":
            malcolm_dir = os.path.dirname(current_dir)
        else:
            malcolm_dir = current_dir

        # Verify this is indeed the Malcolm directory by checking for key files/directories
        if (
            os.path.isdir(os.path.join(malcolm_dir, "scripts"))
            and os.path.isdir(os.path.join(malcolm_dir, "config"))
            and os.path.isfile(os.path.join(malcolm_dir, "docker-compose.yml"))
        ):
            return malcolm_dir
    except Exception:
        pass

    # If that didn't work, try using the current working directory
    try:
        cwd = os.getcwd()
        if (
            os.path.isdir(os.path.join(cwd, "scripts"))
            and os.path.isdir(os.path.join(cwd, "config"))
            and os.path.isfile(os.path.join(cwd, "docker-compose.yml"))
        ):
            return cwd
    except Exception:
        pass

    # If we're running the script directly, try using its location
    try:
        script_path = os.path.abspath(sys.argv[0])
        script_dir = os.path.dirname(script_path)

        # Check if we're running from the scripts directory
        if os.path.basename(script_dir) == "scripts":
            possible_malcolm_dir = os.path.dirname(script_dir)
            if os.path.isdir(
                os.path.join(possible_malcolm_dir, "config")
            ) and os.path.isfile(
                os.path.join(possible_malcolm_dir, "docker-compose.yml")
            ):
                return possible_malcolm_dir
    except Exception:
        pass

    # If all else fails, check if there's an environment variable set
    if "MALCOLM_DIR" in os.environ:
        malcolm_dir = os.environ["MALCOLM_DIR"]
        if (
            os.path.isdir(malcolm_dir)
            and os.path.isdir(os.path.join(malcolm_dir, "scripts"))
            and os.path.isdir(os.path.join(malcolm_dir, "config"))
        ):
            return malcolm_dir

    # If we still can't find it, raise an exception
    raise FileNotFoundError(
        "Could not locate the Malcolm directory. Please run this script from within "
        "the Malcolm directory or set the MALCOLM_DIR environment variable."
    )


def clear_screen() -> None:
    """Clear the terminal screen in a cross-platform way."""
    # Clear screen command for different operating systems
    if os.name == "nt":  # Windows
        os.system("cls")
    else:  # Unix/Linux/MacOS
        os.system("clear")


def get_default_config_dir():
    """Get the default config directory."""
    return os.path.join(get_malcolm_dir(), "config")


def get_scripts_dir():
    """Get the scripts directory."""
    return os.path.join(get_malcolm_dir(), "scripts")


def get_installer_dir():
    """Get the installer_gui directory."""
    return os.path.join(get_scripts_dir(), "installer")


def get_installer_config_dir():
    """Get the installer_config directory."""
    return os.path.join(get_installer_dir(), "configs")


def get_installer_core_dir():
    """Get the installer_core directory."""
    return os.path.join(get_installer_dir(), "core")


def get_installer_gui_dir():
    """Get the installer_gui directory."""
    return os.path.join(get_installer_dir(), "gui")


def get_installer_platforms_dir():
    """Get the installer_platforms directory."""
    return os.path.join(get_installer_dir(), "platforms")


def get_installer_config_constants_dir():
    """Get the installer_config_constants directory."""
    return os.path.join(get_installer_config_dir(), "constants")


def get_installer_config_items_dir():
    """Get the installer_config_items directory."""
    return os.path.join(get_installer_config_dir(), "configuration_items")


def get_installer_installation_items_dir():
    """Get the installer_installation_items directory."""
    return os.path.join(get_installer_config_dir(), "installation_items")


def get_config_file_version():
    """Get the Malcolm version from _config.yml.

    Returns:
        str: The Malcolm version string, or "unknown" if not found
    """
    # config_file_path = os.path.join(get_malcolm_dir(), "_config.yml")
    # with open(config_file_path, "r") as f:
    #     tmpYaml = yaml(typ="safe")
    #     config_data = tmpYaml.load(config_file_path)
    # return config_data.get("malcolm", {}).get("version", "unknown")
    return "unknown"


###################################################################################################
# System-information helpers (used by installer logic)


def _total_memory_bytes() -> int:
    """Return total physical memory in bytes (Linux/BSD portable)."""
    try:
        if sys.platform == "linux" or sys.platform == "linux2":
            with open("/proc/meminfo", "r", encoding="utf-8") as meminfo:
                for line in meminfo:
                    if line.startswith("MemTotal:"):
                        # value is in kB
                        return int(line.split()[1]) * 1024
        # Fallback that works on many *nix via sysconf
        if hasattr(os, "sysconf"):
            pages = os.sysconf("SC_PHYS_PAGES")
            page_size = os.sysconf("SC_PAGE_SIZE")
            return pages * page_size
    except (OSError, ValueError, FileNotFoundError):
        pass
    return 0  # Unknown


def total_memory_gb() -> int:
    """Return total memory in whole GiB (rounded down)."""
    return max(1, _total_memory_bytes() // (1024**3))


def cpu_cores() -> int:
    """Return logical CPU count, falling back to 1."""
    return max(1, os.cpu_count() or 1)


def disk_free_bytes(path: str = "/") -> int:
    """Return free bytes on the filesystem that contains *path*."""
    try:
        return shutil.disk_usage(path).free
    except (OSError, FileNotFoundError):
        return 0


# ------------------------------------------------------------------
# Heuristic defaults the legacy installer used
# ------------------------------------------------------------------


def determine_uid_gid(
    scriptUser,
    scriptPlatform,
    referencePath,
):
    defaultUid = PUID_DEFAULT
    defaultGid = PGID_DEFAULT
    if ((scriptPlatform == PLATFORM_LINUX) or (scriptPlatform == PLATFORM_MAC)) and (
        scriptUser == "root"
    ):
        if pathUid := os.stat(referencePath).st_uid:
            defaultUid = str(pathUid)
        if pathGid := os.stat(referencePath).st_gid:
            defaultGid = str(pathGid)

    uid = defaultUid
    gid = defaultGid
    try:
        if scriptPlatform == PLATFORM_LINUX:
            uid = str(os.getuid())
            gid = str(os.getgid())
            if (uid == "0") or (gid == "0"):
                raise Exception(
                    "it is preferrable not to run Malcolm as root, prompting for UID/GID instead"
                )
    except Exception:
        uid = defaultUid
        gid = defaultGid

    return uid, gid


def suggest_os_memory(total_gb: int | None = None) -> str:
    """Return OpenSearch heap suggestion (e.g., "24g")."""
    if total_gb is None:
        total_gb = total_memory_gb()
    # Legacy rule: half of RAM, capped at 24 GiB, min 2 GiB
    heap_gb = max(2, min(24, total_gb // 2))
    return f"{heap_gb}g"


def suggest_ls_memory(total_gb: int | None = None) -> str:
    """Return Logstash heap suggestion (e.g., "3g")."""
    if total_gb is None:
        total_gb = total_memory_gb()
    # Rough rule: 1/8th of RAM, capped at 8 GiB, min 1 GiB, rounded.
    heap_gb = max(1, min(8, max(1, total_gb // 8)))
    return f"{heap_gb}g"


def suggest_ls_workers(cores: int | None = None) -> int:
    """Return recommended Logstash worker count."""
    if cores is None:
        cores = cpu_cores()
    # Legacy rule: half the logical cores, capped at 6, min 1
    return max(1, min(6, cores // 2))


# ------------------------------------------------------------------
# Snapshot the system facts at import-time so they're reusable anywhere.
# ------------------------------------------------------------------

import platform as _platform


def get_hostname_without_domain():
    return os.getenv("HOSTNAME", os.getenv("COMPUTERNAME", _platform.node())).split(
        "."
    )[0]


# Gather UID/GID suggestion first
try:
    _rec_uid_str, _rec_gid_str = determine_uid_gid(
        os.getenv("USER", "root"),
        _platform.system(),
        os.getcwd(),
    )
    _rec_uid, _rec_gid = int(_rec_uid_str), int(_rec_gid_str)
except Exception:
    _rec_uid, _rec_gid = 1000, 1000


# Detect system architecture for container images
def get_system_image_architecture():
    """Detect system architecture and return appropriate ImageArchitecture enum."""
    from scripts.malcolm_constants import ImageArchitecture

    raw_platform = _platform.machine().lower()
    if raw_platform in ("aarch64", "arm64"):
        return ImageArchitecture.ARM64
    else:
        return ImageArchitecture.AMD64


# Platform detection utilities
def GetPlatformOSRelease():
    try:
        return _platform.freedesktop_os_release().get("VARIANT_ID", None)
    except Exception:
        return None


def get_platform_name() -> str:
    """Determine the current host platform name.

    Returns:
        Platform name string: 'linux', 'macos', 'windows', or 'unknown'
    """
    # first attempt: original logic (may return distro like "ubuntu" or None)
    system = GetPlatformOSRelease()

    # final fallback: use kernel platform
    if not system:
        system = _platform.system()

    # map many distro strings to the generic categories
    normalized = (system or "").lower()
    linux_aliases = {
        "linux",
        "ubuntu",
        "debian",
        "centos",
        "fedora",
        "rhel",
        "arch",
        "manjaro",
        "opensuse",
        "alpine",
        "linuxmint",
        "mint",
    }
    mac_aliases = {"darwin", "mac", "macos", "osx"}
    windows_aliases = {"windows", "win32", "cygwin", "msys"}

    if normalized in linux_aliases:
        return "linux"
    elif normalized in mac_aliases:
        return "macos"
    elif normalized in windows_aliases:
        return "windows"
    else:
        return "unknown"


# Snapshot of system facts and derived recommendations
SYSTEM_INFO: dict[str, object] = {
    "total_mem_gb": total_memory_gb(),
    "cpu_cores": cpu_cores(),
    "uid": os.getuid(),
    "gid": os.getgid(),
    "recommended_nonroot_uid": _rec_uid,
    "recommended_nonroot_gid": _rec_gid,
    "platform": _platform.system(),
    "platform_name": get_platform_name(),
    "image_architecture": get_system_image_architecture(),
}

# Derived recommendations appended to dict
SYSTEM_INFO["suggested_os_memory"] = suggest_os_memory(SYSTEM_INFO["total_mem_gb"])
SYSTEM_INFO["suggested_ls_memory"] = suggest_ls_memory(SYSTEM_INFO["total_mem_gb"])
SYSTEM_INFO["suggested_ls_workers"] = suggest_ls_workers(SYSTEM_INFO["cpu_cores"])

__all__ = [
    "SYSTEM_INFO",
    "get_platform_name",
    "total_memory_gb",
    "cpu_cores",
    "disk_free_bytes",
    "suggest_os_memory",
    "suggest_ls_memory",
    "suggest_ls_workers",
]
