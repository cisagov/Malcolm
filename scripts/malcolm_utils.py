#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2025 Battelle Energy Alliance, LLC.  All rights reserved.

import contextlib
import fnmatch
import functools
import glob
import hashlib
import inspect
import ipaddress
import json
import logging
import mmap
import os
import platform
import re
import socket
import stat
import string
import subprocess
import sys
import time
import textwrap
import types

from base64 import b64encode, b64decode, binascii
from dataclasses import dataclass
from datetime import datetime
from multiprocessing import RawValue
from shutil import move as sh_move, which as sh_which, copyfile as sh_copyfile
from subprocess import PIPE, Popen
from tempfile import NamedTemporaryFile, TemporaryDirectory
from threading import Lock
from typing import Optional

try:
    from collections.abc import Iterable
except ImportError:
    from collections import Iterable
from collections import defaultdict, OrderedDict

# Dynamically create a module named "scripts" which points to this directory
if "scripts" not in sys.modules:
    scripts_module = types.ModuleType("scripts")
    scripts_module.__path__ = [os.path.dirname(os.path.abspath(__file__))]
    sys.modules["scripts"] = scripts_module

from scripts.malcolm_constants import (
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


def base64_encode_files_in_dir(directory, pattern):
    """
    Return a dict mapping relative file paths to Base64-encoded contents
    for all files in the given directory (recursively) matching the glob pattern.
    Example:
        /tmp/foobar/app.env           -> "app.env"
        /tmp/foobar/barbaz/what.env   -> "barbaz/what.env"
    """
    result = {}
    # Enable recursive search with **
    search_pattern = os.path.join(directory, "**", pattern)
    for filepath in glob.glob(search_pattern, recursive=True):
        if os.path.isfile(filepath):
            with open(filepath, "rb") as f:
                encoded = b64encode(f.read()).decode("utf-8")
            rel_path = os.path.relpath(filepath, directory)
            result[rel_path] = encoded
    return result


def base64_decode_files_to_dir(encoded_dict, dest_dir):
    """
    Given a dict mapping relative paths to Base64-encoded contents,
    recreate the files under dest_dir.

    - Creates dest_dir and subdirectories if they don’t exist
    - Skips entries that fail Base64 decoding
    """
    os.makedirs(dest_dir, exist_ok=True)

    for rel_path, b64data in encoded_dict.items():
        try:
            decoded = b64decode(b64data, validate=True)
        except (binascii.Error, ValueError):
            continue

        full_path = os.path.join(dest_dir, rel_path)
        os.makedirs(os.path.dirname(full_path), exist_ok=True)

        try:
            with open(full_path, "wb") as f:
                f.write(decoded)
        except Exception:
            continue


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
# determine a list of available (non-virtual) adapters (Iface's)
@dataclass
class NetworkInterface:
    name: str = ''
    description: str = ''


def get_available_adapters():
    available_adapters = []
    _, all_iface_list = run_subprocess("find /sys/class/net/ -mindepth 1 -maxdepth 1 -type l -printf '%P %l\\n'")
    available_iface_list = [x.split(" ", 1)[0] for x in all_iface_list if 'virtual' not in x]

    # for each adapter, determine its MAC address and link speed
    for adapter in available_iface_list:
        mac_address = '??:??:??:??:??:??'
        speed = '?'
        try:
            with open(f"/sys/class/net/{adapter}/address", 'r') as f:
                mac_address = f.readline().strip()
        except Exception:
            pass
        try:
            with open(f"/sys/class/net/{adapter}/speed", 'r') as f:
                speed = f.readline().strip()
        except Exception:
            pass
        description = f"{mac_address} ({speed} Mbits/sec)"
        iface = NetworkInterface(name=adapter, description=description)
        available_adapters.append(iface)

    return available_adapters


###################################################################################################
# identify the specified adapter using ethtool --identify
def identify_adapter(adapter, duration=10, background=False):
    if background:
        subprocess.Popen(
            ["/sbin/ethtool", "--identify", adapter, str(duration)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return True
    else:
        retCode, _ = run_subprocess(
            f"/sbin/ethtool --identify {adapter} {duration}", stdout=False, stderr=False, timeout=duration * 2
        )
        return retCode == 0


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
        [[b] if a == target else dictsearch(b, target) if isinstance(b, dict) else None for a, b in d.items()],
    )
    return [i for b in val for i in b]


###################################################################################################
# given a dict, return the first value sorted by value
def min_hash_value_by_value(x):
    return next(
        iter(list({k: v for k, v in sorted(x.items(), key=lambda item: item[1])}.values())),
        None,
    )


###################################################################################################
# given a dict, return the first value sorted by key
def min_hash_value_by_key(x):
    return next(
        iter(list({k: v for k, v in sorted(x.items(), key=lambda item: item[0])}.values())),
        None,
    )


###################################################################################################
# given a dict, return the last value sorted by value
def max_hash_value_by_value(x):
    try:
        *_, last = iter(list({k: v for k, v in sorted(x.items(), key=lambda item: item[1])}.values()))
    except Exception:
        last = None
    return last


###################################################################################################
# given a dict, return the last value sorted by key
def max_hash_value_by_key(x):
    try:
        *_, last = iter(list({k: v for k, v in sorted(x.items(), key=lambda item: item[0])}.values()))
    except Exception:
        last = None
    return last


###################################################################################################
# print to stderr
def eprint(*args, **kwargs):
    filteredArgs = (
        {k: v for (k, v) in kwargs.items() if k not in ("timestamp", "flush")} if isinstance(kwargs, dict) else {}
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
OPENSSL_ENC_MAGIC = b"Salted__"
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


def openssl_self_signed_keygen(
    openssl=None,
    outdir=None,
    existing_ca_key=None,
    existing_ca_crt=None,
    ca_prefix="ca",
    server_prefix="server",
    client_prefix="client",
    dhparam_prefix=None,
    dhparam_bits=2048,
    clients=0,
    country="US",
    state="ID",
    org="malcolm",
    genrsa_bits=4096,
    days=3650,
    temp_dir=None,
    debug=False,
):
    result = None

    if not (isinstance(openssl, str) and os.path.isfile(openssl)):
        openssl = 'openssl' if which('openssl', debug=debug) else None

    ca_prefix = ca_prefix or 'nosave_ca'
    server_prefix = server_prefix or 'nosave_server'
    client_prefix = client_prefix or 'nosave_client'

    outdir = os.path.abspath(outdir if (isinstance(outdir, str) and os.path.isdir(outdir)) else os.getcwd())
    genrsa_bits = str(genrsa_bits)
    dhparam_bits = str(dhparam_bits)
    days = str(days)

    if openssl:
        with TemporaryDirectory(dir=temp_dir) as temp_cert_dir:
            with pushd(temp_cert_dir):
                result_files = []

                # -----------------------------------------------
                # generate new ca/server/client certificates/keys

                # dhparam --------------------------
                if dhparam_prefix:
                    err, out = run_process(
                        [openssl, 'dhparam', '-out', f'{dhparam_prefix}.pem', dhparam_bits],
                        stderr=True,
                        debug=debug,
                    )
                    if err == 0:
                        result_files.append(f'{dhparam_prefix}.pem')
                    else:
                        raise Exception(f'Unable to generate dhparam.pem file: {out}')

                # ca -------------------------------
                if not (
                    existing_ca_key
                    and existing_ca_crt
                    and all(os.path.isfile(x) for x in (existing_ca_key, existing_ca_crt))
                ):
                    existing_ca_key = existing_ca_crt = None

                if existing_ca_key and existing_ca_crt:
                    sh_copyfile(existing_ca_key, f'{ca_prefix}.key')
                    sh_copyfile(existing_ca_crt, f'{ca_prefix}.crt')

                else:
                    err, out = run_process(
                        [openssl, 'genrsa', '-out', f'{ca_prefix}.key', genrsa_bits],
                        stderr=True,
                        debug=debug,
                    )
                    if err == 0:
                        result_files.append(f'{ca_prefix}.key')
                    else:
                        raise Exception(f'Unable to generate {ca_prefix}.key: {out}')

                    err, out = run_process(
                        [
                            openssl,
                            'req',
                            '-x509',
                            '-new',
                            '-nodes',
                            '-key',
                            f'{ca_prefix}.key',
                            '-sha256',
                            '-days',
                            days,
                            '-subj',
                            f'/C={country}/ST={state}/O={org}/OU=ca',
                            '-out',
                            f'{ca_prefix}.crt',
                        ],
                        stderr=True,
                        debug=debug,
                    )
                    if err == 0:
                        result_files.append(f'{ca_prefix}.crt')
                    else:
                        raise Exception(f'Unable to generate {ca_prefix}.crt: {out}')

                conf_contents = """\
                [req]
                distinguished_name = req_distinguished_name
                req_extensions = v3_req
                prompt = no

                [req_distinguished_name]
                countryName                     = {country}
                stateOrProvinceName             = {state}
                organizationName                = {org}
                organizationalUnitName          = {prefix}

                [ usr_cert ]
                basicConstraints = CA:FALSE
                nsCertType = client, server
                nsComment = "{prefix} Certificate"
                subjectKeyIdentifier = hash
                authorityKeyIdentifier = keyid,issuer:always
                keyUsage = critical, digitalSignature, keyEncipherment, keyAgreement, nonRepudiation
                extendedKeyUsage = serverAuth, clientAuth

                [v3_req]
                keyUsage = keyEncipherment, dataEncipherment
                extendedKeyUsage = serverAuth, clientAuth
                """
                server_conf_contents = textwrap.dedent(conf_contents).format(
                    country=country, state=state, org=org, prefix=server_prefix
                )
                client_conf_contents = textwrap.dedent(conf_contents).format(
                    country=country, state=state, org=org, prefix=client_prefix
                )

                with NamedTemporaryFile(mode='w', dir=temp_cert_dir, encoding="utf-8", delete=False) as f:
                    f.write(server_conf_contents)
                    server_conf_path = f.name
                with NamedTemporaryFile(mode='w', dir=temp_cert_dir, encoding="utf-8", delete=False) as f:
                    f.write(client_conf_contents)
                    client_conf_path = f.name

                # server -------------------------------
                err, out = run_process(
                    [openssl, 'genrsa', '-out', f'{server_prefix}.key', genrsa_bits],
                    stderr=True,
                    debug=debug,
                )
                if err != 0:
                    raise Exception(f'Unable to generate {server_prefix}.key: {out}')

                err, out = run_process(
                    [
                        openssl,
                        'req',
                        '-sha512',
                        '-new',
                        '-key',
                        f'{server_prefix}.key',
                        '-out',
                        f'{server_prefix}.csr',
                        '-config',
                        server_conf_path,
                    ],
                    stderr=True,
                    debug=debug,
                )
                if err != 0:
                    raise Exception(f'Unable to generate {server_prefix}.csr: {out}')

                err, out = run_process(
                    [
                        openssl,
                        'x509',
                        '-days',
                        days,
                        '-req',
                        '-sha512',
                        '-in',
                        f'{server_prefix}.csr',
                        '-CAcreateserial',
                        '-CA',
                        f'{ca_prefix}.crt',
                        '-CAkey',
                        f'{ca_prefix}.key',
                        '-out',
                        f'{server_prefix}.crt',
                        '-extensions',
                        'v3_req',
                        '-extfile',
                        server_conf_path,
                    ],
                    stderr=True,
                    debug=debug,
                )
                if err == 0:
                    result_files.append(
                        f'{server_prefix}.crt',
                    )
                else:
                    raise Exception(f'Unable to generate {server_prefix}.crt: {out}')

                sh_move(f"{server_prefix}.key", f"{server_prefix}.key.pem")
                err, out = run_process(
                    [
                        openssl,
                        'pkcs8',
                        '-in',
                        f'{server_prefix}.key.pem',
                        '-topk8',
                        '-nocrypt',
                        '-out',
                        f'{server_prefix}.key',
                    ],
                    stderr=True,
                    debug=debug,
                )
                if err == 0:
                    result_files.append(f'{server_prefix}.key')
                else:
                    raise Exception(f'Unable to generate {server_prefix}.key: {out}')

                # client ---------------------------
                for i in range(1, clients + 1):
                    tmp_client_prefix = (
                        (client_prefix + "_" + "{:0>{}}".format(i, len(str(clients)))) if clients > 1 else client_prefix
                    )
                    err, out = run_process(
                        [openssl, 'genrsa', '-out', f'{tmp_client_prefix}.key', genrsa_bits],
                        stderr=True,
                        debug=debug,
                    )
                    if err == 0:
                        result_files.append(f'{tmp_client_prefix}.key')
                    else:
                        raise Exception(f'Unable to generate {tmp_client_prefix}.key: {out}')

                    err, out = run_process(
                        [
                            openssl,
                            'req',
                            '-sha512',
                            '-new',
                            '-key',
                            f'{tmp_client_prefix}.key',
                            '-out',
                            f'{tmp_client_prefix}.csr',
                            '-config',
                            client_conf_path,
                        ],
                        stderr=True,
                        debug=debug,
                    )
                    if err != 0:
                        raise Exception(f'Unable to generate {tmp_client_prefix}.csr: {out}')

                    err, out = run_process(
                        [
                            openssl,
                            'x509',
                            '-days',
                            days,
                            '-req',
                            '-sha512',
                            '-in',
                            f'{tmp_client_prefix}.csr',
                            '-CAcreateserial',
                            '-CA',
                            f'{ca_prefix}.crt',
                            '-CAkey',
                            f'{ca_prefix}.key',
                            '-out',
                            f'{tmp_client_prefix}.crt',
                            '-extensions',
                            'usr_cert',
                            '-extfile',
                            client_conf_path,
                        ],
                        stderr=True,
                        debug=debug,
                    )
                    if err == 0:
                        result_files.append(f'{tmp_client_prefix}.crt')
                    else:
                        raise Exception(f'Unable to generate {tmp_client_prefix}.crt: {out}')

                for fname in [x for x in result_files if not x.startswith('nosave')]:
                    if fname.endswith('.crt'):
                        os.chmod(fname, stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH)  # 644
                    elif fname.endswith('.key'):
                        os.chmod(fname, stat.S_IRUSR | stat.S_IWUSR)  # 600
                    sh_move(fname, os.path.join(outdir, fname))
                result = [os.path.join(outdir, fname) for fname in result_files if not fname.startswith('nosave')]

    return result


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
        if isinstance(value, list) or isinstance(value, tuple) or isinstance(value, set):
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
        if isinstance(value, list) or isinstance(value, tuple) or isinstance(value, set):
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
# return the first part of the system's hostname
def get_hostname_without_domain():
    return os.getenv("HOSTNAME", os.getenv("COMPUTERNAME", platform.node())).split(".")[0]


###################################################################################################
# attempt to decode a string as JSON, returning the object if it decodes and None otherwise
def LoadStrIfJson(jsonStr, default=None):
    try:
        return json.loads(jsonStr)
    except ValueError:
        return default


###################################################################################################
# attempt to decode a file (given by handle) as JSON, returning the object if it decodes and
# None otherwise. Also, if attemptLines=True, attempt to handle cases of a file containing
# individual lines of valid JSON.
def LoadFileIfJson(fileHandle, attemptLines=False, default=None):
    if fileHandle is not None:

        try:
            result = json.load(fileHandle)
        except ValueError:
            result = None

        if result is None:
            if attemptLines:
                fileHandle.seek(0)
                result = []
                for line in fileHandle:
                    try:
                        result.append(json.loads(line))
                    except ValueError:
                        pass
                if not result:
                    result = default
            else:
                result = default

    else:
        result = default

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
            allLines = [x.strip().lstrip("-") for x in f.readlines() if not x.startswith("#")]
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
        elif v.lower() in ("no", "false", "f", "n", "0", ""):
            return False
        else:
            raise ValueError("Boolean value expected")
    elif not v:
        return False
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
        f = NamedTemporaryFile(suffix=suffix, delete=False)
        tmp_name = f.name
        f.close()
        yield tmp_name
    finally:
        os.unlink(tmp_name)


###################################################################################################
# Returns the raw underlying function behind a method, classmethod, staticmethod, or functools.partial/wrapped method.
def unwrap_method(method):

    # Handle classmethod / staticmethod
    if isinstance(method, (classmethod, staticmethod)):
        method = method.__func__

    # Unwrap functools.partial, wraps, etc.
    while hasattr(method, "__wrapped__"):
        method = method.__wrapped__

    # functools.partialmethod stores the underlying function in `func`
    if isinstance(method, functools.partial):
        method = method.func

    return method


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


def get_main_script_path() -> Optional[str]:
    """
    Return the absolute path to the original top-level Python script
    that started execution (the "main" script), handling various
    invocation methods and packaging scenarios.
    Returns None if no script path can be determined (e.g. interactive shell).
    """
    import __main__

    # Case 1: Frozen app (PyInstaller, cx_Freeze, etc.)
    if getattr(sys, 'frozen', False):
        return os.path.abspath(sys.executable)

    # Case 2: Normal script or module invocation
    if hasattr(__main__, "__file__"):
        return os.path.abspath(__main__.__file__)

    # Case 3: sys.argv[0] fallback (covers direct + relative execution)
    argv0 = sys.argv[0]
    if argv0:
        if not os.path.isabs(argv0):
            resolved = sh_which(argv0)
            if resolved:
                return os.path.abspath(resolved)
        return os.path.abspath(argv0)

    # Case 4: Interactive shell or embedded Python
    return None


def get_main_script_dir() -> Optional[str]:
    if mpath := get_main_script_path():
        return os.path.dirname(os.path.abspath(mpath))
    return None


###################################################################################################
# different methods for getting line counts of text files


# run "wc -l" in a subprocess on many files (fastest for large numbers of files)
def count_lines_wc_batch(file_paths):
    if file_paths:
        try:
            result = subprocess.run(["wc", "-l"] + file_paths, capture_output=True, text=True, check=True)
            return [
                (file, int(count))
                for line in result.stdout.strip().split("\n")
                if (count := line.split(maxsplit=1)[0]) and (file := line.split(maxsplit=1)[1].strip()) != "total"
            ]
        except Exception as e:
            print(f"Error counting lines of {file_paths}: {e}", file=sys.stderr)
            return [(file_path, 0) for file_path in file_paths]
    else:
        return []


# run "wc -l" in a subprocess on a single file (not particularly efficient, but faster than pure python)
def count_lines_wc(file_path):
    try:
        result = subprocess.run(["wc", "-l", file_path], capture_output=True, text=True, check=True)
        return file_path, int(result.stdout.split()[0])
    except Exception as e:
        print(f"Error counting lines of {file_path}: {e}", file=sys.stderr)
        return file_path, 0


# use memory-mapped files and count "\n" (fastest for many small files as it avoids subprocess overhead)
def count_lines_mmap(file_path):
    try:
        if os.path.getsize(file_path):
            with open(file_path, "r") as f:
                return file_path, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ).read().count(b"\n")
        else:
            return file_path, 0
    except Exception as e:
        print(f"Error counting lines of {file_path}: {e}", file=sys.stderr)
        return file_path, 0
