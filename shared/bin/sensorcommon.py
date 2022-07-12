#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2022 Battelle Energy Alliance, LLC.  All rights reserved.

import argparse
import ipaddress
import json
import os
import socket
import ssl
import subprocess
import sys
import urllib.request

from base64 import b64encode
from bs4 import BeautifulSoup
from bs4.element import Comment
from contextlib import closing
from http.client import HTTPSConnection, HTTPConnection
from multiprocessing import RawValue
from threading import Lock

NIC_BLINK_SECONDS = 10

###################################################################################################
class CancelledError(Exception):
    """Raised when user cancels the operation"""

    pass


###################################################################################################
class Iface:
    def __init__(self, name, description):
        self.name = name
        self.description = description


###################################################################################################
# clear the terminal window and exit the script
def clearquit():
    os.system('clear')
    sys.exit(0)


###################################################################################################
# print to stderr
def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)


###################################################################################################
# urlencode each character of a string
def aggressive_url_encode(string):
    return "".join("%{0:0>2}".format(format(ord(char), "x")) for char in string)


###################################################################################################
# strip a prefix from the beginning of a string if needed
def remove_prefix(text, prefix):
    if (len(prefix) > 0) and text.startswith(prefix):
        return text[len(prefix) :]
    else:
        return text


###################################################################################################
# nice human-readable file sizes
def sizeof_fmt(num, suffix='B'):
    for unit in ['', 'Ki', 'Mi', 'Gi', 'Ti', 'Pi', 'Ei', 'Zi']:
        if abs(num) < 1024.0:
            return "%3.1f%s%s" % (num, unit, suffix)
        num /= 1024.0
    return "%.1f%s%s" % (num, 'Yi', suffix)


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
                ip = ipaddress.ip_address(v)
        else:
            ip = ipaddress.ip_address(value)
    except:
        result = False
    return result


###################################################################################################
# execute a shell process returning its exit code and output
def run_process(command, stdout=True, stderr=False, stdin=None, timeout=60):
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


def tag_visible(element):
    if element.parent.name in ['style', 'script', 'head', 'title', 'meta', '[document]']:
        return False
    if isinstance(element, Comment):
        return False
    return True


def text_from_html(body):
    soup = BeautifulSoup(body, 'html.parser')
    texts = soup.findAll(text=True)
    visible_texts = filter(tag_visible, texts)
    return u" ".join(t.strip() for t in visible_texts).splitlines()


###################################################################################################
# test a connection to an HTTP/HTTPS server
def test_connection(
    protocol="http",
    host="127.0.0.1",
    port=80,
    uri="",
    username=None,
    password=None,
    ssl_verify="full",
    user_agent="hedgehog",
):
    status = 400
    message = "Connection error"
    output = []

    if protocol.lower() == "https":
        if ssl_verify.lower() == "full":
            c = HTTPSConnection(host, port=port)
        else:
            c = HTTPSConnection(host, port=port, context=ssl._create_unverified_context())
    elif protocol.lower() == "http":
        c = HTTPConnection(host)
    else:
        c = None

    if c:
        try:
            if username and password:
                c.request(
                    'GET',
                    f'/{uri}',
                    headers={
                        'User-agent': user_agent,
                        'Authorization': 'Basic %s' % b64encode(f"{username}:{password}".encode()).decode("ascii"),
                    },
                )
            else:
                c.request('GET', f'/{uri}', headers={'User-agent': user_agent})
            res = c.getresponse()
            status = res.status
            message = res.reason
            output = text_from_html(res.read())

        except Exception as e:
            if len(output) == 0:
                output = ["Error: {}".format(e)]

    return status, message, output


###################################################################################################
# test if a remote port is open
def check_socket(host, port):
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
        sock.settimeout(10)
        if sock.connect_ex((host, port)) == 0:
            return True
        else:
            return False


###################################################################################################
# determine a list of available (non-virtual) adapters (Iface's)
def get_available_adapters():

    available_adapters = []
    _, all_iface_list = run_process("find /sys/class/net/ -mindepth 1 -maxdepth 1 -type l -printf '%P %l\\n'")
    available_iface_list = [x.split(" ", 1)[0] for x in all_iface_list if 'virtual' not in x]

    # for each adapter, determine its MAC address and link speed
    for adapter in available_iface_list:
        mac_address = '??:??:??:??:??:??'
        speed = '?'
        try:
            with open(f"/sys/class/net/{adapter}/address", 'r') as f:
                mac_address = f.readline().strip()
        except:
            pass
        try:
            with open(f"/sys/class/net/{adapter}/speed", 'r') as f:
                speed = f.readline().strip()
        except:
            pass
        description = f"{mac_address} ({speed} Mbits/sec)"
        iface = Iface(adapter, description)
        available_adapters.append(iface)

    return available_adapters


###################################################################################################
# identify the specified adapter using ethtool --identify
def identify_adapter(adapter, duration=NIC_BLINK_SECONDS, background=False):
    if background:
        subprocess.Popen(
            ["/sbin/ethtool", "--identify", adapter, str(duration)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    else:
        retCode, _ = run_process(
            f"/sbin/ethtool --identify {adapter} {duration}", stdout=False, stderr=False, timeout=duration * 2
        )
        return retCode == 0
