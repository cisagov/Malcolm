#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2023 Battelle Energy Alliance, LLC.  All rights reserved.

import argparse
import ipaddress
import json
import os
import socket
import ssl
import sys
import urllib.request
import subprocess

from base64 import b64encode
from bs4 import BeautifulSoup
from bs4.element import Comment
from http.client import HTTPSConnection, HTTPConnection
from subprocess import PIPE, STDOUT, Popen, CalledProcessError

from malcolm_utils import run_subprocess

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
# determine a list of available (non-virtual) adapters (Iface's)
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
        retCode, _ = run_subprocess(
            f"/sbin/ethtool --identify {adapter} {duration}", stdout=False, stderr=False, timeout=duration * 2
        )
        return retCode == 0
