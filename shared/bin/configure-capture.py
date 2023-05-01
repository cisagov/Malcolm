#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2023 Battelle Energy Alliance, LLC.  All rights reserved.

# script for configuring sensor capture and forwarding parameters

import locale
import os
import re
import shutil
import sys
import fileinput
from collections import defaultdict
from dialog import Dialog

from subprocess import PIPE, STDOUT, Popen, CalledProcessError

from zeek_carve_utils import PRESERVE_NONE, PRESERVE_QUARANTINED, PRESERVE_ALL
from sensorcommon import (
    CancelledError,
    clearquit,
    get_available_adapters,
    identify_adapter,
    NIC_BLINK_SECONDS,
    test_connection,
)
from malcolm_utils import run_subprocess, remove_prefix, aggressive_url_encode, isipaddress, check_socket


class Constants:
    CONFIG_CAP = 'Capture Configuration'

    DEV_IDENTIFIER_FILE = '/etc/installer'
    DEV_UNKNOWN = 'unknown'
    DEV_AGGREGATOR = 'aggregator'
    DEV_SENSOR = 'sensor'
    DEV_VALID = {DEV_AGGREGATOR, DEV_SENSOR}
    MSG_ERR_DEV_INVALID = f'Could not determine installation type (not one of {DEV_VALID})'
    MSG_ERR_DEV_INCORRECT = 'This tool is not suitable for configuring {}s'

    SENSOR_CAPTURE_CONFIG = '/opt/sensor/sensor_ctl/control_vars.conf'

    PCAP_CAPTURE_AUTOSTART_ENTRIES = {'AUTOSTART_ARKIME', 'AUTOSTART_NETSNIFF', 'AUTOSTART_TCPDUMP'}

    ZEEK_FILE_CARVING_NONE = 'none'
    ZEEK_FILE_CARVING_ALL = 'all'
    ZEEK_FILE_CARVING_KNOWN = 'known'
    ZEEK_FILE_CARVING_MAPPED = 'mapped'
    ZEEK_FILE_CARVING_MAPPED_MINUS_TEXT = 'mapped (except common plain text files)'
    ZEEK_FILE_CARVING_INTERESTING = 'interesting'
    ZEEK_FILE_CARVING_CUSTOM = 'custom'
    ZEEK_FILE_CARVING_CUSTOM_MIME = 'custom (mime-sorted)'
    ZEEK_FILE_CARVING_CUSTOM_EXT = 'custom (extension-sorted)'
    ZEEK_FILE_CARVING_DEFAULTS = '/opt/zeek/share/zeek/site/extractor_params.zeek'
    ZEEK_FILE_CARVING_OVERRIDE_FILE = '/opt/sensor/sensor_ctl/extractor_override.zeek'
    ZEEK_FILE_CARVING_OVERRIDE_INTERESTING_FILE = '/opt/sensor/sensor_ctl/zeek/extractor_override.interesting.zeek'
    ZEEK_FILE_CARVING_OVERRIDE_FILE_MAP_NAME = 'extractor_mime_to_ext_map'
    ZEEK_FILE_CARVING_PLAIN_TEXT_MIMES = {
        "application/json",
        "application/x-x509-ca-cert",
        "application/xml",
        "text/plain",
        "text/xml",
    }

    FILEBEAT = 'filebeat'
    MISCBEAT = 'miscbeat'
    ARKIMECAP = 'arkime-capture'
    TX_RX_SECURE = 'ssl-client-receive'

    BEAT_DIR = {
        FILEBEAT: f'/opt/sensor/sensor_ctl/{FILEBEAT}',
        MISCBEAT: f'/opt/sensor/sensor_ctl/{MISCBEAT}',
    }

    BEAT_CMD = {
        FILEBEAT: f'{FILEBEAT} --path.home "{BEAT_DIR[FILEBEAT]}" --path.config "{BEAT_DIR[FILEBEAT]}" --path.data "{BEAT_DIR[FILEBEAT]}/data" --path.logs "{BEAT_DIR[FILEBEAT]}/logs" -c "{BEAT_DIR[FILEBEAT]}/{FILEBEAT}.yml"',
        MISCBEAT: f'{FILEBEAT} --path.home "{BEAT_DIR[MISCBEAT]}" --path.config "{BEAT_DIR[MISCBEAT]}" --path.data "{BEAT_DIR[MISCBEAT]}/data" --path.logs "{BEAT_DIR[MISCBEAT]}/logs" -c "{BEAT_DIR[MISCBEAT]}/{FILEBEAT}.yml"',
    }

    # specific to beats forwarded to logstash (eg., filebeat, etc.)
    BEAT_LS_HOST = 'BEAT_LS_HOST'
    BEAT_LS_PORT = 'BEAT_LS_PORT'
    BEAT_LS_SSL = 'BEAT_LS_SSL'
    BEAT_LS_SSL_CA_CRT = 'BEAT_LS_SSL_CA_CRT'
    BEAT_LS_SSL_CLIENT_CRT = 'BEAT_LS_SSL_CLIENT_CRT'
    BEAT_LS_SSL_CLIENT_KEY = 'BEAT_LS_SSL_CLIENT_KEY'
    BEAT_LS_SSL_VERIFY = 'BEAT_LS_SSL_VERIFY'
    BEAT_LS_CERT_DIR_DEFAULT = "/opt/sensor/sensor_ctl/logstash-client-certificates"

    # since the OpenSearch fork from ElasticSearch, we're no longer using beats forwarding directly to OpenSearch

    # however, Arkime does connect directly to opensearch
    BEAT_OS_HOST = "BEAT_OS_HOST"
    BEAT_OS_PORT = "BEAT_OS_PORT"
    BEAT_OS_PROTOCOL = "BEAT_OS_PROTOCOL"
    BEAT_OS_SSL_VERIFY = "BEAT_OS_SSL_VERIFY"
    BEAT_HTTP_PASSWORD = "BEAT_HTTP_PASSWORD"
    BEAT_HTTP_USERNAME = "BEAT_HTTP_USERNAME"

    # specific to filebeat
    BEAT_ZEEK_LOG_PATH_SUBDIR = os.path.join('logs', 'current')
    BEAT_ZEEK_LOG_PATTERN_KEY = 'BEAT_LOG_PATTERN'
    BEAT_STATIC_ZEEK_LOG_PATH_SUBDIR = os.path.join('logs', 'static')
    BEAT_STATIC_ZEEK_LOG_PATTERN_KEY = 'BEAT_STATIC_LOG_PATTERN'
    BEAT_SURICATA_LOG_PATH_SUBDIR = 'suricata'
    BEAT_SURICATA_LOG_PATTERN_KEY = 'BEAT_SURICATA_LOG_PATTERN'
    BEAT_ZEEK_LOG_PATTERN_VAL = '*.log'
    BEAT_SURICATA_LOG_PATTERN_VAL = 'eve*.json'

    # specific to arkime
    ARKIME_PACKET_ACL = "ARKIME_PACKET_ACL"
    ARKIME_COMPRESSION_TYPE = "ARKIME_COMPRESSION_TYPE"
    ARKIME_COMPRESSION_LEVEL = "ARKIME_COMPRESSION_LEVEL"
    ARKIME_COMPRESSION_TYPES = (
        # 'gzip', - gzip has got issues on Hedgehog for some reason
        'none',
        'zstd',
    )
    ARKIME_COMPRESSION_LEVELS = {
        'gzip': (1, 9, 3),
        'zstd': (-5, 19, 3),
    }

    MSG_CONFIG_MODE = 'Configuration Mode'
    MSG_CONFIG_MODE_CAPTURE = 'Configure Capture'
    MSG_CONFIG_MODE_FORWARD = 'Configure Forwarding'
    MSG_CONFIG_MODE_AUTOSTART = 'Configure Autostart Services'
    MSG_CONFIG_GENERIC = 'Configure {}'
    MSG_CONFIG_ARKIME = (f'{ARKIMECAP}', f'Configure Arkime session forwarding via {ARKIMECAP}')
    MSG_CONFIG_ARKIME_COMPRESSION = 'Specify Arkime PCAP compression mode'
    MSG_CONFIG_ARKIME_COMPRESSION_LEVEL = 'Specify Arkime PCAP {} compression level'
    MSG_CONFIG_FILEBEAT = (f'{FILEBEAT}', f'Configure Zeek log forwarding via {FILEBEAT}')
    MSG_CONFIG_MISCBEAT = (f'{MISCBEAT}', f"Configure miscellaneous sensor metrics forwarding via {FILEBEAT}")
    MSG_CONFIG_TXRX = (f'{TX_RX_SECURE}', f'Receive client SSL files for {FILEBEAT} from Malcolm')
    MSG_OVERWRITE_CONFIG = '{} is already configured, overwrite current settings?'
    MSG_IDENTIFY_NICS = 'Do you need help identifying network interfaces?'
    MSG_BACKGROUND_TITLE = 'Sensor Configuration'
    MSG_CONFIG_AUTOSTARTS = 'Specify autostart processes'
    MSG_CONFIG_ZEEK_CARVED_SCANNERS = 'Specify scanners for Zeek-carved files'
    MSG_CONFIG_ZEEK_CARVING = 'Specify Zeek file carving mode'
    MSG_CONFIG_ZEEK_CARVING_MIMES = 'Specify file types to carve'
    MSG_CONFIG_CARVED_FILE_PRESERVATION = 'Specify which carved files to preserve'
    MSG_CONFIG_CAP_CONFIRM = 'Sensor will capture traffic with the following parameters:\n\n{}'
    MSG_CONFIG_AUTOSTART_CONFIRM = 'Sensor autostart the following services:\n\n{}'
    MSG_CONFIG_FORWARDING_CONFIRM = '{} will forward with the following parameters:\n\n{}'
    MSG_CONFIG_CAP_PATHS = 'Provide paths for captured PCAPs and Zeek logs'
    MSG_CONFIG_CAPTURE_SUCCESS = 'Capture interface set to {} in {}.\n\nReboot to apply changes.'
    MSG_CONFIG_AUTOSTART_SUCCESS = 'Autostart services configured.\n\nReboot to apply changes.'
    MSG_CONFIG_FORWARDING_SUCCESS = (
        '{} forwarding configured:\n\n{}\n\nRestart forwarding services or reboot to apply changes.'
    )
    MSG_CONFIG_ARKIME_PCAP_ACL = 'Specify IP addresses for PCAP retrieval ACL (one per line)'
    MSG_ERR_PLEBE_REQUIRED = 'this utility should be be run as non-privileged user'
    MSG_ERROR_DIR_NOT_FOUND = 'One or more of the paths specified does not exist'
    MSG_ERROR_FILE_NOT_FOUND = 'One or more of the files specified does not exist'
    MSG_ERROR_BAD_HOST = 'Invalid host or port'
    MSG_ERROR_FWD_DIR_NOT_FOUND = 'The path {} does not exist, {} cannot be configured'
    MSG_ERROR_MISSING_CAP_CONFIG = f'Capture configuration file {SENSOR_CAPTURE_CONFIG} does not exist'
    MSG_ERROR_KEYSTORE = 'There was an error creating the keystore for {}:\n\n{}'
    MSG_ERROR_FILTER_VALIDATION = (
        "Warning: capture filter failed validation ({}). Adjust filter, or resubmit unchanged to ignore warning."
    )
    MSG_MESSAGE_ERROR = 'Error: {}\n\nPlease try again.'
    MSG_CANCEL_ERROR = 'Operation cancelled, goodbye!'
    MSG_INVALID_FORWARDING_TYPE = "Invalid forwarder selected"
    MSG_EMPTY_CONFIG_ERROR = "No configuration values were supplied"
    MSG_SELECT_INTERFACE = 'Select capture interface(s)'
    MSG_SELECT_BLINK_INTERFACE = 'Select capture interface to identify'
    MSG_BLINK_INTERFACE = '{} will blink for {} seconds'
    MSG_WELCOME_TITLE = 'Welcome to the sensor capture and forwarding configuration utility!'
    MSG_TESTING_CONNECTION = 'Testing {} connection...'
    MSG_TESTING_CONNECTION_SUCCESS = '{} connection succeeded! ({} {})'
    MSG_TESTING_CONNECTION_FAILURE = "{} connection error: {} {}:\n\n {}"
    MSG_TESTING_CONNECTION_FAILURE_LOGSTASH = "{} connection error: could not connect to {}:{}"
    MSG_WARNING_MULTIPLE_PCAP = (
        "Warning: multiple PCAP processes are enabled ({}). Using a single PCAP process is recommended."
    )


# the main dialog window used for the duration of this tool
d = Dialog(dialog='dialog', autowidgetsize=True)
d.set_background_title(Constants.MSG_BACKGROUND_TITLE)


###################################################################################################
def mime_to_extension_mappings(mapfile):
    # get all mime-to-extension mappings from our mapping zeek file into a dictionary
    mime_maps = defaultdict(str)

    if os.path.exists(mapfile):
        maps_list = []
        with open(mapfile) as f:
            maps_list = [
                x.replace(' ', '')
                for x in re.findall(
                    r'(\[\s*"[A-Za-z0-9/\.\+_-]+"\s*\]\s*=\s*"[A-Za-z0-9\.\+_-]+")', f.read(), re.MULTILINE
                )
            ]
        mime_map_re = re.compile(r'\[\s*"([A-Za-z0-9/\.\+_-]+)"\s*\]\s*=\s*"([A-Za-z0-9\.\+_-]+)"')
        for mime_map in maps_list:
            match = mime_map_re.search(mime_map)
            if match:
                mime_maps[match.group(1)] = match.group(2)

    return mime_maps


###################################################################################################
def input_opensearch_connection_info(
    forwarder,
    default_os_host=None,
    default_os_port=None,
    default_username=None,
    default_password=None,
):
    return_dict = defaultdict(str)

    # OpenSearch configuration
    # opensearch protocol and SSL verification mode
    opensearch_protocol = "http"
    opensearch_ssl_verify = "none"
    if d.yesno("OpenSearch connection protocol", yes_label="HTTPS", no_label="HTTP") == Dialog.OK:
        opensearch_protocol = "https"
        if d.yesno("OpenSearch SSL verification", yes_label="None", no_label="Full") != Dialog.OK:
            opensearch_ssl_verify = "full"
    return_dict[Constants.BEAT_OS_PROTOCOL] = opensearch_protocol
    return_dict[Constants.BEAT_OS_SSL_VERIFY] = opensearch_ssl_verify

    while True:
        # host/port for OpenSearch
        code, values = d.form(
            Constants.MSG_CONFIG_GENERIC.format(forwarder),
            [
                ('OpenSearch Host', 1, 1, default_os_host or "", 1, 25, 30, 255),
                ('OpenSearch Port', 2, 1, default_os_port or "9200", 2, 25, 6, 5),
            ],
        )
        values = [x.strip() for x in values]

        if (code == Dialog.CANCEL) or (code == Dialog.ESC):
            raise CancelledError

        elif (len(values[0]) <= 0) or (len(values[1]) <= 0) or (not values[1].isnumeric()):
            code = d.msgbox(text=Constants.MSG_ERROR_BAD_HOST)

        else:
            return_dict[Constants.BEAT_OS_HOST] = values[0]
            return_dict[Constants.BEAT_OS_PORT] = values[1]
            break

    # HTTP/HTTPS authentication
    code, http_username = d.inputbox("OpenSearch HTTP/HTTPS server username", init=default_username)
    if (code == Dialog.CANCEL) or (code == Dialog.ESC):
        raise CancelledError
    return_dict[Constants.BEAT_HTTP_USERNAME] = http_username.strip()

    # make them enter the password twice
    while True:
        code, http_password = d.passwordbox(
            "OpenSearch HTTP/HTTPS server password", insecure=True, init=default_password
        )
        if (code == Dialog.CANCEL) or (code == Dialog.ESC):
            raise CancelledError

        code, http_password2 = d.passwordbox(
            "OpenSearch HTTP/HTTPS server password (again)",
            insecure=True,
            init=default_password if (http_password == default_password) else "",
        )
        if (code == Dialog.CANCEL) or (code == Dialog.ESC):
            raise CancelledError

        if http_password == http_password2:
            return_dict[Constants.BEAT_HTTP_PASSWORD] = http_password.strip()
            break
        else:
            code = d.msgbox(text=Constants.MSG_MESSAGE_ERROR.format("Passwords did not match"))

    # test OpenSearch connection
    code = d.infobox(Constants.MSG_TESTING_CONNECTION.format("OpenSearch"))
    retcode, message, output = test_connection(
        protocol=return_dict[Constants.BEAT_OS_PROTOCOL],
        host=return_dict[Constants.BEAT_OS_HOST],
        port=return_dict[Constants.BEAT_OS_PORT],
        username=return_dict[Constants.BEAT_HTTP_USERNAME]
        if (len(return_dict[Constants.BEAT_HTTP_USERNAME]) > 0)
        else None,
        password=return_dict[Constants.BEAT_HTTP_PASSWORD]
        if (len(return_dict[Constants.BEAT_HTTP_PASSWORD]) > 0)
        else None,
        ssl_verify=return_dict[Constants.BEAT_OS_SSL_VERIFY],
    )
    if retcode == 200:
        code = d.msgbox(text=Constants.MSG_TESTING_CONNECTION_SUCCESS.format("OpenSearch", retcode, message))
    else:
        code = d.yesno(
            text=Constants.MSG_TESTING_CONNECTION_FAILURE.format("OpenSearch", retcode, message, "\n".join(output)),
            yes_label="Ignore Error",
            no_label="Start Over",
        )
        if code != Dialog.OK:
            raise CancelledError

    return return_dict


###################################################################################################
###################################################################################################
def main():
    locale.setlocale(locale.LC_ALL, '')

    # make sure we are NOT being run as root
    if os.getuid() == 0:
        print(Constants.MSG_ERR_PLEBE_REQUIRED)
        sys.exit(1)

    # what are we (sensor vs. aggregator)
    installation = Constants.DEV_UNKNOWN
    modeChoices = []
    try:
        with open(Constants.DEV_IDENTIFIER_FILE, 'r') as f:
            installation = f.readline().strip()
    except Exception:
        pass
    if installation not in Constants.DEV_VALID:
        print(Constants.MSG_ERR_DEV_INVALID)
        sys.exit(1)
    elif installation == Constants.DEV_SENSOR:
        modeChoices = [
            (Constants.MSG_CONFIG_MODE_CAPTURE, ""),
            (Constants.MSG_CONFIG_MODE_FORWARD, ""),
            (Constants.MSG_CONFIG_MODE_AUTOSTART, ""),
        ]
    else:
        print(Constants.MSG_ERR_DEV_INCORRECT.format(installation))
        sys.exit(1)

    start_dir = os.getcwd()
    quit_flag = False

    # store previously-entered opensearch values in case they are going through the loop
    # mulitple times to prevent them from having to enter them over and over
    previous_config_values = defaultdict(str)

    while not quit_flag:
        try:
            os.chdir(start_dir)

            if not os.path.isfile(Constants.SENSOR_CAPTURE_CONFIG):
                # SENSOR_CAPTURE_CONFIG file doesn't exist, can't continue
                raise Exception(Constants.MSG_ERROR_MISSING_CAP_CONFIG)

            # read existing configuration from SENSOR_CAPTURE_CONFIG into a dictionary file (not written back out as such, just used
            # as a basis for default values)
            capture_config_dict = defaultdict(str)
            with open(Constants.SENSOR_CAPTURE_CONFIG) as file:
                for line in file:
                    if len(line.strip()) > 0:
                        name, var = remove_prefix(line, "export").partition("=")[::2]
                        capture_config_dict[name.strip()] = var.strip().strip("'").strip('"')
            if (Constants.BEAT_OS_HOST not in previous_config_values.keys()) and (
                "OS_HOST" in capture_config_dict.keys()
            ):
                previous_config_values[Constants.BEAT_OS_HOST] = capture_config_dict["OS_HOST"]
            if (Constants.BEAT_OS_PORT not in previous_config_values.keys()) and (
                "OS_PORT" in capture_config_dict.keys()
            ):
                previous_config_values[Constants.BEAT_OS_PORT] = capture_config_dict["OS_PORT"]
            if (Constants.BEAT_HTTP_USERNAME not in previous_config_values.keys()) and (
                "OS_USERNAME" in capture_config_dict.keys()
            ):
                previous_config_values[Constants.BEAT_HTTP_USERNAME] = capture_config_dict["OS_USERNAME"]
            if (Constants.ARKIME_PACKET_ACL not in previous_config_values.keys()) and (
                "ARKIME_PACKET_ACL" in capture_config_dict.keys()
            ):
                previous_config_values[Constants.ARKIME_PACKET_ACL] = capture_config_dict[Constants.ARKIME_PACKET_ACL]

            code = d.yesno(Constants.MSG_WELCOME_TITLE, yes_label="Continue", no_label="Quit")
            if code == Dialog.CANCEL or code == Dialog.ESC:
                quit_flag = True
                raise CancelledError

            code, mode = d.menu(Constants.MSG_CONFIG_MODE, choices=modeChoices)
            if code != Dialog.OK:
                quit_flag = True
                raise CancelledError

            if mode == Constants.MSG_CONFIG_MODE_AUTOSTART:
                # sensor autostart services configuration #############################################################################################

                while True:
                    # select processes for autostart (except for the file scan ones, handle those with the file scanning stuff)
                    autostart_choices = []
                    for k, v in sorted(capture_config_dict.items()):
                        if k.startswith("AUTOSTART_"):
                            autostart_choices.append((k, '', v.lower() == "true"))
                    code, autostart_tags = d.checklist(Constants.MSG_CONFIG_AUTOSTARTS, choices=autostart_choices)
                    if code == Dialog.CANCEL or code == Dialog.ESC:
                        raise CancelledError

                    for tag in [x[0] for x in autostart_choices]:
                        capture_config_dict[tag] = "false"
                    for tag in autostart_tags:
                        capture_config_dict[tag] = "true"

                    # warn them if we're doing mulitple PCAP capture processes
                    pcap_procs_enabled = [x for x in autostart_tags if x in Constants.PCAP_CAPTURE_AUTOSTART_ENTRIES]
                    if (len(pcap_procs_enabled) <= 1) or (
                        d.yesno(
                            text=Constants.MSG_WARNING_MULTIPLE_PCAP.format(", ".join(pcap_procs_enabled)),
                            yes_label="Continue Anyway",
                            no_label="Adjust Selections",
                        )
                        == Dialog.OK
                    ):
                        break

                # get confirmation from user that we really want to do this
                code = d.yesno(
                    Constants.MSG_CONFIG_AUTOSTART_CONFIRM.format(
                        "\n".join(sorted([f"{k}={v}" for k, v in capture_config_dict.items() if "AUTOSTART" in k]))
                    ),
                    yes_label="OK",
                    no_label="Cancel",
                )
                if code == Dialog.OK:
                    # modify specified values in-place in SENSOR_CAPTURE_CONFIG file
                    autostart_re = re.compile(r"(\bAUTOSTART_\w+)\s*=\s*.+?$")
                    with fileinput.FileInput(Constants.SENSOR_CAPTURE_CONFIG, inplace=True, backup='.bak') as file:
                        for line in file:
                            line = line.rstrip("\n")
                            autostart_match = autostart_re.search(line)
                            if autostart_match is not None:
                                print(autostart_re.sub(r"\1=%s" % capture_config_dict[autostart_match.group(1)], line))
                            else:
                                print(line)

                    # hooray
                    code = d.msgbox(text=Constants.MSG_CONFIG_AUTOSTART_SUCCESS)

            elif mode == Constants.MSG_CONFIG_MODE_CAPTURE:
                # sensor capture configuration ########################################################################################################

                # determine a list of available (non-virtual) adapters
                available_adapters = get_available_adapters()
                # previously used capture interfaces
                preselected_ifaces = set([x.strip() for x in capture_config_dict["CAPTURE_INTERFACE"].split(',')])

                while (len(available_adapters) > 0) and (d.yesno(Constants.MSG_IDENTIFY_NICS) == Dialog.OK):
                    code, blinky_iface = d.radiolist(
                        Constants.MSG_SELECT_BLINK_INTERFACE,
                        choices=[(adapter.name, adapter.description, False) for adapter in available_adapters],
                    )
                    if (code == Dialog.OK) and (len(blinky_iface) > 0):
                        if (
                            d.yesno(
                                Constants.MSG_BLINK_INTERFACE.format(blinky_iface, NIC_BLINK_SECONDS),
                                yes_label="Ready",
                                no_label="Cancel",
                            )
                            == Dialog.OK
                        ):
                            identify_adapter(adapter=blinky_iface, duration=NIC_BLINK_SECONDS, background=True)
                            code = d.pause(
                                f"Identifying {blinky_iface}", seconds=NIC_BLINK_SECONDS, width=60, height=15
                            )
                    elif code != Dialog.OK:
                        break

                # user selects interface(s) for capture
                code, tag = d.checklist(
                    Constants.MSG_SELECT_INTERFACE,
                    choices=[
                        (adapter.name, adapter.description, adapter.name in preselected_ifaces)
                        for adapter in available_adapters
                    ],
                )
                if code != Dialog.OK:
                    raise CancelledError
                selected_ifaces = tag

                if len(selected_ifaces) > 0:
                    # user specifies capture filter (and we validate it with tcpdump)
                    prev_capture_filter = capture_config_dict["CAPTURE_FILTER"]
                    while True:
                        code, capture_filter = d.inputbox(
                            "PCAP capture filter (tcpdump-like filter expression; leave blank to capture all traffic)",
                            init=prev_capture_filter,
                        )
                        if (code == Dialog.CANCEL) or (code == Dialog.ESC):
                            raise CancelledError
                        capture_filter = capture_filter.strip()
                        if len(capture_filter) > 0:
                            # test out the capture filter to see if there's a syntax error
                            ecode, filter_test_results = run_subprocess(
                                f'tcpdump -i {selected_ifaces[0]} -d "{capture_filter}"', stdout=False, stderr=True
                            )
                        else:
                            # nothing to validate
                            ecode = 0
                            filter_test_results = [""]
                        if (prev_capture_filter == capture_filter) or (
                            (ecode == 0)
                            and (not any(x.lower().startswith("tcpdump: warning") for x in filter_test_results))
                            and (not any(x.lower().startswith("tcpdump: error") for x in filter_test_results))
                            and (not any("syntax error" in x.lower() for x in filter_test_results))
                        ):
                            break
                        else:
                            code = d.msgbox(
                                text=Constants.MSG_ERROR_FILTER_VALIDATION.format(
                                    " ".join([x.strip() for x in filter_test_results])
                                )
                            )
                        prev_capture_filter = capture_filter

                # regular expressions for selected name=value pairs to update in configuration file
                capture_interface_re = re.compile(r"(\bCAPTURE_INTERFACE)\s*=\s*.+?$")
                capture_filter_re = re.compile(r"(\bCAPTURE_FILTER)\s*=\s*.*?$")
                pcap_path_re = re.compile(r"(\bPCAP_PATH)\s*=\s*.+?$")
                zeek_path_re = re.compile(r"(\bZEEK_LOG_PATH)\s*=\s*.+?$")
                zeek_carve_re = re.compile(r"(\bZEEK_EXTRACTOR_MODE)\s*=\s*.+?$")
                zeek_file_preservation_re = re.compile(r"(\bEXTRACTED_FILE_PRESERVATION)\s*=\s*.+?$")
                zeek_carve_override_re = re.compile(r"(\bZEEK_EXTRACTOR_OVERRIDE_FILE)\s*=\s*.*?$")
                zeek_file_watch_re = re.compile(r"(\bZEEK_FILE_WATCH)\s*=\s*.+?$")
                zeek_file_scanner_re = re.compile(r"(\bZEEK_FILE_SCAN_\w+)\s*=\s*.+?$")

                # get paths for captured PCAP and Zeek files
                while True:
                    code, path_values = d.form(
                        Constants.MSG_CONFIG_CAP_PATHS,
                        [
                            ('PCAP Path', 1, 1, capture_config_dict.get("PCAP_PATH", ""), 1, 20, 30, 255),
                            ('Zeek Log Path', 2, 1, capture_config_dict.get("ZEEK_LOG_PATH", ""), 2, 20, 30, 255),
                        ],
                    )
                    path_values = [x.strip() for x in path_values]

                    if code == Dialog.CANCEL or code == Dialog.ESC:
                        raise CancelledError

                    # paths must be specified, and must already exist
                    if (
                        (len(path_values[0]) > 0)
                        and os.path.isdir(path_values[0])
                        and (len(path_values[1]) > 0)
                        and os.path.isdir(path_values[1])
                    ):
                        break
                    else:
                        code = d.msgbox(text=Constants.MSG_ERROR_DIR_NOT_FOUND)

                # configure file carving
                code, zeek_carve_mode = d.radiolist(
                    Constants.MSG_CONFIG_ZEEK_CARVING,
                    choices=[
                        (
                            Constants.ZEEK_FILE_CARVING_NONE,
                            'Disable file carving',
                            (capture_config_dict["ZEEK_EXTRACTOR_MODE"] == Constants.ZEEK_FILE_CARVING_NONE),
                        ),
                        (
                            Constants.ZEEK_FILE_CARVING_MAPPED,
                            'Carve files with recognized mime types',
                            (
                                (capture_config_dict["ZEEK_EXTRACTOR_MODE"] == Constants.ZEEK_FILE_CARVING_MAPPED)
                                and (len(capture_config_dict["ZEEK_EXTRACTOR_OVERRIDE_FILE"]) == 0)
                            ),
                        ),
                        (
                            Constants.ZEEK_FILE_CARVING_MAPPED_MINUS_TEXT,
                            'Carve files with recognized mime types (except common plain text files)',
                            False,
                        ),
                        (
                            Constants.ZEEK_FILE_CARVING_KNOWN,
                            'Carve files for which any mime type can be determined',
                            (capture_config_dict["ZEEK_EXTRACTOR_MODE"] == Constants.ZEEK_FILE_CARVING_KNOWN),
                        ),
                        (
                            Constants.ZEEK_FILE_CARVING_INTERESTING,
                            'Carve files with mime types of common attack vectors',
                            False,
                        ),
                        (
                            Constants.ZEEK_FILE_CARVING_CUSTOM_MIME,
                            'Use a custom selection of mime types (sorted by mime type)',
                            (
                                (capture_config_dict["ZEEK_EXTRACTOR_MODE"] == Constants.ZEEK_FILE_CARVING_MAPPED)
                                and (len(capture_config_dict["ZEEK_EXTRACTOR_OVERRIDE_FILE"]) > 0)
                            ),
                        ),
                        (
                            Constants.ZEEK_FILE_CARVING_CUSTOM_EXT,
                            'Use a custom selection of mime types (sorted by file extension)',
                            False,
                        ),
                        (
                            Constants.ZEEK_FILE_CARVING_ALL,
                            'Carve all files',
                            (capture_config_dict["ZEEK_EXTRACTOR_MODE"] == Constants.ZEEK_FILE_CARVING_ALL),
                        ),
                    ],
                )
                if code == Dialog.CANCEL or code == Dialog.ESC:
                    raise CancelledError

                mime_tags = []
                capture_config_dict["ZEEK_EXTRACTOR_OVERRIDE_FILE"] = ""
                zeek_carved_file_preservation = PRESERVE_NONE

                if zeek_carve_mode.startswith(Constants.ZEEK_FILE_CARVING_CUSTOM) or zeek_carve_mode.startswith(
                    Constants.ZEEK_FILE_CARVING_MAPPED_MINUS_TEXT
                ):
                    # get all known mime-to-extension mappings into a dictionary
                    all_mime_maps = mime_to_extension_mappings(Constants.ZEEK_FILE_CARVING_DEFAULTS)

                    if zeek_carve_mode == Constants.ZEEK_FILE_CARVING_MAPPED_MINUS_TEXT:
                        # all mime types minus common text mime types
                        mime_tags.extend(
                            [
                                mime
                                for mime in all_mime_maps.keys()
                                if mime not in Constants.ZEEK_FILE_CARVING_PLAIN_TEXT_MIMES
                            ]
                        )

                    else:
                        # select mimes to carve (pre-selecting items previously in the override file)
                        if zeek_carve_mode == Constants.ZEEK_FILE_CARVING_CUSTOM_EXT:
                            mime_choices = [
                                (
                                    pair[0],
                                    pair[1],
                                    pair[0] in mime_to_extension_mappings(Constants.ZEEK_FILE_CARVING_OVERRIDE_FILE),
                                )
                                for pair in sorted(all_mime_maps.items(), key=lambda x: x[1].lower())
                            ]
                        else:
                            mime_choices = [
                                (
                                    pair[0],
                                    pair[1],
                                    pair[0] in mime_to_extension_mappings(Constants.ZEEK_FILE_CARVING_OVERRIDE_FILE),
                                )
                                for pair in sorted(all_mime_maps.items(), key=lambda x: x[0].lower())
                            ]
                        code, mime_tags = d.checklist(Constants.MSG_CONFIG_ZEEK_CARVING_MIMES, choices=mime_choices)
                        if code == Dialog.CANCEL or code == Dialog.ESC:
                            raise CancelledError

                    mime_tags.sort()
                    if len(mime_tags) == 0:
                        zeek_carve_mode = Constants.ZEEK_FILE_CARVING_NONE
                    elif len(mime_tags) >= len(all_mime_maps):
                        zeek_carve_mode = Constants.ZEEK_FILE_CARVING_MAPPED
                    elif len(mime_tags) > 0:
                        zeek_carve_mode = Constants.ZEEK_FILE_CARVING_MAPPED
                        capture_config_dict["ZEEK_EXTRACTOR_OVERRIDE_FILE"] = Constants.ZEEK_FILE_CARVING_OVERRIDE_FILE
                    else:
                        zeek_carve_mode = Constants.ZEEK_FILE_CARVING_MAPPED

                elif zeek_carve_mode.startswith(Constants.ZEEK_FILE_CARVING_INTERESTING):
                    shutil.copy(
                        Constants.ZEEK_FILE_CARVING_OVERRIDE_INTERESTING_FILE, Constants.ZEEK_FILE_CARVING_OVERRIDE_FILE
                    )
                    zeek_carve_mode = Constants.ZEEK_FILE_CARVING_MAPPED
                    capture_config_dict["ZEEK_EXTRACTOR_OVERRIDE_FILE"] = Constants.ZEEK_FILE_CARVING_OVERRIDE_FILE

                # what to do with carved files
                if zeek_carve_mode != Constants.ZEEK_FILE_CARVING_NONE:
                    # select engines for file scanning
                    scanner_choices = []
                    for k, v in sorted(capture_config_dict.items()):
                        if k.startswith("ZEEK_FILE_SCAN_"):
                            scanner_choices.append((k, '', v.lower() == "true"))
                    code, scanner_tags = d.checklist(Constants.MSG_CONFIG_ZEEK_CARVED_SCANNERS, choices=scanner_choices)
                    if code == Dialog.CANCEL or code == Dialog.ESC:
                        raise CancelledError

                    for tag in [x[0] for x in scanner_choices]:
                        capture_config_dict[tag] = "false"
                    for tag in scanner_tags:
                        capture_config_dict[tag] = "true"
                    capture_config_dict["ZEEK_FILE_WATCH"] = "true" if (len(scanner_tags) > 0) else "false"

                    # specify what to do with files that triggered the scanner engine(s)
                    code, zeek_carved_file_preservation = d.radiolist(
                        Constants.MSG_CONFIG_CARVED_FILE_PRESERVATION,
                        choices=[
                            (
                                PRESERVE_QUARANTINED,
                                'Preserve only quarantined files',
                                (capture_config_dict["EXTRACTED_FILE_PRESERVATION"] == PRESERVE_QUARANTINED),
                            ),
                            (
                                PRESERVE_ALL,
                                'Preserve all files',
                                (capture_config_dict["EXTRACTED_FILE_PRESERVATION"] == PRESERVE_ALL),
                            ),
                            (
                                PRESERVE_NONE,
                                'Preserve no files',
                                (capture_config_dict["EXTRACTED_FILE_PRESERVATION"] == PRESERVE_NONE),
                            ),
                        ],
                    )
                    if code == Dialog.CANCEL or code == Dialog.ESC:
                        raise CancelledError

                else:
                    # file carving disabled, so disable file scanning as well
                    for key in [
                        "ZEEK_FILE_WATCH",
                        "ZEEK_FILE_SCAN_CLAMAV",
                        "ZEEK_FILE_SCAN_VTOT",
                        "ZEEK_FILE_SCAN_YARA",
                    ]:
                        capture_config_dict[key] = "false"

                # reconstitute dictionary with user-specified values
                capture_config_dict["CAPTURE_INTERFACE"] = ",".join(selected_ifaces)
                capture_config_dict["CAPTURE_FILTER"] = capture_filter
                capture_config_dict["PCAP_PATH"] = path_values[0]
                capture_config_dict["ZEEK_LOG_PATH"] = path_values[1]
                capture_config_dict["ZEEK_EXTRACTOR_MODE"] = zeek_carve_mode
                capture_config_dict["EXTRACTED_FILE_PRESERVATION"] = zeek_carved_file_preservation

                # get confirmation from user that we really want to do this
                code = d.yesno(
                    Constants.MSG_CONFIG_CAP_CONFIRM.format(
                        "\n".join(
                            sorted(
                                [
                                    f"{k}={v}"
                                    for k, v in capture_config_dict.items()
                                    if (not k.startswith("#")) and ("AUTOSTART" not in k) and ("PASSWORD" not in k)
                                ]
                            )
                        )
                    ),
                    yes_label="OK",
                    no_label="Cancel",
                )
                if code == Dialog.OK:
                    # modify specified values in-place in SENSOR_CAPTURE_CONFIG file
                    with fileinput.FileInput(Constants.SENSOR_CAPTURE_CONFIG, inplace=True, backup='.bak') as file:
                        for line in file:
                            line = line.rstrip("\n")
                            if capture_interface_re.search(line) is not None:
                                print(capture_interface_re.sub(r"\1=%s" % ",".join(selected_ifaces), line))
                            elif zeek_carve_override_re.search(line) is not None:
                                print(
                                    zeek_carve_override_re.sub(
                                        r'\1="%s"' % capture_config_dict["ZEEK_EXTRACTOR_OVERRIDE_FILE"], line
                                    )
                                )
                            elif zeek_carve_re.search(line) is not None:
                                print(zeek_carve_re.sub(r"\1=%s" % zeek_carve_mode, line))
                            elif zeek_file_preservation_re.search(line) is not None:
                                print(zeek_file_preservation_re.sub(r"\1=%s" % zeek_carved_file_preservation, line))
                            elif capture_filter_re.search(line) is not None:
                                print(capture_filter_re.sub(r'\1="%s"' % capture_filter, line))
                            elif pcap_path_re.search(line) is not None:
                                print(pcap_path_re.sub(r'\1="%s"' % capture_config_dict["PCAP_PATH"], line))
                            elif zeek_path_re.search(line) is not None:
                                print(zeek_path_re.sub(r'\1="%s"' % capture_config_dict["ZEEK_LOG_PATH"], line))
                            elif zeek_file_watch_re.search(line) is not None:
                                print(zeek_file_watch_re.sub(r"\1=%s" % capture_config_dict["ZEEK_FILE_WATCH"], line))
                            else:
                                zeek_file_scanner_match = zeek_file_scanner_re.search(line)
                                if zeek_file_scanner_match is not None:
                                    print(
                                        zeek_file_scanner_re.sub(
                                            r"\1=%s" % capture_config_dict[zeek_file_scanner_match.group(1)], line
                                        )
                                    )
                                else:
                                    print(line)

                    # write out file carving overrides if specified
                    if (len(mime_tags) > 0) and (len(capture_config_dict["ZEEK_EXTRACTOR_OVERRIDE_FILE"]) > 0):
                        with open(capture_config_dict["ZEEK_EXTRACTOR_OVERRIDE_FILE"], "w+") as f:
                            f.write('#!/usr/bin/env zeek\n')
                            f.write('\n')
                            f.write('export {\n')
                            f.write(
                                f'  redef {Constants.ZEEK_FILE_CARVING_OVERRIDE_FILE_MAP_NAME} : table[string] of string = {{\n'
                            )
                            f.write(",\n".join([f'    ["{m}"] = "{all_mime_maps[m]}"' for m in mime_tags]))
                            f.write('\n  } &default="bin";\n')
                            f.write('}\n')

                    # hooray
                    code = d.msgbox(
                        text=Constants.MSG_CONFIG_CAPTURE_SUCCESS.format(
                            ",".join(selected_ifaces), Constants.SENSOR_CAPTURE_CONFIG
                        )
                    )

            elif mode == Constants.MSG_CONFIG_MODE_FORWARD:
                # sensor forwarding (beats) configuration #############################################################################

                # only display MSG_CONFIG_TXRX if we have appropriate executable and script
                txRxScript = '/opt/sensor/sensor_ctl/tx-rx-secure.sh'
                txRxScript = (
                    txRxScript if (txRxScript and os.path.isfile(txRxScript)) else '/usr/local/bin/tx-rx-secure.sh'
                )
                txRxScript = txRxScript if (txRxScript and os.path.isfile(txRxScript)) else '/usr/bin/tx-rx-secure.sh'
                txRxScript = txRxScript if (txRxScript and os.path.isfile(txRxScript)) else None

                code, fwd_mode = d.menu(
                    Constants.MSG_CONFIG_MODE,
                    choices=[
                        Constants.MSG_CONFIG_ARKIME,
                        Constants.MSG_CONFIG_FILEBEAT,
                        Constants.MSG_CONFIG_MISCBEAT,
                        Constants.MSG_CONFIG_TXRX,
                    ][: 4 if txRxScript else -1],
                )
                if code != Dialog.OK:
                    raise CancelledError

                if fwd_mode == Constants.ARKIMECAP:
                    # forwarding configuration for arkime capture

                    # get opensearch connection information from user
                    opensearch_config_dict = input_opensearch_connection_info(
                        forwarder=fwd_mode,
                        default_os_host=previous_config_values[Constants.BEAT_OS_HOST],
                        default_os_port=previous_config_values[Constants.BEAT_OS_PORT],
                        default_username=previous_config_values[Constants.BEAT_HTTP_USERNAME],
                        default_password=previous_config_values[Constants.BEAT_HTTP_PASSWORD],
                    )
                    arkime_opensearch_config_dict = opensearch_config_dict.copy()
                    # massage the data a bit for how arkime's going to want it in the control_vars.conf file
                    if Constants.BEAT_HTTP_USERNAME in arkime_opensearch_config_dict.keys():
                        arkime_opensearch_config_dict["OS_USERNAME"] = arkime_opensearch_config_dict.pop(
                            Constants.BEAT_HTTP_USERNAME
                        )
                    if Constants.BEAT_HTTP_PASSWORD in arkime_opensearch_config_dict.keys():
                        arkime_opensearch_config_dict["OS_PASSWORD"] = aggressive_url_encode(
                            arkime_opensearch_config_dict.pop(Constants.BEAT_HTTP_PASSWORD)
                        )
                    arkime_opensearch_config_dict = {
                        k.replace('BEAT_', ''): v for k, v in arkime_opensearch_config_dict.items()
                    }

                    # get list of IP addresses allowed for packet payload retrieval
                    lines = previous_config_values[Constants.ARKIME_PACKET_ACL].split(",")
                    lines.append(opensearch_config_dict[Constants.BEAT_OS_HOST])
                    code, lines = d.editbox_str(
                        "\n".join(list(filter(None, list(set(lines))))), title=Constants.MSG_CONFIG_ARKIME_PCAP_ACL
                    )
                    if code != Dialog.OK:
                        raise CancelledError
                    arkime_opensearch_config_dict[Constants.ARKIME_PACKET_ACL] = ','.join(
                        [
                            ip
                            for ip in list(set(filter(None, [x.strip() for x in lines.split('\n')])))
                            if isipaddress(ip)
                        ]
                    )

                    # arkime PCAP compression settings
                    code, compression_type = d.radiolist(
                        Constants.MSG_CONFIG_ARKIME_COMPRESSION,
                        choices=[
                            (x, x, x == capture_config_dict[Constants.ARKIME_COMPRESSION_TYPE])
                            for x in Constants.ARKIME_COMPRESSION_TYPES
                        ],
                    )
                    if code == Dialog.CANCEL or code == Dialog.ESC:
                        raise CancelledError
                    arkime_opensearch_config_dict[Constants.ARKIME_COMPRESSION_TYPE] = compression_type

                    compression_level = 0
                    if compression_type in Constants.ARKIME_COMPRESSION_LEVELS:
                        prev_compression_level = capture_config_dict.get(
                            Constants.ARKIME_COMPRESSION_LEVEL,
                            Constants.ARKIME_COMPRESSION_LEVELS[compression_type][2],
                        )
                        prev_compression_level = (
                            int(prev_compression_level)
                            if prev_compression_level.isdigit()
                            else int(Constants.ARKIME_COMPRESSION_LEVELS[compression_type][2])
                        )
                        code, compression_level = d.rangebox(
                            f"{Constants.MSG_CONFIG_ARKIME_COMPRESSION_LEVEL.format(compression_type)}",
                            width=(
                                len(
                                    range(
                                        Constants.ARKIME_COMPRESSION_LEVELS[compression_type][0],
                                        Constants.ARKIME_COMPRESSION_LEVELS[compression_type][1],
                                    )
                                )
                                + 1
                            )
                            * 3,
                            min=Constants.ARKIME_COMPRESSION_LEVELS[compression_type][0],
                            max=Constants.ARKIME_COMPRESSION_LEVELS[compression_type][1],
                            init=prev_compression_level,
                        )
                    if code == Dialog.CANCEL or code == Dialog.ESC:
                        raise CancelledError
                    arkime_opensearch_config_dict[Constants.ARKIME_COMPRESSION_LEVEL] = str(compression_level)

                    list_results = sorted(
                        [
                            f"{k}={v}"
                            for k, v in arkime_opensearch_config_dict.items()
                            if ("PASSWORD" not in k) and (not k.startswith("#"))
                        ]
                    )

                    code = d.yesno(
                        Constants.MSG_CONFIG_FORWARDING_CONFIRM.format(fwd_mode, "\n".join(list_results)),
                        yes_label="OK",
                        no_label="Cancel",
                    )
                    if code != Dialog.OK:
                        raise CancelledError

                    previous_config_values = opensearch_config_dict.copy()

                    # modify specified values in-place in SENSOR_CAPTURE_CONFIG file
                    opensearch_values_re = re.compile(
                        r"\b(" + '|'.join(list(arkime_opensearch_config_dict.keys())) + r")\s*=\s*.*?$"
                    )
                    with fileinput.FileInput(Constants.SENSOR_CAPTURE_CONFIG, inplace=True, backup='.bak') as file:
                        for line in file:
                            line = line.rstrip("\n")
                            opensearch_key_match = opensearch_values_re.search(line)
                            if opensearch_key_match is not None:
                                print(
                                    opensearch_values_re.sub(
                                        r"\1=%s" % arkime_opensearch_config_dict[opensearch_key_match.group(1)], line
                                    )
                                )
                            else:
                                print(line)

                    # hooray
                    code = d.msgbox(
                        text=Constants.MSG_CONFIG_FORWARDING_SUCCESS.format(fwd_mode, "\n".join(list_results))
                    )

                elif (fwd_mode == Constants.FILEBEAT) or (fwd_mode == Constants.MISCBEAT):
                    # forwarder configuration for beats -> logstash

                    if not os.path.isdir(Constants.BEAT_DIR[fwd_mode]):
                        # beat dir not found, give up
                        raise Exception(
                            Constants.MSG_ERROR_FWD_DIR_NOT_FOUND.format(Constants.BEAT_DIR[fwd_mode], fwd_mode)
                        )

                    # chdir to the beat directory
                    os.chdir(Constants.BEAT_DIR[fwd_mode])

                    # check to see if a keystore has already been created for the forwarder
                    ecode, list_results = run_subprocess(f"{Constants.BEAT_CMD[fwd_mode]} keystore list")
                    if (ecode == 0) and (len(list_results) > 0):
                        # it has, do they wish to overwrite it?
                        if d.yesno(Constants.MSG_OVERWRITE_CONFIG.format(fwd_mode)) != Dialog.OK:
                            raise CancelledError

                    ecode, create_results = run_subprocess(
                        f"{Constants.BEAT_CMD[fwd_mode]} keystore create --force", stderr=True
                    )
                    if ecode != 0:
                        # keystore creation failed
                        raise Exception(Constants.MSG_ERROR_KEYSTORE.format(fwd_mode, "\n".join(create_results)))

                    forwarder_dict = defaultdict(str)

                    while True:
                        forwarder_dict = defaultdict(str)

                        forwarder_config_error = False
                        log_path = None
                        logstash_host = None
                        logstash_port = None

                        if fwd_mode == Constants.FILEBEAT:
                            # zeek log dir is filebeat only
                            code, values = d.form(
                                Constants.MSG_CONFIG_GENERIC.format(fwd_mode),
                                [
                                    ('Log Path', 1, 1, capture_config_dict["ZEEK_LOG_PATH"], 1, 20, 30, 255),
                                ],
                            )
                            if code == Dialog.CANCEL or code == Dialog.ESC:
                                raise CancelledError
                            values = [x.strip() for x in values]
                            if (len(values[0]) <= 0) or (not os.path.isdir(values[0])):
                                code = d.msgbox(text=Constants.MSG_ERROR_DIR_NOT_FOUND)
                                forwarder_config_error = True
                            else:
                                log_path = values[0]

                        if not forwarder_config_error:
                            # host/port for LogStash
                            code, values = d.form(
                                Constants.MSG_CONFIG_GENERIC.format(fwd_mode),
                                [
                                    (
                                        'Logstash Host',
                                        1,
                                        1,
                                        previous_config_values[Constants.BEAT_LS_HOST],
                                        1,
                                        25,
                                        30,
                                        255,
                                    ),
                                    (
                                        'Logstash Port',
                                        2,
                                        1,
                                        previous_config_values[Constants.BEAT_LS_PORT]
                                        if Constants.BEAT_LS_PORT in previous_config_values
                                        else "5044",
                                        2,
                                        25,
                                        6,
                                        5,
                                    ),
                                ],
                            )
                            if code == Dialog.CANCEL or code == Dialog.ESC:
                                raise CancelledError
                            values = [x.strip() for x in values]
                            if (len(values[0]) <= 0) or (len(values[1]) <= 0) or (not values[1].isnumeric()):
                                code = d.msgbox(text=Constants.MSG_ERROR_BAD_HOST)
                                forwarder_config_error = True
                            else:
                                logstash_host = values[0]
                                logstash_port = values[1]

                        if not forwarder_config_error:
                            # store inputted items into the configuration dictionary for the forwarder

                            if log_path is not None:
                                forwarder_dict[Constants.BEAT_ZEEK_LOG_PATTERN_KEY] = os.path.join(
                                    os.path.join(log_path, Constants.BEAT_ZEEK_LOG_PATH_SUBDIR),
                                    Constants.BEAT_ZEEK_LOG_PATTERN_VAL,
                                )
                                forwarder_dict[Constants.BEAT_STATIC_ZEEK_LOG_PATTERN_KEY] = os.path.join(
                                    os.path.join(log_path, Constants.BEAT_STATIC_ZEEK_LOG_PATH_SUBDIR),
                                    Constants.BEAT_ZEEK_LOG_PATTERN_VAL,
                                )
                                forwarder_dict[Constants.BEAT_SURICATA_LOG_PATTERN_KEY] = os.path.join(
                                    os.path.join(log_path, Constants.BEAT_SURICATA_LOG_PATH_SUBDIR),
                                    Constants.BEAT_SURICATA_LOG_PATTERN_VAL,
                                )

                            if logstash_host is not None:
                                forwarder_dict[Constants.BEAT_LS_HOST] = logstash_host

                            if logstash_port is not None:
                                forwarder_dict[Constants.BEAT_LS_PORT] = logstash_port

                            break

                    # optionally, filebeat can use SSL if Logstash is configured for it
                    logstash_ssl = "false"
                    logstash_ssl_verify = "none"
                    if (
                        d.yesno(
                            "Forward to Logstash over SSL? (Note: This requires the destination to be similarly configured and a corresponding copy of the client SSL files.)",
                            yes_label="SSL",
                            no_label="Unencrypted",
                        )
                        == Dialog.OK
                    ):
                        logstash_ssl = "true"
                        if d.yesno("Logstash SSL verification", yes_label="None", no_label="Force Peer") != Dialog.OK:
                            logstash_ssl_verify = "force_peer"
                    forwarder_dict[Constants.BEAT_LS_SSL] = logstash_ssl
                    forwarder_dict[Constants.BEAT_LS_SSL_VERIFY] = logstash_ssl_verify

                    if forwarder_dict[Constants.BEAT_LS_SSL] == "true":
                        while True:
                            code, values = d.form(
                                Constants.MSG_CONFIG_GENERIC.format(fwd_mode),
                                [
                                    (
                                        'SSL Certificate Authorities File',
                                        1,
                                        1,
                                        previous_config_values[Constants.BEAT_LS_SSL_CA_CRT]
                                        if Constants.BEAT_LS_SSL_CA_CRT in previous_config_values
                                        else f"{Constants.BEAT_LS_CERT_DIR_DEFAULT}/ca.crt",
                                        1,
                                        35,
                                        30,
                                        255,
                                    ),
                                    (
                                        'SSL Certificate File',
                                        2,
                                        1,
                                        previous_config_values[Constants.BEAT_LS_SSL_CLIENT_CRT]
                                        if Constants.BEAT_LS_SSL_CLIENT_CRT in previous_config_values
                                        else f"{Constants.BEAT_LS_CERT_DIR_DEFAULT}/client.crt",
                                        2,
                                        35,
                                        30,
                                        255,
                                    ),
                                    (
                                        'SSL Key File',
                                        3,
                                        1,
                                        previous_config_values[Constants.BEAT_LS_SSL_CLIENT_KEY]
                                        if Constants.BEAT_LS_SSL_CLIENT_KEY in previous_config_values
                                        else f"{Constants.BEAT_LS_CERT_DIR_DEFAULT}/client.key",
                                        3,
                                        35,
                                        30,
                                        255,
                                    ),
                                ],
                            )
                            values = [x.strip() for x in values]

                            if (code == Dialog.CANCEL) or (code == Dialog.ESC):
                                raise CancelledError

                            elif (
                                (len(values[0]) <= 0)
                                or (not os.path.isfile(values[0]))
                                or (len(values[1]) <= 0)
                                or (not os.path.isfile(values[1]))
                                or (len(values[2]) <= 0)
                                or (not os.path.isfile(values[2]))
                            ):
                                code = d.msgbox(text=Constants.MSG_ERROR_FILE_NOT_FOUND)

                            else:
                                forwarder_dict[Constants.BEAT_LS_SSL_CA_CRT] = values[0]
                                forwarder_dict[Constants.BEAT_LS_SSL_CLIENT_CRT] = values[1]
                                forwarder_dict[Constants.BEAT_LS_SSL_CLIENT_KEY] = values[2]
                                break

                    else:
                        forwarder_dict[Constants.BEAT_LS_SSL_CA_CRT] = ""
                        forwarder_dict[Constants.BEAT_LS_SSL_CLIENT_CRT] = ""
                        forwarder_dict[Constants.BEAT_LS_SSL_CLIENT_KEY] = ""

                    # see if logstash port is open (not a great connection test, but better than nothing!)
                    code = d.infobox(Constants.MSG_TESTING_CONNECTION.format("Logstash"))
                    if not check_socket(
                        forwarder_dict[Constants.BEAT_LS_HOST], int(forwarder_dict[Constants.BEAT_LS_PORT])
                    ):
                        code = d.yesno(
                            text=Constants.MSG_TESTING_CONNECTION_FAILURE_LOGSTASH.format(
                                "Logstash",
                                forwarder_dict[Constants.BEAT_LS_HOST],
                                forwarder_dict[Constants.BEAT_LS_PORT],
                            ),
                            yes_label="Ignore Error",
                            no_label="Start Over",
                        )
                        if code != Dialog.OK:
                            raise CancelledError

                    # get confirmation of parameters before we pull the trigger
                    code = d.yesno(
                        Constants.MSG_CONFIG_FORWARDING_CONFIRM.format(
                            fwd_mode,
                            "\n".join(sorted([f"{k}={v}" for k, v in forwarder_dict.items() if "PASSWORD" not in k])),
                        ),
                        yes_label="OK",
                        no_label="Cancel",
                    )
                    if code != Dialog.OK:
                        raise CancelledError

                    previous_config_values = forwarder_dict.copy()

                    # it's go time, call keystore add for each item
                    for k, v in sorted(forwarder_dict.items()):
                        ecode, add_results = run_subprocess(
                            f"{Constants.BEAT_CMD[fwd_mode]} keystore add {k} --stdin --force", stdin=v, stderr=True
                        )
                        if ecode != 0:
                            # keystore creation failed
                            raise Exception(Constants.MSG_ERROR_KEYSTORE.format(fwd_mode, "\n".join(add_results)))

                    # get a final list of parameters that were set to show the user that stuff happened
                    ecode, list_results = run_subprocess(f"{Constants.BEAT_CMD[fwd_mode]} keystore list")
                    if ecode == 0:
                        code = d.msgbox(
                            text=Constants.MSG_CONFIG_FORWARDING_SUCCESS.format(fwd_mode, "\n".join(list_results))
                        )

                    else:
                        # keystore list failed
                        raise Exception(Constants.MSG_ERROR_KEYSTORE.format(fwd_mode, "\n".join(add_results)))

                elif (fwd_mode == Constants.TX_RX_SECURE) and txRxScript:
                    # use tx-rx-secure.sh (via croc) to get certs from Malcolm
                    code = d.msgbox(text='Run auth_setup on Malcolm "Transfer self-signed client certificates..."')

                    tx_ip = None
                    rx_token = None

                    while True:
                        code, values = d.form(
                            Constants.MSG_CONFIG_TXRX[1],
                            [
                                ('Malcolm Server IP', 1, 1, "", 1, 25, 40, 255),
                                ('Single-use Code Phrase', 2, 1, "", 2, 25, 40, 255),
                            ],
                        )
                        values = [x.strip() for x in values]

                        if (code == Dialog.CANCEL) or (code == Dialog.ESC):
                            raise CancelledError

                        elif (len(values[0]) >= 3) and (len(values[1]) >= 16):
                            tx_ip = values[0]
                            rx_token = values[1]
                            break

                    for oldFile in ('ca.crt', 'client.crt', 'client.key'):
                        try:
                            os.unlink(os.path.join(Constants.BEAT_LS_CERT_DIR_DEFAULT, oldFile))
                        except Exception:
                            pass

                    with Popen(
                        [
                            txRxScript,
                            '-s',
                            tx_ip,
                            '-r',
                            rx_token,
                            '-o',
                            Constants.BEAT_LS_CERT_DIR_DEFAULT,
                        ],
                        stdout=PIPE,
                        stderr=STDOUT,
                        bufsize=0,
                    ) as p:
                        d.programbox(
                            fd=p.stdout.fileno(),
                            text=os.path.basename(txRxScript),
                            width=78,
                            height=20,
                        )
                        if (code == Dialog.CANCEL) or (code == Dialog.ESC):
                            raise RuntimeError("Operation cancelled")

                        p.poll()

                else:
                    # we're here without a valid forwarding type selection?!?
                    raise Exception(Constants.MSG_MESSAGE_ERROR.format(Constants.MSG_INVALID_FORWARDING_TYPE))

        except CancelledError:
            # d.msgbox(text=Constants.MSG_CANCEL_ERROR)
            # just start over
            continue

        except Exception as e:
            d.msgbox(text=Constants.MSG_MESSAGE_ERROR.format(e))
            raise


if __name__ == '__main__':
    main()
    clearquit()
