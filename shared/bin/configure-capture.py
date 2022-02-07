#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2022 Battelle Energy Alliance, LLC.  All rights reserved.

# script for configuring sensor capture and forwarding parameters

import locale
import os
import re
import shutil
import sys
import fileinput
from collections import defaultdict
from dialog import Dialog
from zeek_carve_utils import *
from sensorcommon import *


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
    METRICBEAT = 'metricbeat'
    AUDITBEAT = 'auditbeat'
    HEATBEAT = 'heatbeat'  # protologbeat to log temperature and other misc. stuff
    SYSLOGBEAT = 'filebeat-syslog'  # another filebeat instance for syslog
    ARKIMECAP = 'arkime-capture'

    BEAT_DIR = {
        FILEBEAT: f'/opt/sensor/sensor_ctl/{FILEBEAT}',
        METRICBEAT: f'/opt/sensor/sensor_ctl/{METRICBEAT}',
        AUDITBEAT: f'/opt/sensor/sensor_ctl/{AUDITBEAT}',
        SYSLOGBEAT: f'/opt/sensor/sensor_ctl/{SYSLOGBEAT}',
        HEATBEAT: f'/opt/sensor/sensor_ctl/{HEATBEAT}',
    }

    BEAT_DASHBOARDS_DIR = {
        FILEBEAT: f'/usr/share/{FILEBEAT}/kibana',
        METRICBEAT: f'/usr/share/{METRICBEAT}/kibana',
        AUDITBEAT: f'/usr/share/{AUDITBEAT}/kibana',
        SYSLOGBEAT: f'/usr/share/{FILEBEAT}/kibana',
        HEATBEAT: f'/usr/share/protologbeat/kibana/',
    }

    BEAT_CMD = {
        FILEBEAT: f'{FILEBEAT} --path.home "{BEAT_DIR[FILEBEAT]}" --path.config "{BEAT_DIR[FILEBEAT]}" --path.data "{BEAT_DIR[FILEBEAT]}/data" --path.logs "{BEAT_DIR[FILEBEAT]}/logs" -c "{BEAT_DIR[FILEBEAT]}/{FILEBEAT}.yml"',
        METRICBEAT: f'{METRICBEAT} --path.home "{BEAT_DIR[METRICBEAT]}" --path.config "{BEAT_DIR[METRICBEAT]}" --path.data "{BEAT_DIR[METRICBEAT]}/data" --path.logs "{BEAT_DIR[METRICBEAT]}/logs" -c "{BEAT_DIR[METRICBEAT]}/{METRICBEAT}.yml"',
        AUDITBEAT: f'{AUDITBEAT} --path.home "{BEAT_DIR[AUDITBEAT]}" --path.config "{BEAT_DIR[AUDITBEAT]}" --path.data "{BEAT_DIR[AUDITBEAT]}/data" --path.logs "{BEAT_DIR[AUDITBEAT]}/logs" -c "{BEAT_DIR[AUDITBEAT]}/{AUDITBEAT}.yml"',
        SYSLOGBEAT: f'{FILEBEAT} --path.home "{BEAT_DIR[SYSLOGBEAT]}" --path.config "{BEAT_DIR[SYSLOGBEAT]}" --path.data "{BEAT_DIR[SYSLOGBEAT]}/data" --path.logs "{BEAT_DIR[SYSLOGBEAT]}/logs" -c "{BEAT_DIR[SYSLOGBEAT]}/{SYSLOGBEAT}.yml"',
        HEATBEAT: f'protologbeat --path.home "{BEAT_DIR[HEATBEAT]}" --path.config "{BEAT_DIR[HEATBEAT]}" --path.data "{BEAT_DIR[HEATBEAT]}/data" --path.logs "{BEAT_DIR[HEATBEAT]}/logs" -c "{BEAT_DIR[HEATBEAT]}/protologbeat.yml"',
    }

    # specific to beats forwarded to logstash (eg., filebeat)
    BEAT_LS_HOST = 'BEAT_LS_HOST'
    BEAT_LS_PORT = 'BEAT_LS_PORT'
    BEAT_LS_SSL = 'BEAT_LS_SSL'
    BEAT_LS_SSL_CA_CRT = 'BEAT_LS_SSL_CA_CRT'
    BEAT_LS_SSL_CLIENT_CRT = 'BEAT_LS_SSL_CLIENT_CRT'
    BEAT_LS_SSL_CLIENT_KEY = 'BEAT_LS_SSL_CLIENT_KEY'
    BEAT_LS_SSL_VERIFY = 'BEAT_LS_SSL_VERIFY'

    # specific to beats forwarded to OpenSearch (eg., metricbeat, auditbeat, filebeat-syslog)
    BEAT_OS_HOST = "BEAT_OS_HOST"
    BEAT_OS_PORT = "BEAT_OS_PORT"
    BEAT_OS_PROTOCOL = "BEAT_OS_PROTOCOL"
    BEAT_OS_SSL_VERIFY = "BEAT_OS_SSL_VERIFY"
    BEAT_HTTP_PASSWORD = "BEAT_HTTP_PASSWORD"
    BEAT_HTTP_USERNAME = "BEAT_HTTP_USERNAME"
    BEAT_DASHBOARDS_ENABLED = "BEAT_DASHBOARDS_ENABLED"
    BEAT_DASHBOARDS_PATH = "BEAT_DASHBOARDS_PATH"
    BEAT_DASHBOARDS_HOST = "BEAT_DASHBOARDS_HOST"
    BEAT_DASHBOARDS_PORT = "BEAT_DASHBOARDS_PORT"
    BEAT_DASHBOARDS_PROTOCOL = "BEAT_DASHBOARDS_PROTOCOL"
    BEAT_DASHBOARDS_SSL_VERIFY = "BEAT_DASHBOARDS_SSL_VERIFY"

    # specific to filebeat
    BEAT_LOG_PATH_SUBDIR = os.path.join('logs', 'current')
    BEAT_LOG_PATTERN_KEY = 'BEAT_LOG_PATTERN'
    BEAT_STATIC_LOG_PATH_SUBDIR = os.path.join('logs', 'static')
    BEAT_STATIC_LOG_PATTERN_KEY = 'BEAT_STATIC_LOG_PATTERN'
    BEAT_LOG_PATTERN_VAL = '*.log'

    # specific to metricbeat
    BEAT_INTERVAL = "BEAT_INTERVAL"

    # specific to arkime
    ARKIME_PACKET_ACL = "ARKIME_PACKET_ACL"

    MSG_CONFIG_MODE = 'Configuration Mode'
    MSG_CONFIG_MODE_CAPTURE = 'Configure Capture'
    MSG_CONFIG_MODE_FORWARD = 'Configure Forwarding'
    MSG_CONFIG_MODE_AUTOSTART = 'Configure Autostart Services'
    MSG_CONFIG_GENERIC = 'Configure {}'
    MSG_CONFIG_ARKIME = (f'{ARKIMECAP}', f'Configure Arkime session forwarding via {ARKIMECAP}')
    MSG_CONFIG_FILEBEAT = (f'{FILEBEAT}', f'Configure Zeek log forwarding via {FILEBEAT}')
    MSG_CONFIG_METRICBEAT = (f'{METRICBEAT}', f'Configure resource metrics forwarding via {METRICBEAT}')
    MSG_CONFIG_AUDITBEAT = (f'{AUDITBEAT}', f'Configure audit log forwarding via {AUDITBEAT}')
    MSG_CONFIG_SYSLOGBEAT = (f'{SYSLOGBEAT}', f'Configure syslog forwarding via {FILEBEAT}')
    MSG_CONFIG_HEATBEAT = (f'{HEATBEAT}', f'Configure hardware metrics (temperature, etc.) forwarding via protologbeat')
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
    default_dashboards_host=None,
    default_dashboards_port=None,
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

    # Dashboards configuration (if supported by forwarder)
    if (forwarder in Constants.BEAT_DASHBOARDS_DIR.keys()) and (
        d.yesno(f"Configure {forwarder} Dashboards connectivity?") == Dialog.OK
    ):
        # opensearch protocol and SSL verification mode
        dashboards_protocol = "http"
        dashboards_ssl_verify = "none"
        if d.yesno("Dashboards connection protocol", yes_label="HTTPS", no_label="HTTP") == Dialog.OK:
            dashboards_protocol = "https"
            if d.yesno("Dashboards SSL verification", yes_label="None", no_label="Full") != Dialog.OK:
                dashboards_ssl_verify = "full"
        return_dict[Constants.BEAT_DASHBOARDS_PROTOCOL] = dashboards_protocol
        return_dict[Constants.BEAT_DASHBOARDS_SSL_VERIFY] = dashboards_ssl_verify

        while True:
            # host/port for Dashboards
            code, values = d.form(
                Constants.MSG_CONFIG_GENERIC.format(forwarder),
                [
                    ('Dashboards Host', 1, 1, default_dashboards_host or "", 1, 20, 30, 255),
                    ('Dashboards Port', 2, 1, default_dashboards_port or "5601", 2, 20, 6, 5),
                ],
            )
            values = [x.strip() for x in values]

            if (code == Dialog.CANCEL) or (code == Dialog.ESC):
                raise CancelledError

            elif (len(values[0]) <= 0) or (len(values[1]) <= 0) or (not values[1].isnumeric()):
                code = d.msgbox(text=Constants.MSG_ERROR_BAD_HOST)

            else:
                return_dict[Constants.BEAT_DASHBOARDS_HOST] = values[0]
                return_dict[Constants.BEAT_DASHBOARDS_PORT] = values[1]
                break

        if d.yesno(f"Configure {forwarder} Dashboards dashboards?") == Dialog.OK:
            dashboards_enabled = "true"
        else:
            dashboards_enabled = "false"
        return_dict[Constants.BEAT_DASHBOARDS_ENABLED] = dashboards_enabled

        if dashboards_enabled == "true":
            while True:
                code, values = d.form(
                    Constants.MSG_CONFIG_GENERIC.format(forwarder),
                    [('Dashboards Dashboards Path', 1, 1, Constants.BEAT_DASHBOARDS_DIR[forwarder], 1, 30, 30, 255)],
                )
                values = [x.strip() for x in values]

                if (code == Dialog.CANCEL) or (code == Dialog.ESC):
                    raise CancelledError

                elif (len(values[0]) <= 0) or (not os.path.isdir(values[0])):
                    code = d.msgbox(text=Constants.MSG_ERROR_DIR_NOT_FOUND)

                else:
                    return_dict[Constants.BEAT_DASHBOARDS_PATH] = values[0]
                    break

    server_display_name = (
        "OpenSearch/Dashboards" if Constants.BEAT_DASHBOARDS_HOST in return_dict.keys() else "OpenSearch"
    )

    # HTTP/HTTPS authentication
    code, http_username = d.inputbox(f"{server_display_name} HTTP/HTTPS server username", init=default_username)
    if (code == Dialog.CANCEL) or (code == Dialog.ESC):
        raise CancelledError
    return_dict[Constants.BEAT_HTTP_USERNAME] = http_username.strip()

    # make them enter the password twice
    while True:
        code, http_password = d.passwordbox(
            f"{server_display_name} HTTP/HTTPS server password", insecure=True, init=default_password
        )
        if (code == Dialog.CANCEL) or (code == Dialog.ESC):
            raise CancelledError

        code, http_password2 = d.passwordbox(
            f"{server_display_name} HTTP/HTTPS server password (again)",
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

    # test Dashboards connection
    if Constants.BEAT_DASHBOARDS_HOST in return_dict.keys():
        code = d.infobox(Constants.MSG_TESTING_CONNECTION.format("Dashboards"))
        retcode, message, output = test_connection(
            protocol=return_dict[Constants.BEAT_DASHBOARDS_PROTOCOL],
            host=return_dict[Constants.BEAT_DASHBOARDS_HOST],
            port=return_dict[Constants.BEAT_DASHBOARDS_PORT],
            uri="api/status",
            username=return_dict[Constants.BEAT_HTTP_USERNAME]
            if (len(return_dict[Constants.BEAT_HTTP_USERNAME]) > 0)
            else None,
            password=return_dict[Constants.BEAT_HTTP_PASSWORD]
            if (len(return_dict[Constants.BEAT_HTTP_PASSWORD]) > 0)
            else None,
            ssl_verify=return_dict[Constants.BEAT_DASHBOARDS_SSL_VERIFY],
        )
        if retcode == 200:
            code = d.msgbox(text=Constants.MSG_TESTING_CONNECTION_SUCCESS.format("Dashboards", retcode, message))
        else:
            code = d.yesno(
                text=Constants.MSG_TESTING_CONNECTION_FAILURE.format("Dashboards", retcode, message, "\n".join(output)),
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
    except:
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
                previous_config_values[Constants.BEAT_DASHBOARDS_HOST] = capture_config_dict["OS_HOST"]
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
                ##### sensor autostart services configuration #######################################################################################

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
                ##### sensor capture configuration ##################################################################################################

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
                            ecode, filter_test_results = run_process(
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
                        "ZEEK_FILE_SCAN_MALASS",
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
                ##### sensor forwarding (beats) configuration #########################################################################

                code, fwd_mode = d.menu(
                    Constants.MSG_CONFIG_MODE,
                    choices=[
                        Constants.MSG_CONFIG_FILEBEAT,
                        Constants.MSG_CONFIG_ARKIME,
                        Constants.MSG_CONFIG_METRICBEAT,
                        Constants.MSG_CONFIG_AUDITBEAT,
                        Constants.MSG_CONFIG_SYSLOGBEAT,
                        Constants.MSG_CONFIG_HEATBEAT,
                    ],
                )
                if code != Dialog.OK:
                    raise CancelledError

                if fwd_mode == Constants.ARKIMECAP:
                    # forwarding configuration for arkime capture

                    # get opensearch/dashboards connection information from user
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

                elif (
                    (fwd_mode == Constants.FILEBEAT)
                    or (fwd_mode == Constants.METRICBEAT)
                    or (fwd_mode == Constants.AUDITBEAT)
                    or (fwd_mode == Constants.SYSLOGBEAT)
                    or (fwd_mode == Constants.HEATBEAT)
                ):
                    # forwarder configuration for beats

                    if not os.path.isdir(Constants.BEAT_DIR[fwd_mode]):
                        # beat dir not found, give up
                        raise Exception(
                            Constants.MSG_ERROR_FWD_DIR_NOT_FOUND.format(Constants.BEAT_DIR[fwd_mode], fwd_mode)
                        )

                    # chdir to the beat directory
                    os.chdir(Constants.BEAT_DIR[fwd_mode])

                    # check to see if a keystore has already been created for the forwarder
                    ecode, list_results = run_process(f"{Constants.BEAT_CMD[fwd_mode]} keystore list")
                    if (ecode == 0) and (len(list_results) > 0):
                        # it has, do they wish to overwrite it?
                        if d.yesno(Constants.MSG_OVERWRITE_CONFIG.format(fwd_mode)) != Dialog.OK:
                            raise CancelledError

                    ecode, create_results = run_process(
                        f"{Constants.BEAT_CMD[fwd_mode]} keystore create --force", stderr=True
                    )
                    if ecode != 0:
                        # keystore creation failed
                        raise Exception(Constants.MSG_ERROR_KEYSTORE.format(fwd_mode, "\n".join(create_results)))

                    forwarder_dict = defaultdict(str)

                    if (
                        (fwd_mode == Constants.METRICBEAT)
                        or (fwd_mode == Constants.AUDITBEAT)
                        or (fwd_mode == Constants.SYSLOGBEAT)
                        or (fwd_mode == Constants.HEATBEAT)
                    ):
                        #### auditbeat/metricbeat/filebeat-syslog ###################################################################
                        # enter beat configuration (in a few steps)

                        if fwd_mode == Constants.METRICBEAT:
                            # interval is metricbeat only, the rest is used by both
                            code, beat_interval = d.rangebox(
                                f"{Constants.MSG_CONFIG_GENERIC.format(fwd_mode)} interval (seconds)",
                                width=60,
                                min=1,
                                max=60,
                                init=30,
                            )
                            if code == Dialog.CANCEL or code == Dialog.ESC:
                                raise CancelledError
                            forwarder_dict[Constants.BEAT_INTERVAL] = f"{beat_interval}s"

                        # get opensearch/dashboards connection information from user
                        forwarder_dict.update(
                            input_opensearch_connection_info(
                                forwarder=fwd_mode,
                                default_os_host=previous_config_values[Constants.BEAT_OS_HOST],
                                default_os_port=previous_config_values[Constants.BEAT_OS_PORT],
                                default_dashboards_host=previous_config_values[Constants.BEAT_DASHBOARDS_HOST],
                                default_dashboards_port=previous_config_values[Constants.BEAT_DASHBOARDS_PORT],
                                default_username=previous_config_values[Constants.BEAT_HTTP_USERNAME],
                                default_password=previous_config_values[Constants.BEAT_HTTP_PASSWORD],
                            )
                        )

                    elif fwd_mode == Constants.FILEBEAT:
                        #### filebeat #############################################################################################
                        while True:
                            forwarder_dict = defaultdict(str)

                            # enter main filebeat configuration
                            code, values = d.form(
                                Constants.MSG_CONFIG_GENERIC.format(fwd_mode),
                                [
                                    ('Log Path', 1, 1, capture_config_dict["ZEEK_LOG_PATH"], 1, 20, 30, 255),
                                    ('Destination Host', 2, 1, "", 2, 20, 30, 255),
                                    ('Destination Port', 3, 1, "5044", 3, 20, 6, 5),
                                ],
                            )
                            values = [x.strip() for x in values]

                            if (code == Dialog.CANCEL) or (code == Dialog.ESC):
                                raise CancelledError

                            elif (len(values[0]) <= 0) or (not os.path.isdir(values[0])):
                                code = d.msgbox(text=Constants.MSG_ERROR_DIR_NOT_FOUND)

                            elif (len(values[1]) <= 0) or (len(values[2]) <= 0) or (not values[2].isnumeric()):
                                code = d.msgbox(text=Constants.MSG_ERROR_BAD_HOST)

                            else:
                                forwarder_dict[Constants.BEAT_LOG_PATTERN_KEY] = os.path.join(
                                    os.path.join(values[0], Constants.BEAT_LOG_PATH_SUBDIR),
                                    Constants.BEAT_LOG_PATTERN_VAL,
                                )
                                forwarder_dict[Constants.BEAT_STATIC_LOG_PATTERN_KEY] = os.path.join(
                                    os.path.join(values[0], Constants.BEAT_STATIC_LOG_PATH_SUBDIR),
                                    Constants.BEAT_LOG_PATTERN_VAL,
                                )
                                forwarder_dict[Constants.BEAT_LS_HOST] = values[1]
                                forwarder_dict[Constants.BEAT_LS_PORT] = values[2]
                                break

                        # optionally, filebeat can use SSL if Logstash is configured for it
                        logstash_ssl = "false"
                        logstash_ssl_verify = "none"
                        if (
                            d.yesno(
                                "Forward Zeek logs over SSL? (Note: This requires the destination to be similarly configured and a corresponding copy of the client SSL files.)",
                                yes_label="SSL",
                                no_label="Unencrypted",
                            )
                            == Dialog.OK
                        ):
                            logstash_ssl = "true"
                            if (
                                d.yesno("Logstash SSL verification", yes_label="None", no_label="Force Peer")
                                != Dialog.OK
                            ):
                                logstash_ssl_verify = "force_peer"
                        forwarder_dict[Constants.BEAT_LS_SSL] = logstash_ssl
                        forwarder_dict[Constants.BEAT_LS_SSL_VERIFY] = logstash_ssl_verify

                        if forwarder_dict[Constants.BEAT_LS_SSL] == "true":
                            while True:
                                code, values = d.form(
                                    Constants.MSG_CONFIG_GENERIC.format(fwd_mode),
                                    [
                                        ('SSL Certificate Authorities File', 1, 1, "", 1, 35, 30, 255),
                                        ('SSL Certificate File', 2, 1, "", 2, 35, 30, 255),
                                        ('SSL Key File', 3, 1, "", 3, 35, 30, 255),
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

                    # outside of filebeat/metricbeat if/else, get confirmation and write out the values to the keystore
                    if forwarder_dict:

                        # get confirmation of parameters before we pull the trigger
                        code = d.yesno(
                            Constants.MSG_CONFIG_FORWARDING_CONFIRM.format(
                                fwd_mode,
                                "\n".join(
                                    sorted([f"{k}={v}" for k, v in forwarder_dict.items() if "PASSWORD" not in k])
                                ),
                            ),
                            yes_label="OK",
                            no_label="Cancel",
                        )
                        if code != Dialog.OK:
                            raise CancelledError

                        previous_config_values = forwarder_dict.copy()

                        # it's go time, call keystore add for each item
                        for k, v in sorted(forwarder_dict.items()):
                            ecode, add_results = run_process(
                                f"{Constants.BEAT_CMD[fwd_mode]} keystore add {k} --stdin --force", stdin=v, stderr=True
                            )
                            if ecode != 0:
                                # keystore creation failed
                                raise Exception(Constants.MSG_ERROR_KEYSTORE.format(fwd_mode, "\n".join(add_results)))

                        # get a final list of parameters that were set to show the user that stuff happened
                        ecode, list_results = run_process(f"{Constants.BEAT_CMD[fwd_mode]} keystore list")
                        if ecode == 0:
                            code = d.msgbox(
                                text=Constants.MSG_CONFIG_FORWARDING_SUCCESS.format(fwd_mode, "\n".join(list_results))
                            )

                        else:
                            # keystore list failed
                            raise Exception(Constants.MSG_ERROR_KEYSTORE.format(fwd_mode, "\n".join(add_results)))

                    else:
                        # we got through the config but ended up with no values for configuration!
                        raise Exception(Constants.MSG_MESSAGE_ERROR.format(Constants.MSG_EMPTY_CONFIG_ERROR))

        except CancelledError as c:
            # d.msgbox(text=Constants.MSG_CANCEL_ERROR)
            # just start over
            continue

        except Exception as e:
            d.msgbox(text=Constants.MSG_MESSAGE_ERROR.format(e))
            raise


if __name__ == '__main__':
    main()
    clearquit()
