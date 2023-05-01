#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2023 Battelle Energy Alliance, LLC.  All rights reserved.

# script for configuring sensor network interface controller(s)

import locale
import os
import sys
import netifaces
import fileinput
import re
from dialog import Dialog
from debinterface.interfaces import Interfaces

from sensorcommon import (
    CancelledError,
    clearquit,
    get_available_adapters,
    identify_adapter,
    NIC_BLINK_SECONDS,
)
from malcolm_utils import (
    eprint,
    run_subprocess,
    remove_prefix,
    aggressive_url_encode,
    isipaddress,
    check_socket,
)


class Constants:
    DHCP = 'dhcp'
    STATIC = 'static'
    UNASSIGNED = 'manual'

    DEV_IDENTIFIER_FILE = '/etc/installer'
    DEV_UNKNOWN = 'unknown'
    DEV_AGGREGATOR = 'aggregator'
    DEV_SENSOR = 'sensor'
    DEV_VALID = {DEV_AGGREGATOR, DEV_SENSOR}
    MSG_ERR_DEV_INVALID = f'Could not determine installation type (not one of {DEV_VALID})'

    CONFIG_IFACE = 'Interface Configuration'

    SENSOR_BACKUP_CONFIG = '/tmp/sensor_interface.bak'
    SENSOR_INTERFACES_CONFIG = '/etc/network/interfaces.d/sensor'
    ETC_HOSTS = '/etc/hosts'

    TIME_SYNC_NTP = 'ntp'
    TIME_SYNC_HTPDATE = 'htpdate'
    TIME_SYNC_HTPDATE_CRON = '/etc/cron.d/htpdate'
    TIME_SYNC_HTPDATE_TEST_COMMAND = '/usr/sbin/htpdate -4 -a -b -d'
    TIME_SYNC_HTPDATE_COMMAND = '/usr/sbin/htpdate -4 -a -b -l -s'
    TIME_SYNC_NTP_CONFIG = '/etc/ntp.conf'

    MSG_CONFIG_MODE = 'Configuration Mode'
    MSG_BACKGROUND_TITLE = 'Sensor Configuration'
    MSG_CONFIG_HOST = ('Hostname', 'Configure sensor hostname')
    MSG_CONFIG_INTERFACE = ('Interface', 'Configure an interface\'s IP address')
    MSG_CONFIG_TIME_SYNC = ('Time Sync', 'Configure time synchronization')
    MSG_CONFIG_STATIC_TITLE = 'Provide the values for static IP configuration'
    MSG_ERR_ROOT_REQUIRED = 'Elevated privileges required, run as root'
    MSG_ERR_BAD_HOST = 'Invalid host or port'
    MSG_MESSAGE_DHCP = 'Configuring for DHCP provided address...'
    MSG_MESSAGE_ERROR = 'Error: {}\n\nPlease try again.'
    MSG_MESSAGE_STATIC = 'Configuring for static IP address...'
    MSG_MESSAGE_UNASSIGNED = 'Configuring for no IP address...'
    MSG_NETWORK_START_ERROR = 'Error occured while configuring network interface!\n\n'
    MSG_NETWORK_START_SUCCESS = 'Network interface configuration completed successfully!\n\n'
    MSG_NETWORK_STOP_ERROR = 'Error occured while bringing down the network interface!\n\n'
    MSG_NETWORK_STOP_SUCCESS = 'Brought down the network interface successfully!\n\n'
    MSG_TIME_SYNC_TYPE = 'Select time synchronization method'
    MSG_TIME_SYNC_HTPDATE_CONFIG = 'Provide values for HTTP/HTTPS Server'
    MSG_TIME_SYNC_TEST_SUCCESS = 'Server time retrieved successfully!\n\n'
    MSG_TIME_SYNC_CONFIG_SUCCESS = 'Time synchronization configured successfully!\n\n'
    MSG_TIME_SYNC_TEST_FAILURE = 'Server time could not be retrieved. Ignore error?\n\n'
    MSG_TIME_SYNC_NTP_CONFIG = 'Provide values for NTP Server'
    MSG_TESTING_CONNECTION = 'Testing {} connection...'
    MSG_TESTING_CONNECTION_FAILURE = "Connection error: could not connect to {}:{}"
    MSG_SET_HOSTNAME_CURRENT = 'Current sensor identification information\n\n'
    MSG_SET_HOSTNAME_SUCCESS = 'Set sensor hostname successfully!\n\n'
    MSG_IDENTIFY_NICS = 'Do you need help identifying network interfaces?'
    MSG_SELECT_INTERFACE = 'Select interface to configure'
    MSG_SELECT_BLINK_INTERFACE = 'Select capture interface to identify'
    MSG_BLINK_INTERFACE = '{} will blink for {} seconds'
    MSG_SELECT_SOURCE = 'Select address source'
    MSG_WELCOME_TITLE = 'Welcome to the sensor network interface controller utility!'


# the main dialog window used for the duration of this tool
d = Dialog(dialog='dialog', autowidgetsize=True)
d.set_background_title(Constants.MSG_BACKGROUND_TITLE)


###################################################################################################
# if the given interface is up, "ifdown" it
def network_stop(selected_iface):
    iface_state = "unknown"
    with open(f"/sys/class/net/{selected_iface}/operstate", 'r') as f:
        iface_state = f.readline().strip()

    if iface_state == "up":
        command = f"ifdown {selected_iface}"
    else:
        command = f"cat /sys/class/net/{selected_iface}/operstate"

    return run_subprocess(command, stderr=True)


###################################################################################################
# if the given interface is not up, "ifup" it
def network_start(selected_iface):
    iface_state = "unknown"
    with open(f"/sys/class/net/{selected_iface}/operstate", 'r') as f:
        iface_state = f.readline().strip()

    if iface_state != "up":
        command = f"ifup {selected_iface}"
    else:
        command = f"cat /sys/class/net/{selected_iface}/operstate"

    return run_subprocess(command, stderr=True)


###################################################################################################
# for a given interface, bring it down, write its new settings, and bring it back up
def write_and_display_results(interfaces, selected_iface):
    ecode, stop_results = network_stop(selected_iface)
    stop_results = list(
        filter(
            lambda x: (len(x) > 0)
            and ('Internet Systems' not in x)
            and ('Copyright' not in x)
            and ('All rights' not in x)
            and ('For info' not in x),
            stop_results,
        )
    )
    if ecode == 0:
        stop_text = Constants.MSG_NETWORK_STOP_SUCCESS
    else:
        stop_text = Constants.MSG_NETWORK_STOP_ERROR

    interfaces.writeInterfaces()

    ecode, start_results = network_start(selected_iface)
    start_results = list(
        filter(
            lambda x: (len(x.strip()) > 0)
            and ('Internet Systems' not in x)
            and ('Copyright' not in x)
            and ('All rights' not in x)
            and ('For info' not in x),
            start_results,
        )
    )
    if ecode == 0:
        start_text = Constants.MSG_NETWORK_START_SUCCESS
    else:
        start_text = Constants.MSG_NETWORK_START_ERROR

    d.msgbox(stop_text + "\n".join(stop_results) + "\n\n. . .\n\n" + start_text + "\n".join(start_results))


###################################################################################################
###################################################################################################
def main():
    locale.setlocale(locale.LC_ALL, '')

    # make sure we are being run as root
    if os.getuid() != 0:
        print(Constants.MSG_ERR_ROOT_REQUIRED)
        sys.exit(1)

    # what are we (sensor vs. aggregator)
    installation = Constants.DEV_UNKNOWN
    modeChoices = []
    try:
        with open(Constants.DEV_IDENTIFIER_FILE, 'r') as f:
            installation = f.readline().strip()
    except Exception:
        pass
    if installation == Constants.DEV_SENSOR:
        modeChoices = [Constants.MSG_CONFIG_INTERFACE, Constants.MSG_CONFIG_HOST, Constants.MSG_CONFIG_TIME_SYNC]
    elif installation == Constants.DEV_AGGREGATOR:
        modeChoices = [Constants.MSG_CONFIG_HOST, Constants.MSG_CONFIG_TIME_SYNC]
    else:
        print(Constants.MSG_ERR_DEV_INVALID)
        sys.exit(1)

    start_dir = os.getcwd()
    quit_flag = False

    while not quit_flag:
        os.chdir(start_dir)
        try:
            # welcome
            code = d.yesno(Constants.MSG_WELCOME_TITLE, yes_label="Continue", no_label="Quit")
            if code == Dialog.CANCEL or code == Dialog.ESC:
                quit_flag = True
                raise CancelledError

            # configuring an interface or setting the hostname?
            code, config_mode = d.menu(Constants.MSG_CONFIG_MODE, choices=modeChoices)
            if code != Dialog.OK:
                quit_flag = True
                raise CancelledError

            if config_mode == Constants.MSG_CONFIG_HOST[0]:
                # system hostname configuration ######################################################################################################

                # get current host/identification information
                ecode, host_get_output = run_subprocess('hostnamectl', stderr=True)
                if ecode == 0:
                    emsg_str = '\n'.join(host_get_output)
                    code = d.msgbox(text=f"{Constants.MSG_SET_HOSTNAME_CURRENT}{emsg_str}")

                    code, hostname_get_output = run_subprocess('hostname', stderr=False)
                    if (code == 0) and (len(hostname_get_output) > 0):
                        old_hostname = hostname_get_output[0].strip()
                    else:
                        old_hostname = ""

                    # user input for new hostname
                    while True:
                        code, new_hostname = d.inputbox("Sensor hostname", init=old_hostname)
                        if (code == Dialog.CANCEL) or (code == Dialog.ESC):
                            raise CancelledError
                        elif len(new_hostname) <= 0:
                            code = d.msgbox(text=Constants.MSG_MESSAGE_ERROR.format('Invalid hostname specified'))
                        else:
                            break

                    # set new hostname
                    ecode, host_set_output = run_subprocess(
                        f'hostnamectl set-hostname {new_hostname.strip()}', stderr=True
                    )
                    if ecode == 0:
                        ecode, host_get_output = run_subprocess('hostnamectl', stderr=True)
                        emsg_str = '\n'.join(host_get_output)
                        code = d.msgbox(text=f"{Constants.MSG_SET_HOSTNAME_SUCCESS}{emsg_str}")

                        # modify /etc/hosts 127.0.1.1 entry
                        local_hosts_re = re.compile(r"^\s*127\.0\.1\.1\b")
                        with fileinput.FileInput(Constants.ETC_HOSTS, inplace=True, backup='.bak') as file:
                            for line in file:
                                if local_hosts_re.search(line) is not None:
                                    print(f"127.0.1.1\t{new_hostname}")
                                else:
                                    print(line, end='')

                    else:
                        # error running hostnamectl set-hostname
                        emsg_str = '\n'.join(host_get_output)
                        code = d.msgbox(
                            text=Constants.MSG_MESSAGE_ERROR.format(f"Getting hostname failed with {ecode}:{emsg_str}")
                        )

                else:
                    # error running hostnamectl
                    emsg_str = '\n'.join(host_get_output)
                    code = d.msgbox(
                        text=Constants.MSG_MESSAGE_ERROR.format(f"Getting hostname failed with {ecode}:{emsg_str}")
                    )

            elif config_mode == Constants.MSG_CONFIG_TIME_SYNC[0]:
                # time synchronization configuration##################################################################################################
                time_sync_mode = ''
                code = Dialog.OK
                while (len(time_sync_mode) == 0) and (code == Dialog.OK):
                    code, time_sync_mode = d.radiolist(
                        Constants.MSG_TIME_SYNC_TYPE,
                        choices=[
                            (
                                Constants.TIME_SYNC_HTPDATE,
                                'Use a Malcolm server (or another HTTP/HTTPS server)',
                                (installation == Constants.DEV_SENSOR),
                            ),
                            (Constants.TIME_SYNC_NTP, 'Use an NTP server', False),
                        ],
                    )
                if code != Dialog.OK:
                    raise CancelledError

                elif time_sync_mode == Constants.TIME_SYNC_HTPDATE:
                    # sync time via htpdate, run via cron

                    http_host = ''
                    http_port = ''
                    while True:
                        # host/port for htpdate
                        code, values = d.form(
                            Constants.MSG_TIME_SYNC_HTPDATE_CONFIG,
                            [('Host', 1, 1, '', 1, 25, 30, 255), ('Port', 2, 1, '9200', 2, 25, 6, 5)],
                        )
                        values = [x.strip() for x in values]

                        if (code == Dialog.CANCEL) or (code == Dialog.ESC):
                            raise CancelledError

                        elif (len(values[0]) <= 0) or (len(values[1]) <= 0) or (not values[1].isnumeric()):
                            code = d.msgbox(text=Constants.MSG_ERR_BAD_HOST)

                        else:
                            http_host = values[0]
                            http_port = values[1]
                            break

                    # test with htpdate to see if we can connect
                    ecode, test_output = run_subprocess(
                        f"{Constants.TIME_SYNC_HTPDATE_TEST_COMMAND} {http_host}:{http_port}"
                    )
                    if ecode == 0:
                        emsg_str = '\n'.join(test_output)
                        code = d.msgbox(text=f"{Constants.MSG_TIME_SYNC_TEST_SUCCESS}{emsg_str}")
                    else:
                        emsg_str = '\n'.join(test_output)
                        code = d.yesno(
                            text=f"{Constants.MSG_TIME_SYNC_TEST_FAILURE}{emsg_str}",
                            yes_label="Ignore Error",
                            no_label="Start Over",
                        )
                        if code != Dialog.OK:
                            raise CancelledError

                    # get polling interval
                    code, htpdate_interval = d.rangebox(
                        "Time synchronization polling interval (minutes)", width=60, min=1, max=60, init=15
                    )
                    if code == Dialog.CANCEL or code == Dialog.ESC:
                        raise CancelledError

                    # stop and disable the ntp process
                    run_subprocess('/bin/systemctl stop ntp')
                    run_subprocess('/bin/systemctl disable ntp')

                    # write out htpdate file for cron
                    with open(Constants.TIME_SYNC_HTPDATE_CRON, 'w+') as f:
                        f.write('SHELL=/bin/bash\n')
                        f.write('PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin\n')
                        f.write('\n')
                        f.write(
                            f'*/{htpdate_interval} * * * * root {Constants.TIME_SYNC_HTPDATE_COMMAND} {http_host}:{http_port}\n'
                        )
                        f.write('\n')
                    code = d.msgbox(text=f"{Constants.MSG_TIME_SYNC_CONFIG_SUCCESS}")

                elif time_sync_mode == Constants.TIME_SYNC_NTP:
                    # sync time via ntp, run via service

                    ntp_host = ''
                    while True:
                        # host/port for ntp
                        code, values = d.form(Constants.MSG_TIME_SYNC_NTP_CONFIG, [('Host', 1, 1, '', 1, 25, 30, 255)])
                        values = [x.strip() for x in values]

                        if (code == Dialog.CANCEL) or (code == Dialog.ESC):
                            raise CancelledError

                        elif len(values[0]) <= 0:
                            code = d.msgbox(text=Constants.MSG_ERR_BAD_HOST)

                        else:
                            ntp_host = values[0]
                            break

                    # disable htpdate (no need to have two sync-ers) by removing it from cron
                    if os.path.exists(Constants.TIME_SYNC_HTPDATE_CRON):
                        os.remove(Constants.TIME_SYNC_HTPDATE_CRON)

                    # write out ntp config file (changing values in place)
                    server_written = False
                    server_re = re.compile(r"^\s*#?\s*(server)\s*.+?$")
                    with fileinput.FileInput(Constants.TIME_SYNC_NTP_CONFIG, inplace=True, backup='.bak') as file:
                        for line in file:
                            line = line.rstrip("\n")
                            server_match = server_re.search(line)
                            if server_match is not None:
                                if not server_written:
                                    print(f'server {ntp_host}')
                                    server_written = True
                                else:
                                    print(f"{'' if line.startswith('#') else '#'}{line}")
                            else:
                                print(line)

                    # enable and start the ntp process
                    run_subprocess('/bin/systemctl stop ntp')
                    run_subprocess('/bin/systemctl enable ntp')
                    ecode, start_output = run_subprocess('/bin/systemctl start ntp', stderr=True)
                    if ecode == 0:
                        code = d.msgbox(text=f"{Constants.MSG_TIME_SYNC_CONFIG_SUCCESS}")
                    else:
                        code = d.msgbox(text=Constants.MSG_MESSAGE_ERROR.format('\n'.join(start_output)))

                else:
                    raise CancelledError

            else:
                # interface IP address configuration #################################################################################################

                # read configuration from /etc/network/interfaces.d/sensor (or the default /etc/network/interfaces if for some reason it doesn't exist)
                interfaces_path = (
                    Constants.SENSOR_INTERFACES_CONFIG if os.path.isfile(Constants.SENSOR_INTERFACES_CONFIG) else None
                )
                interfaces = Interfaces(interfaces_path=interfaces_path, backup_path=Constants.SENSOR_BACKUP_CONFIG)

                # determine a list of available (non-virtual) adapters
                available_adapters = get_available_adapters()

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

                code, tag = d.menu(
                    Constants.MSG_SELECT_INTERFACE,
                    choices=[(adapter.name, adapter.description) for adapter in available_adapters],
                )
                if code != Dialog.OK:
                    raise CancelledError

                # which interface are wer configuring?
                selected_iface = tag

                # check if selected_iface already has entry in system configuration
                configured_iface = None
                for adapter in interfaces.adapters:
                    item = adapter.export()
                    if item['name'] == selected_iface:
                        configured_iface = item
                        break

                # if it was already configured, remove from configured adapter list to be replaced by the new settings
                if configured_iface is not None:
                    interfaces.removeAdapterByName(selected_iface)

                # static, dynamic, or unassigned IP address?
                code, tag = d.menu(
                    Constants.MSG_SELECT_SOURCE,
                    choices=[
                        (Constants.STATIC, 'Static IP (recommended)'),
                        (Constants.DHCP, 'Dynamic IP'),
                        (Constants.UNASSIGNED, 'No IP'),
                    ],
                )
                if code != Dialog.OK:
                    raise CancelledError

                if tag == Constants.DHCP:
                    # DHCP ##########################################################
                    code = d.infobox(Constants.MSG_MESSAGE_DHCP)

                    interfaces.addAdapter(
                        {
                            'name': selected_iface,
                            'auto': True,
                            'hotplug': True,
                            'addrFam': 'inet',
                            'source': Constants.DHCP,
                        },
                        index=0,
                        interfaces_path=interfaces_path,
                    )

                    write_and_display_results(interfaces, selected_iface)

                elif tag == Constants.UNASSIGNED:
                    # unassigned (but up) ###########################################
                    code = d.infobox(Constants.MSG_MESSAGE_UNASSIGNED)

                    interfaces.addAdapter(
                        {
                            'name': selected_iface,
                            'auto': True,
                            'hotplug': True,
                            'addrFam': 'inet',
                            'source': Constants.UNASSIGNED,
                            'pre-up': 'ip link set dev $IFACE up',
                            'post-up': '/usr/local/bin/nic-capture-setup.sh $IFACE',
                            'post-down': 'ip link set dev $IFACE down',
                        },
                        index=0,
                        interfaces_path=interfaces_path,
                    )

                    write_and_display_results(interfaces, selected_iface)

                elif tag == Constants.STATIC:
                    # static ########################################################

                    # see if the adapter currently has an IP address, use it as a starting suggestion
                    try:
                        previous_ip = netifaces.ifaddresses(selected_iface)[netifaces.AF_INET][0]['addr']
                        previous_gw = '.'.join(previous_ip.split('.')[0:3] + ['1'])
                    except Exception as e:
                        code = d.msgbox(text=Constants.MSG_MESSAGE_ERROR.format(e))
                        previous_ip = "192.168.0.10"
                        previous_gw = "192.168.0.1"
                    if previous_ip.startswith('172.'):
                        previous_mask = "255.255.0.0"
                    elif previous_ip.startswith('10.'):
                        previous_mask = "255.0.0.0"
                    else:
                        previous_mask = "255.255.255.0"

                    while True:
                        code, values = d.form(
                            Constants.MSG_CONFIG_STATIC_TITLE,
                            [
                                # title, row_1, column_1, field, row_1, column_20, field_length, input_length
                                ('IP Address', 1, 1, previous_ip, 1, 20, 15, 15),
                                # title, row_2, column_1, field, row_2, column_20, field_length, input_length
                                ('Netmask', 2, 1, previous_mask, 2, 20, 15, 15),
                                # title, row_3, column_1, field, row_3, column_20, field_length, input_length
                                ('Gateway', 3, 1, previous_gw, 3, 20, 15, 15),
                            ],
                        )
                        values = [x.strip() for x in values]

                        if code == Dialog.CANCEL or code == Dialog.ESC:
                            raise CancelledError

                        elif (len(values[0]) <= 0) or (len(values[1]) <= 0) or (len(values[2]) <= 0):
                            code = d.msgbox(
                                text=Constants.MSG_MESSAGE_ERROR.format("Invalid value(s), please try again")
                            )

                        else:
                            code = d.infobox(Constants.MSG_MESSAGE_STATIC)

                            interfaces.addAdapter(
                                {
                                    'name': selected_iface,
                                    'auto': True,
                                    'hotplug': True,
                                    'addrFam': 'inet',
                                    'source': Constants.STATIC,
                                    'address': values[0],
                                    'netmask': values[1],
                                    'gateway': values[2],
                                },
                                index=0,
                                interfaces_path=interfaces_path,
                            )

                            write_and_display_results(interfaces, selected_iface)
                            break

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
