#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2026 Battelle Energy Alliance, LLC.  All rights reserved.

# script for some misc. Malcolm/Hedgehog system configuration stuff:
#   - Time Sync
#   - Host Name
#   - SSH
#   - Identify network interfaces

import os
import sys
import fileinput
import re

from dialog import Dialog
from malcolm_utils import run_subprocess, get_available_adapters, identify_adapter


ETC_HOSTS = '/etc/hosts'
MSG_BLINK_INTERFACE = '{} will blink for {} seconds'
MSG_CONFIG_HOST = ('Hostname', 'Configure system hostname')
MSG_CONFIG_INTERFACE_ID = ('Interface', 'Identify network interfaces')
MSG_CONFIG_SSH = ('SSH Authentication', 'Configure SSH authentication')
MSG_CONFIG_SSH_SUCCESS = 'SSH authentication configured successfully!\n\n'
MSG_CONFIG_TIME_SYNC = ('Time Sync', 'Configure time synchronization')
MSG_ERR_BAD_HOST = 'Invalid host/URL or port'
MSG_ERR_ROOT_REQUIRED = 'Configuring {} requires elevated privileges, run as root or with "sudo"'
MSG_MESSAGE_ERROR = 'Error: {}\n\nPlease try again.'
MSG_SELECT_BLINK_INTERFACE = 'Select capture interface to identify'
MSG_SET_HOSTNAME_CURRENT = 'Current system identification information\n\n'
MSG_SET_HOSTNAME_SUCCESS = 'Set system hostname successfully!\n\n'
MSG_SSH_PASSWORD_AUTH = 'Allow SSH password authentication?'
MSG_TIME_SYNC_CONFIG_SUCCESS = 'Time synchronization configured successfully!\n\n'
MSG_TIME_SYNC_HTPDATE_CONFIG = 'Provide URL for HTTP/HTTPS Server Time Sync'
MSG_TIME_SYNC_NTP_CONFIG = 'Provide values for NTP Server'
MSG_TIME_SYNC_TEST_FAILURE = 'Server time could not be retrieved. Ignore error?\n\n'
MSG_TIME_SYNC_TEST_SUCCESS = 'Server time retrieved successfully!\n\n'
MSG_TIME_SYNC_TYPE = 'Select time synchronization method'
SSHD_CONFIG_FILE = "/etc/ssh/sshd_config"
TIME_SYNC_HTPDATE = 'htpdate'
TIME_SYNC_HTPDATE_INITIAL_COMMAND = '/usr/sbin/htpdate -4 -l -s'
TIME_SYNC_HTPDATE_PERIODIC_COMMAND = '/usr/sbin/htpdate -4 -a -l'
TIME_SYNC_HTPDATE_CRON = '/etc/cron.d/htpdate'
TIME_SYNC_HTPDATE_DEFAULT_URL = 'https://1.1.1.1:443'
TIME_SYNC_HTPDATE_DEFAULT_INTERVAL = 15
TIME_SYNC_HTPDATE_TEST_COMMAND = '/usr/sbin/htpdate -4 -a -d'
TIME_SYNC_NTP = 'ntp'
TIME_SYNC_NTP_CONFIG = '/etc/ntpsec/ntp.conf'


###################################################################################################
class CancelledError(Exception):
    """Raised when user cancels the operation"""

    pass


def clearquit():
    os.system('clear')
    sys.exit(0)


def get_htpdate_config():
    """Parse the htpdate cron entry written by this script, if any.

    Returns:
        tuple: (url, interval_minutes), either or both of which may be None
    """
    url = None
    interval = None
    cron_re = re.compile(r"^\s*\*/(\d+)\s+(?:\S+\s+){4}root\s+\S*htpdate\s+(?:-\S+\s+)*(\S+)\s*$")
    try:
        with open(TIME_SYNC_HTPDATE_CRON) as f:
            for line in f:
                cron_match = cron_re.search(line)
                if cron_match is not None:
                    interval = int(cron_match.group(1))
                    url = cron_match.group(2)
                    break
    except (OSError, ValueError):
        pass
    return url, interval


def get_ntp_config():
    """Parse the NTP configuration file for the active server, if any.

    Returns:
        str: the host of the first uncommented 'server' directive, or None
    """
    server_re = re.compile(r"^\s*server\s+(\S+)")
    try:
        with open(TIME_SYNC_NTP_CONFIG) as f:
            for line in f:
                server_match = server_re.search(line)
                if server_match is not None:
                    return server_match.group(1)
    except OSError:
        pass
    return None


# the main dialog window used for the duration of this tool
d = Dialog(dialog='dialog', autowidgetsize=True)


###################################################################################################
def main():
    modeChoices = (
        MSG_CONFIG_INTERFACE_ID,
        MSG_CONFIG_HOST,
        MSG_CONFIG_TIME_SYNC,
        MSG_CONFIG_SSH,
    )

    start_dir = os.getcwd()
    quit_flag = False

    while not quit_flag:
        os.chdir(start_dir)
        try:
            # configuring an interface or setting the hostname?
            code, config_mode = d.menu('System Quickstart', choices=modeChoices)
            if code != Dialog.OK:
                quit_flag = True
                raise CancelledError

            if config_mode in (MSG_CONFIG_HOST[0], MSG_CONFIG_TIME_SYNC[0], MSG_CONFIG_SSH[0]) and (os.getuid() != 0):
                code = d.msgbox(text=MSG_ERR_ROOT_REQUIRED.format(config_mode.lower()))
                continue

            elif config_mode == MSG_CONFIG_HOST[0]:
                # system hostname configuration ######################################################################################################

                # get current host/identification information
                ecode, host_get_output = run_subprocess('hostnamectl', stderr=True)
                if ecode == 0:
                    emsg_str = '\n'.join(host_get_output)
                    code = d.msgbox(text=f"{MSG_SET_HOSTNAME_CURRENT}{emsg_str}")

                    code, hostname_get_output = run_subprocess('hostname', stderr=False)
                    if (code == 0) and (len(hostname_get_output) > 0):
                        old_hostname = hostname_get_output[0].strip()
                    else:
                        old_hostname = ""

                    # user input for new hostname
                    while True:
                        code, new_hostname = d.inputbox("System hostname", init=old_hostname)
                        if (code == Dialog.CANCEL) or (code == Dialog.ESC):
                            raise CancelledError
                        elif len(new_hostname) <= 0:
                            code = d.msgbox(text=MSG_MESSAGE_ERROR.format('Invalid hostname specified'))
                        else:
                            break

                    # set new hostname
                    ecode, host_set_output = run_subprocess(
                        f'hostnamectl set-hostname {new_hostname.strip()}', stderr=True
                    )
                    if ecode == 0:
                        ecode, host_get_output = run_subprocess('hostnamectl', stderr=True)
                        emsg_str = '\n'.join(host_get_output)
                        code = d.msgbox(text=f"{MSG_SET_HOSTNAME_SUCCESS}{emsg_str}")

                        # modify /etc/hosts 127.0.1.1 entry
                        local_hosts_re = re.compile(r"^\s*127\.0\.1\.1\b")
                        with fileinput.FileInput(ETC_HOSTS, inplace=True, backup='.bak') as file:
                            for line in file:
                                if local_hosts_re.search(line) is not None:
                                    print(f"127.0.1.1\t{new_hostname}")
                                else:
                                    print(line, end='')

                    else:
                        # error running hostnamectl set-hostname
                        emsg_str = '\n'.join(host_get_output)
                        code = d.msgbox(
                            text=MSG_MESSAGE_ERROR.format(f"Getting hostname failed with {ecode}:{emsg_str}")
                        )

                else:
                    # error running hostnamectl
                    emsg_str = '\n'.join(host_get_output)
                    code = d.msgbox(text=MSG_MESSAGE_ERROR.format(f"Getting hostname failed with {ecode}:{emsg_str}"))

            elif config_mode == MSG_CONFIG_TIME_SYNC[0]:
                # time synchronization configuration##################################################################################################

                # Prepopulate values from existing configuration, if present.
                # A parseable htpdate cron entry indicates htpdate is the active method.
                # Configuring NTP removes that cron file; otherwise, an uncommented
                # "server" line in ntp.conf indicates NTP.
                prev_htpdate_url, prev_htpdate_interval = get_htpdate_config()
                prev_ntp_host = get_ntp_config()
                htpdate_selected = (prev_htpdate_url is not None) or (prev_ntp_host is None)

                time_sync_mode = ''
                code = Dialog.OK
                while (len(time_sync_mode) == 0) and (code == Dialog.OK):
                    code, time_sync_mode = d.radiolist(
                        MSG_TIME_SYNC_TYPE,
                        choices=[
                            (
                                TIME_SYNC_HTPDATE,
                                'Use a Malcolm server (or another HTTP/HTTPS server)',
                                htpdate_selected,
                            ),
                            (TIME_SYNC_NTP, 'Use an NTP server', not htpdate_selected),
                        ],
                    )
                if code != Dialog.OK:
                    raise CancelledError

                elif time_sync_mode == TIME_SYNC_HTPDATE:
                    # sync time via htpdate, run via cron

                    http_url = ''
                    while True:
                        # http/https URL for htpdate
                        code, values = d.form(
                            MSG_TIME_SYNC_HTPDATE_CONFIG,
                            [
                                (
                                    'URL',
                                    1,
                                    1,
                                    prev_htpdate_url if prev_htpdate_url else TIME_SYNC_HTPDATE_DEFAULT_URL,
                                    1,
                                    25,
                                    30,
                                    255,
                                )
                            ],
                        )
                        values = [x.strip() for x in values]

                        if (code == Dialog.CANCEL) or (code == Dialog.ESC):
                            raise CancelledError

                        elif len(values[0]) <= 0:
                            code = d.msgbox(text=MSG_ERR_BAD_HOST)

                        else:
                            http_url = values[0]
                            break

                    # test with htpdate to see if we can connect
                    ecode, test_output = run_subprocess(f"{TIME_SYNC_HTPDATE_TEST_COMMAND} {http_url}")
                    if ecode == 0:
                        emsg_str = '\n'.join(test_output)
                        code = d.msgbox(text=f"{MSG_TIME_SYNC_TEST_SUCCESS}{emsg_str}")
                    else:
                        emsg_str = '\n'.join(test_output)
                        code = d.yesno(
                            text=f"{MSG_TIME_SYNC_TEST_FAILURE}{emsg_str}",
                            yes_label="Ignore Error",
                            no_label="Start Over",
                        )
                        if code != Dialog.OK:
                            raise CancelledError

                    # get polling interval
                    code, htpdate_interval = d.rangebox(
                        "Time synchronization polling interval (minutes)",
                        width=60,
                        min=1,
                        max=60,
                        init=prev_htpdate_interval if prev_htpdate_interval else TIME_SYNC_HTPDATE_DEFAULT_INTERVAL,
                    )
                    if code == Dialog.CANCEL or code == Dialog.ESC:
                        raise CancelledError

                    # stop and disable the ntp process
                    run_subprocess('/bin/systemctl stop ntpsec')
                    run_subprocess('/bin/systemctl disable ntpsec')

                    # write out htpdate file for cron
                    with open(TIME_SYNC_HTPDATE_CRON, 'w+') as f:
                        f.write('SHELL=/bin/bash\n')
                        f.write('PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin\n')
                        f.write('\n')
                        f.write(f'*/{htpdate_interval} * * * * root {TIME_SYNC_HTPDATE_PERIODIC_COMMAND} {http_url}\n')
                        f.write('\n')

                    # now actually do the sync "for real" one time (so we can get in sync before waiting for the interval)
                    ecode, sync_output = run_subprocess(f"{TIME_SYNC_HTPDATE_INITIAL_COMMAND} {http_url}")
                    if ecode == 0 and os.path.isfile('/usr/sbin/fake-hwclock'):
                        run_subprocess('/usr/sbin/fake-hwclock save')
                    emsg_str = '\n'.join(sync_output)
                    code = d.msgbox(text=f"{MSG_TIME_SYNC_CONFIG_SUCCESS if (ecode == 0) else ''}{emsg_str}")

                elif time_sync_mode == TIME_SYNC_NTP:
                    # sync time via ntp, run via service

                    ntp_host = ''
                    while True:
                        # host/port for ntp
                        code, values = d.form(
                            MSG_TIME_SYNC_NTP_CONFIG,
                            [('Host', 1, 1, prev_ntp_host if prev_ntp_host else '', 1, 25, 30, 255)],
                        )
                        values = [x.strip() for x in values]

                        if (code == Dialog.CANCEL) or (code == Dialog.ESC):
                            raise CancelledError

                        elif len(values[0]) <= 0:
                            code = d.msgbox(text=MSG_ERR_BAD_HOST)

                        else:
                            ntp_host = values[0]
                            break

                    # disable htpdate (no need to have two sync-ers) by removing it from cron
                    if os.path.exists(TIME_SYNC_HTPDATE_CRON):
                        os.remove(TIME_SYNC_HTPDATE_CRON)

                    # write out ntp config file (changing values in place)
                    server_written = False
                    server_re = re.compile(r"^\s*#?\s*(server)\s*.+?$")
                    with fileinput.FileInput(TIME_SYNC_NTP_CONFIG, inplace=True, backup='.bak') as file:
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
                    run_subprocess('/bin/systemctl stop ntpsec')
                    run_subprocess('/bin/systemctl enable ntpsec')
                    ecode, start_output = run_subprocess('/bin/systemctl start ntpsec', stderr=True)

                    if ecode == 0:
                        wait_ecode, _ = run_subprocess(
                            '/usr/sbin/ntpwait -n 5 -s 2',
                            stderr=True,
                        )
                        if wait_ecode == 0 and os.path.isfile('/usr/sbin/fake-hwclock'):
                            run_subprocess('/usr/sbin/fake-hwclock save')

                        code = d.msgbox(text=MSG_TIME_SYNC_CONFIG_SUCCESS)
                    else:
                        code = d.msgbox(text=MSG_MESSAGE_ERROR.format('\n'.join(start_output)))

                else:
                    raise CancelledError

            elif config_mode == MSG_CONFIG_SSH[0]:
                # configure SSH authentication options
                code = d.yesno(
                    MSG_SSH_PASSWORD_AUTH,
                    # "Human sacrifice! Dogs and cats living together! Mass hysteria!"
                    # (yes == No because I want "No" to be the default)
                    yes_label="No",
                    no_label="Yes",
                )
                if code == Dialog.OK or code == Dialog.CANCEL:
                    password_re = re.compile(r'^\s*#*\s*PasswordAuthentication\s+(yes|no)')
                    with fileinput.FileInput(SSHD_CONFIG_FILE, inplace=True, backup='.bak') as file:
                        for line in file:
                            if password_re.match(line):
                                line = f"PasswordAuthentication {'yes' if code == Dialog.CANCEL else 'no'}"
                            print(line)
                    # restart the ssh process
                    ecode, start_output = run_subprocess('/bin/systemctl restart ssh', stderr=True)
                    if ecode == 0:
                        code = d.msgbox(text=f"{MSG_CONFIG_SSH_SUCCESS}")
                    else:
                        code = d.msgbox(text=MSG_MESSAGE_ERROR.format('\n'.join(start_output)))
                else:
                    raise CancelledError

            else:
                # interface identification ###########################################################################################################

                available_adapters = get_available_adapters()

                code, blinky_iface = d.radiolist(
                    MSG_SELECT_BLINK_INTERFACE,
                    choices=[
                        (adapter.name, adapter.description, i == 0) for i, adapter in enumerate(available_adapters)
                    ],
                )
                if (code == Dialog.OK) and (len(blinky_iface) > 0):
                    blink_seconds = 10
                    if (
                        d.yesno(
                            MSG_BLINK_INTERFACE.format(blinky_iface, blink_seconds),
                            yes_label="Ready",
                            no_label="Cancel",
                        )
                        == Dialog.OK
                    ):
                        identify_adapter(adapter=blinky_iface, duration=blink_seconds, background=True)
                        code = d.pause(f"Identifying {blinky_iface}", seconds=blink_seconds, width=60, height=15)

        except CancelledError:
            # just start over
            continue

        except Exception as e:
            d.msgbox(text=MSG_MESSAGE_ERROR.format(e))
            raise


if __name__ == '__main__':
    main()
    clearquit()
