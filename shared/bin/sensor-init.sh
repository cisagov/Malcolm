#!/bin/bash

# Copyright (c) 2019 Battelle Energy Alliance, LLC.  All rights reserved.

SCRIPT_PATH="$(dirname $(realpath -e "${BASH_SOURCE[0]}"))"

echo "sensor" > /etc/installer

if [[ -r "$SCRIPT_PATH"/common-init.sh ]]; then
  . "$SCRIPT_PATH"/common-init.sh

  # remove default accounts/groups we don't want, create/set directories for non-user users for stig to not complain
  CleanDefaultAccounts

  # get a list of the hardware interfaces
  PopulateInterfaces

  # set up some sensor-specific stuff
  if [[ -d /opt/sensor ]]; then
    # set ownership for /opt/sensor files for sensor UID:GID
    chown -R 1000:1000 /opt/sensor
    find /opt/sensor/ -type d -exec chmod 750 "{}" \;
    find /opt/sensor/ -type f -exec chmod 640 "{}" \;
    find /opt/sensor/ -type f -name "*.sh" -exec chmod 750 "{}" \;
    find /opt/sensor/ -type f -name "*.keystore" -exec chmod 600 "{}" \;

    if [[ -f /opt/sensor/sensor_ctl/control_vars.conf ]]; then
      # if the capture interface hasn't been set in control_vars.conf, set it now
      if grep --quiet CAPTURE_INTERFACE=xxxx /opt/sensor/sensor_ctl/control_vars.conf; then
        CAP_IFACE="$(DetermineCaptureInterface)"
        if [[ -n "${CAP_IFACE}" ]]; then
          sed -i "s/CAPTURE_INTERFACE=xxxx/CAPTURE_INTERFACE=${CAP_IFACE}/g" /opt/sensor/sensor_ctl/control_vars.conf
        fi
      fi
    fi
  fi

  # broctl won't like being run by a non-root user unless the whole stupid thing is owned by the non-root user
  if [[ -d /opt/bro.orig ]]; then
    # as such, we're going to reset bro to a "clean" state after each reboot. the config files will get
    # regenerated when we are about to deploy bro itself
    [[ -d /opt/bro ]] && rm -rf /opt/bro
    rsync -a /opt/bro.orig/ /opt/bro
  fi
  if [[ -d /opt/bro ]]; then
    chown -R 1000:1000 /opt/bro/*
    [[ -f /opt/bro/bin/bro ]] && setcap 'CAP_NET_RAW+eip CAP_NET_ADMIN+eip' /opt/bro/bin/bro
  fi

  # if the network configuration files for the interfaces haven't been set to come up on boot, configure that now.
  InitializeNetworking

  # fix some permisions to make sure things belong to the right person
  MAIN_USER="$(id -nu 1000)"
  [[ -n $MAIN_USER ]] && FixPermissions "$MAIN_USER"

  # chromium tries to call home despite my best efforts
  BadGoogle

  exit 0
else
  exit 1
fi

