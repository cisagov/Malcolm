#!/bin/bash

# don't run kiosk mode if we're running as a "live boot"
grep -q boot=live /proc/cmdline && exit 0

# don't run kiosk mode if we haven't been configured yet
MAIN_USER="$(id -nu 1000)"
if [[ -n $MAIN_USER ]]; then
  MAIN_USER_HOME="$(getent passwd "$MAIN_USER" | cut -d: -f6)"
  [[ -f "$MAIN_USER_HOME"/Malcolm/.configured ]] || exit 0
fi

# start firefox in kiosk mode and load the performance metrics dashboard
/usr/bin/firefox --setDefaultBrowser --no-remote --private --kiosk http://127.0.0.1:5000
