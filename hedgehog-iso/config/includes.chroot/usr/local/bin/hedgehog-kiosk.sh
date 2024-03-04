#!/bin/bash

# don't run kiosk mode if we're running as a "live boot"
grep -q boot=live /proc/cmdline && exit 0

# don't run kiosk mode if we haven't been configured for capture yet
grep -q CAPTURE_INTERFACE=lo /opt/sensor/sensor_ctl/control_vars.conf && exit 0

# start firefox in kiosk mode and load the performance metrics dashboard
/usr/bin/firefox --setDefaultBrowser --no-remote --private --kiosk http://127.0.0.1:5000
