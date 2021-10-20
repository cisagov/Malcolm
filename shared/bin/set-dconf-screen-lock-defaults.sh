#!/bin/bash

# Copyright (c) 2021 Battelle Energy Alliance, LLC.  All rights reserved.

grep -q boot=live /proc/cmdline && exit 0

if [[ -f /etc/light-locker-dconf-defaults.conf ]]; then



fi