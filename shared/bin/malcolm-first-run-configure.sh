#!/bin/bash

# Copyright (c) 2023 Battelle Energy Alliance, LLC.  All rights reserved.

grep -q boot=live /proc/cmdline && exit 0

if [[ -d "$HOME"/Malcolm ]] && [[ ! -f "$HOME"/Malcolm/.configured ]] ; then
    tilix \
      --title="Malcolm Configuration" \
      --maximize \
      -e /bin/bash -l -c "/usr/bin/python3 ~/Malcolm/scripts/install.py --configure"
fi
