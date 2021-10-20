#!/bin/bash

# Copyright (c) 2021 Battelle Energy Alliance, LLC.  All rights reserved.

grep -q boot=live /proc/cmdline && exit 0

if [[ -f "$HOME"/.config/light-locker-dconf-defaults.conf ]]; then
  dconf load / < "$HOME"/.config/light-locker-dconf-defaults.conf && \
  dconf update && \
  rm -f "$HOME"/.config/light-locker-dconf-defaults.conf
fi
