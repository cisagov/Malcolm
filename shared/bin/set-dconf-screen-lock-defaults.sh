#!/bin/bash

# Copyright (c) 2025 Battelle Energy Alliance, LLC.  All rights reserved.

grep -q boot=live /proc/cmdline && exit 0

if [[ -f "$HOME"/.config/light-locker-dconf-defaults.conf ]]; then
  sleep 30
  pushd "$HOME"/.config >/dev/null 2>&1

  dconf load / < "$HOME"/.config/light-locker-dconf-defaults.conf && \
    dconf update && \
    rm -f "$HOME"/.config/light-locker-dconf-defaults.conf

  popd >/dev/null 2>&1
fi
