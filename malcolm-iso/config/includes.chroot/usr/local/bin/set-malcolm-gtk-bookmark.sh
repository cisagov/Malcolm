#!/bin/bash

# Copyright (c) 2024 Battelle Energy Alliance, LLC.  All rights reserved.

if ! grep -q Malcolm$ "$HOME"/.config/gtk-3.0/bookmarks && [[ -d "$HOME"/Malcolm ]]; then
  mkdir -p "$HOME"/.config/gtk-3.0/
  echo -e "\nfile://$HOME/Malcolm" >> "$HOME"/.config/gtk-3.0/bookmarks
fi
