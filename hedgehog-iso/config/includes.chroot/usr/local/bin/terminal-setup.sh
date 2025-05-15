#!/bin/bash

[[ -r ~/.config/tilix.dconf ]] && dconf load /com/gexperts/Tilix/ < ~/.config/tilix.dconf && rm -f ~/.config/tilix.dconf
