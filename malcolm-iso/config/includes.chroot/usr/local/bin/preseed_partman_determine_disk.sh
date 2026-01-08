#!/bin/sh

parted_devices | egrep "^($(find /sys/block -mindepth 1 -maxdepth 1 -type l \( -name '[hs]d*' -o -name 'nvme*' \) -exec ls -l '{}' ';' | grep -v "usb" | sed 's@^.*\([hs]d[a-z]\+\|nvme[0-9]\+\).*$@/dev/\1@' | sed -e :a -e '$!N; s/\n/|/; ta'))" | sort -k2n | head -1 | cut -f1
