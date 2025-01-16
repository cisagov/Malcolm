#!/bin/sh

# Copyright (c) 2025 Battelle Energy Alliance, LLC.  All rights reserved.

cd "${ARKIME_DIR:-/opt/arkime}"/etc

wget -nv --no-check-certificate -O ipv4-address-space.csv_new https://www.iana.org/assignments/ipv4-address-space/ipv4-address-space.csv && \
  mv -f ipv4-address-space.csv_new ipv4-address-space.csv || \
  rm -f ipv4-address-space.csv_new

wget -nv -O oui.txt_new https://www.wireshark.org/download/automated/data/manuf && \
  mv -f oui.txt_new oui.txt || \
  rm -f oui.txt_new

/usr/local/bin/maxmind-mmdb-download.sh -o "$(pwd)"
