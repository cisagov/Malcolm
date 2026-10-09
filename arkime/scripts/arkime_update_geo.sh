#!/bin/sh

# Copyright (c) 2026 Battelle Energy Alliance, LLC.  All rights reserved.

cd "${ARKIME_DIR:-/opt/arkime}"/etc

wget -nv --no-check-certificate --timeout=30 --tries=2 -O ipv4-address-space.csv_new https://www.iana.org/assignments/ipv4-address-space/ipv4-address-space.csv && \
  mv -f ipv4-address-space.csv_new ipv4-address-space.csv || \
  rm -f ipv4-address-space.csv_new

wget -nv --timeout=30 --tries=2 -O oui.txt_new https://www.wireshark.org/download/automated/data/manuf && \
  mv -f oui.txt_new oui.txt || \
  rm -f oui.txt_new

/usr/local/bin/maxmind-mmdb-download.sh -o "$(pwd)"
download_status=$?

# Arkime retains its own local databases. A separate copy is published to the
# shared volume for Logstash only when that volume has been mounted.
shared_dir="${MALCOLM_SHARED_GEOIP_DIR:-/var/local/geoip}"
if [ -d "$shared_dir" ]; then
  /usr/local/bin/publish-shared-geoip.sh "$(pwd)" "$shared_dir" || exit 1
fi
exit "$download_status"
