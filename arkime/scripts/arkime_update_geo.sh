#!/bin/sh

# Copyright (c) 2023 Battelle Energy Alliance, LLC.  All rights reserved.

cd "${ARKIME_DIR:-/opt/arkime}"/etc

wget -nv --no-check-certificate -O ipv4-address-space.csv_new https://www.iana.org/assignments/ipv4-address-space/ipv4-address-space.csv && \
  mv -f ipv4-address-space.csv_new ipv4-address-space.csv || \
  rm -f ipv4-address-space.csv_new

wget -nv -O oui.txt_new https://gitlab.com/wireshark/wireshark/raw/release-4.0/manuf && \
  mv -f oui.txt_new oui.txt || \
  rm -f oui.txt_new

# MaxMind now requires a (free) license key to download the free versions of
# their GeoIP databases. This should be provided as an environment variable.
#   see https://dev.maxmind.com/geoip/geoipupdate/#Direct_Downloads
#   see https://github.com/arkime/arkime/issues/1350
#   see https://github.com/arkime/arkime/issues/1352
if [ ${#MAXMIND_GEOIP_DB_LICENSE_KEY} -gt 1 ]; then
  for DB in ASN Country City; do
    curl -s -S -L -o "GeoLite2-$DB.mmdb.tar.gz" "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-$DB&license_key=$MAXMIND_GEOIP_DB_LICENSE_KEY&suffix=tar.gz" && \
      tar xf "GeoLite2-$DB.mmdb.tar.gz" --wildcards --no-anchored '*.mmdb' --strip=1 && \
      chmod 644 "GeoLite2-$DB.mmdb" && \
      rm -f "GeoLite2-$DB.mmdb.tar.gz"
  done
fi
