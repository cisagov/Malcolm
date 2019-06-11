#!/bin/sh

# Copyright (c) 2019 Battelle Energy Alliance, LLC.  All rights reserved.


cd "/data/moloch/etc"

wget -nv --no-check-certificate -O ipv4-address-space.csv_new https://www.iana.org/assignments/ipv4-address-space/ipv4-address-space.csv && \
  mv -f ipv4-address-space.csv_new ipv4-address-space.csv || \
  rm -f ipv4-address-space.csv_new

wget -nv -O GeoLite2-Country.mmdb.gz 'https://updates.maxmind.com/app/update_secure?edition_id=GeoLite2-Country' && \
  (/bin/rm -f GeoLite2-Country.mmdb && zcat GeoLite2-Country.mmdb.gz > GeoLite2-Country.mmdb) || \
  rm -f GeoLite2-Country.mmdb.gz

wget -nv -O GeoLite2-ASN.mmdb.gz 'https://updates.maxmind.com/app/update_secure?edition_id=GeoLite2-ASN' && \
  (/bin/rm -f GeoLite2-ASN.mmdb && zcat GeoLite2-ASN.mmdb.gz > GeoLite2-ASN.mmdb) || \
  rm -f GeoLite2-ASN.mmdb.gz

wget -nv -O oui.txt_new https://raw.githubusercontent.com/wireshark/wireshark/master/manuf && \
  mv -f oui.txt_new oui.txt || \
  rm -f oui.txt_new

