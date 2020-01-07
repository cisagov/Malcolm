#!/bin/bash

# Copyright (c) 2019 Battelle Energy Alliance, LLC.  All rights reserved.

OUTPUT_DIR="/tmp"
unset VERBOSE

while getopts o:v opts; do
   case ${opts} in
      o) OUTPUT_DIR=${OPTARG} ;;
      v) VERBOSE=1 ;;
   esac
done

set -e
if [[ -n $VERBOSE ]]; then
  set -x
fi

apt-get -q update

mkdir -p /opt
curl -L -o /tmp/moloch.tar.gz "https://github.com/aol/moloch/archive/v$MOLOCH_VERSION.tar.gz"

cd /tmp
tar -xvf "moloch.tar.gz"
rm -f "moloch.tar.gz"

cd "./moloch-"$MOLOCH_VERSION

export PATH="$MOLOCHDIR/bin:/tmp/moloch-$MOLOCH_VERSION/node_modules/.bin:${PATH}"

./easybutton-build.sh --dir "$MOLOCHDIR"

npm -g config set user root

make install

cp -r ./capture/plugins/lua/samples "$MOLOCHDIR"/lua

npm install license-checker; release/notice.txt.pl $MOLOCHDIR NOTICE release/CAPTURENOTICE > $MOLOCHDIR/NOTICE.txt

curl -L -o "$MOLOCHDIR"/etc/ipv4-address-space.csv "https://www.iana.org/assignments/ipv4-address-space/ipv4-address-space.csv"
curl -L -o "$MOLOCHDIR"/etc/oui.txt "https://raw.githubusercontent.com/wireshark/wireshark/master/manuf"

# todo MaxMind now requires an API license to download databases, not sure how this will be handled
# this is a temporary, not-great solution as these are old out-of-date files used for Moloch testing
#   see https://dev.maxmind.com/geoip/geoipupdate/#Direct_Downloads
#   see https://github.com/aol/moloch/issues/1350
#   see https://github.com/aol/moloch/issues/1352

curl -L -o "$MOLOCHDIR"/etc/GeoLite2-Country.mmdb 'https://s3.amazonaws.com/files.molo.ch/testing/GeoLite2-Country.mmdb'
curl -L -o "$MOLOCHDIR"/etc/GeoLite2-ASN.mmdb 'https://s3.amazonaws.com/files.molo.ch/testing/GeoLite2-ASN.mmdb'

# curl -L -o /tmp/GeoLite2-Country.mmdb.gz 'https://s3.amazonaws.com/files.molo.ch/testing/GeoLite2-Country.mmdb'
# curl -L -o /tmp/GeoLite2-ASN.mmdb.gz "https://updates.maxmind.com/app/update_secure?edition_id=GeoLite2-ASN"
# zcat /tmp/GeoLite2-Country.mmdb.gz > "$MOLOCHDIR"/etc/GeoLite2-Country.mmdb
# zcat /tmp/GeoLite2-ASN.mmdb.gz > "$MOLOCHDIR"/etc/GeoLite2-ASN.mmdb

fpm -s dir -t deb -n moloch -x opt/moloch/logs -x opt/moloch/raw -v $MOLOCH_VERSION --iteration 1 --template-scripts --after-install "release/afterinstall.sh" --url "http://molo.ch" --description "Moloch Full Packet System" -d libwww-perl -d libjson-perl -d ethtool -d libyaml-dev "$MOLOCHDIR"

ls -l *.deb && mv -v *.deb "$OUTPUT_DIR"/

cd /tmp
rm -rf /tmp/moloch-$MOLOCH_VER.tar.gz /tmp/moloch-$MOLOCH_VER /tmp/GeoLite2-Country.mmdb.gz /tmp/GeoLite2-ASN.mmdb.gz

if [[ -n $VERBOSE ]]; then
  set +x
fi
set +e
