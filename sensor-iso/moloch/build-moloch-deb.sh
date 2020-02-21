#!/bin/bash

# Copyright (c) 2020 Battelle Energy Alliance, LLC.  All rights reserved.

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

ETC_FILES=$(shopt -s nullglob dotglob; echo /moloch-etc/*)
if (( ${#ETC_FILES} )) ; then
  mkdir -p $MOLOCHDIR/etc
  cp -r /moloch-etc/* $MOLOCHDIR/etc/
fi

fpm -s dir -t deb -n moloch -x opt/moloch/logs -x opt/moloch/raw -v $MOLOCH_VERSION --iteration 1 --template-scripts --after-install "release/afterinstall.sh" --url "http://molo.ch" --description "Moloch Full Packet System" -d libwww-perl -d libjson-perl -d ethtool -d libyaml-dev "$MOLOCHDIR"

ls -l *.deb && mv -v *.deb "$OUTPUT_DIR"/

cd /tmp

if [[ -n $VERBOSE ]]; then
  set +x
fi
set +e
