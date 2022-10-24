#!/bin/bash

# Copyright (c) 2022 Battelle Energy Alliance, LLC.  All rights reserved.

ARKIME_URL="https://github.com/arkime/arkime.git"
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

cd /tmp
git clone --recurse-submodules --branch="v$ARKIME_VERSION" "$ARKIME_URL" "./arkime-"$ARKIME_VERSION
cd "./arkime-"$ARKIME_VERSION
for i in /opt/patches/*; do
  patch -p 1 -r - --no-backup-if-mismatch < $i || true
done

export PATH="$ARKIME_DIR/bin:/tmp/arkime-$ARKIME_VERSION/node_modules/.bin:${PATH}"

./easybutton-build.sh --dir "$ARKIME_DIR"

npm -g config set user root

make install

cp -r ./capture/plugins/lua/samples "$ARKIME_DIR"/lua

npm install license-checker
release/notice.txt.pl $ARKIME_DIR NOTICE release/CAPTURENOTICE > $ARKIME_DIR/NOTICE.txt

ETC_FILES=$(shopt -s nullglob dotglob; echo /arkime-etc/*)
if (( ${#ETC_FILES} )) ; then
  mkdir -p $ARKIME_DIR/etc
  cp -r /arkime-etc/* $ARKIME_DIR/etc/
fi

rm -f $ARKIME_DIR/etc/*.systemd.service

fpm -s dir -t deb -n arkime -x opt/arkime/logs -x opt/arkime/raw -v $ARKIME_VERSION --iteration 1 --template-scripts --after-install "release/afterinstall.sh" --url "https://arkime.com" --description "Arkime Full Packet System" -d libwww-perl -d libjson-perl -d ethtool -d libyaml-dev "$ARKIME_DIR"

ls -l *.deb && mv -v *.deb "$OUTPUT_DIR"/

cd /tmp

if [[ -n $VERBOSE ]]; then
  set +x
fi
set +e
