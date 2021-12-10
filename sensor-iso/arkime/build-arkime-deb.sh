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
git clone --depth=1 --single-branch --recurse-submodules --shallow-submodules --no-tags --branch="v$ARKIME_VERSION" "$ARKIME_URL" "./arkime-"$ARKIME_VERSION
cd "./arkime-"$ARKIME_VERSION
find . -name "*.js" -exec sed -i "s/\(rejectUnauthorized[[:space:]]*:[[:space:]]*\)[^,]*/\1false/" "{}" \;

export PATH="$ARKIMEDIR/bin:/tmp/arkime-$ARKIME_VERSION/node_modules/.bin:${PATH}"

./easybutton-build.sh --dir "$ARKIMEDIR"

npm -g config set user root

make install

cp -r ./capture/plugins/lua/samples "$ARKIMEDIR"/lua

npm install license-checker
release/notice.txt.pl $ARKIMEDIR NOTICE release/CAPTURENOTICE > $ARKIMEDIR/NOTICE.txt

ETC_FILES=$(shopt -s nullglob dotglob; echo /arkime-etc/*)
if (( ${#ETC_FILES} )) ; then
  mkdir -p $ARKIMEDIR/etc
  cp -r /arkime-etc/* $ARKIMEDIR/etc/
fi

fpm -s dir -t deb -n arkime -x opt/arkime/logs -x opt/arkime/raw -v $ARKIME_VERSION --iteration 1 --template-scripts --after-install "release/afterinstall.sh" --url "http://molo.ch" --description "Arkime Full Packet System" -d libwww-perl -d libjson-perl -d ethtool -d libyaml-dev "$ARKIMEDIR"

ls -l *.deb && mv -v *.deb "$OUTPUT_DIR"/

cd /tmp

if [[ -n $VERBOSE ]]; then
  set +x
fi
set +e
