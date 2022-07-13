#!/bin/bash

# Copyright (c) 2022 Battelle Energy Alliance, LLC.  All rights reserved.

AIDE_URL="https://github.com/aide/aide.git"
AIDE_BRANCH=master
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
git clone --depth=1 --single-branch --recurse-submodules --shallow-submodules --no-tags --branch="$AIDE_BRANCH" "$AIDE_URL" "./aide-$AIDE_BRANCH"
cd "./aide-$AIDE_BRANCH"
AIDE_COMMIT_DATE="$(git log -1 --format="%at" | xargs -I{} date -d @{} "+%Y%m%d%H%M%S")"

bash ./autogen.sh
./configure --prefix=/usr
make
checkinstall -y -D \
  --strip=yes \
  --stripso=yes \
  --install=no \
  --fstrans=no \
  --pkgname=aide \
  --pkgversion="$AIDE_COMMIT_DATE" \
  --pkgarch="amd64" \
  --pkgsource="$AIDE_URL"

ls -l *.deb && mv -v *.deb "$OUTPUT_DIR"/

cd /tmp

if [[ -n $VERBOSE ]]; then
  set +x
fi
set +e
