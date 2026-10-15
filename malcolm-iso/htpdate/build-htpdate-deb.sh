#!/bin/bash

# Copyright (c) 2026 Battelle Energy Alliance, LLC.  All rights reserved.

HTPDATE_URL="https://github.com/twekkel/htpdate"
# pinned version and SHA-256, shared with the Hedgehog Raspberry Pi build
. "$( cd -P "$( dirname "${BASH_SOURCE[0]}" )" && pwd )/htpdate.env"
HTPDATE_VER="$HTPDATE_VERSION"
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


cd /tmp
mkdir ./htpdate
curl -fsSL -o ./htpdate.tar.gz "https://codeload.github.com/twekkel/htpdate/tar.gz/refs/tags/v${HTPDATE_VER}"
echo "${HTPDATE_SHA256}  ./htpdate.tar.gz" | sha256sum -c -
tar xzf ./htpdate.tar.gz -C ./htpdate --strip-components 1
cd ./htpdate
sed -i '/.*man8.*/d' Makefile
rm -f scripts/*
make https
checkinstall -y -D --nodoc --strip=yes --stripso=yes --install=no --fstrans=no --pkgname=htpdate --pkgversion="$HTPDATE_VER" --pkgarch="amd64" --pkgsource="$HTPDATE_URL"
ls -l *.deb && mv -v *.deb "$OUTPUT_DIR"/

cd /tmp

if [[ -n $VERBOSE ]]; then
  set +x
fi
set +e
