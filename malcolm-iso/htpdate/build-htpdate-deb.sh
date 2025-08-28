#!/bin/bash

# Copyright (c) 2025 Battelle Energy Alliance, LLC.  All rights reserved.

HTPDATE_URL="https://github.com/twekkel/htpdate"
HTPDATE_VER="$(curl -sqI "$HTPDATE_URL/releases/latest" | awk -F '/' '/^location/ {print  substr($NF, 1, length($NF)-1)}' | sed 's/^v//')"
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
curl -sSL "$HTPDATE_URL/tarball/v$HTPDATE_VER" | tar xzf - -C ./htpdate --strip-components 1
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
