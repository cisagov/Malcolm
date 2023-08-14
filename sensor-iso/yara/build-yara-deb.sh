#!/bin/bash

# Copyright (c) 2023 Battelle Energy Alliance, LLC.  All rights reserved.

YARA_URL="https://github.com/VirusTotal/YARA"
YARA_VER="$(curl -sqI "$YARA_URL/releases/latest" | awk -F '/' '/^location/ {print  substr($NF, 1, length($NF)-1)}' | sed 's/^v//')"
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
mkdir ./yara
curl -sSL "$YARA_URL/tarball/v$YARA_VER" | tar xzf - -C ./yara --strip-components 1
cd ./yara
./bootstrap.sh
./configure --prefix=/usr --with-crypto --enable-magic --enable-cuckoo
make
checkinstall -y -D --strip=yes --stripso=yes --install=no --fstrans=no --pkgname=yara --pkgversion="$YARA_VER" --pkgarch="amd64" --pkgsource="$YARA_URL"
ls -l *.deb && mv -v *.deb "$OUTPUT_DIR"/

cd /tmp

if [[ -n $VERBOSE ]]; then
  set +x
fi
set +e
