#!/bin/bash

# Copyright (c) 2023 Battelle Energy Alliance, LLC.  All rights reserved.

export CCACHE_DIR=/var/spool/ccache
export CCACHE_COMPRESS=1
export PYTHONDONTWRITEBYTECODE=1
export PYTHONUNBUFFERED=1

ZEEK_URL=https://github.com/zeek/zeek.git
ZEEK_VERSION=6.0.1
ZEEK_DIR=/opt/zeek
BUILD_JOBS=0
OUTPUT_DIR=/tmp
unset VERBOSE

while getopts b:p:o:j:v opts; do
   case ${opts} in
      b) ZEEK_VERSION=${OPTARG} ;;
      p) ZEEK_DIR=${OPTARG} ;;
      o) OUTPUT_DIR=${OPTARG} ;;
      j) BUILD_JOBS=${OPTARG} ;;
      v) VERBOSE=1 ;;
   esac
done

set -e
if [[ -n $VERBOSE ]]; then
  set -x
fi

cd /tmp
mkdir ./"zeek-v${ZEEK_VERSION}"
curl -sSL "https://download.zeek.org/zeek-${ZEEK_VERSION}.tar.gz" | tar xzf - -C ./"zeek-v${ZEEK_VERSION}" --strip-components 1

mkdir -p "${CCACHE_DIR}"
pushd /tmp/"zeek-v${ZEEK_VERSION}" >/dev/null 2>&1
./configure --prefix="${ZEEK_DIR}" --generator=Ninja --ccache --enable-perftools
mkdir -p build
pushd build >/dev/null 2>&1
ninja -j "${BUILD_JOBS}"
checkinstall -y -D --strip=yes --stripso=yes --install=no --fstrans=no --pkgname="zeek" --pkgversion="$ZEEK_VERSION" --pkgarch="amd64" --pkgsource="$ZEEK_URL" ninja install
ls -l *.deb && mv -v *.deb "$OUTPUT_DIR"/
popd >/dev/null 2>&1
popd >/dev/null 2>&1

if [[ -n $VERBOSE ]]; then
  set +x
fi
set +e
