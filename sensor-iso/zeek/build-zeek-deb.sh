#!/bin/bash

# Copyright (c) 2023 Battelle Energy Alliance, LLC.  All rights reserved.

export CCACHE_DIR=/var/spool/ccache
export CCACHE_COMPRESS=1
export PYTHONDONTWRITEBYTECODE=1
export PYTHONUNBUFFERED=1

ZEEK_URL=https://github.com/zeek/zeek.git
ZEEK_VERSION=6.0.1
ZEEK_DIR=/opt/zeek
OUTPUT_DIR=/tmp
unset VERBOSE

while getopts b:p:o:v opts; do
   case ${opts} in
      b) ZEEK_VERSION=${OPTARG} ;;
      p) ZEEK_DIR=${OPTARG} ;;
      o) OUTPUT_DIR=${OPTARG} ;;
      v) VERBOSE=1 ;;
   esac
done

set -e
if [[ -n $VERBOSE ]]; then
  set -x
fi

git clone \
    --recurse-submodules \
    --shallow-submodules \
    --depth=1 \
    --single-branch \
    --branch="v${ZEEK_VERSION}" \
    https://github.com/zeek/zeek \
    /tmp/"zeek-v${ZEEK_VERSION}"

mkdir -p "${CCACHE_DIR}"
pushd /tmp/"zeek-v${ZEEK_VERSION}" >/dev/null 2>&1
./configure --prefix="${ZEEK_DIR}" --generator=Ninja --ccache --enable-perftools
ninja -C build
pushd build >/dev/null 2>&1
cpack -G DEB
ls -l *.deb && mv -v *.deb "$OUTPUT_DIR"/
popd >/dev/null 2>&1
popd >/dev/null 2>&1

if [[ -n $VERBOSE ]]; then
  set +x
fi
set +e
