#!/bin/bash

# Copyright (c) 2024 Battelle Energy Alliance, LLC.  All rights reserved.

unset VERBOSE
command -v dpkg >/dev/null 2>&1 && ARCH="$(dpkg --print-architecture)" || ARCH=amd64
DISTRO=Debian_12
OUTPUT_DIR=/tmp
ZEEK_VERSION=7.0.0-0

while getopts a:d:o:vz: opts; do
   case ${opts} in
      a) ARCH=${OPTARG} ;;
      d) DISTRO=${OPTARG} ;;
      o) OUTPUT_DIR=${OPTARG} ;;
      v) VERBOSE=1 ;;
      z) ZEEK_VERSION=${OPTARG} ;;
   esac
done

set -e
if [[ -n $VERBOSE ]]; then
  set -x
fi

URL_PREFIX="https://downloadcontentcdn.opensuse.org/repositories/security:/zeek/${DISTRO}"
URLS=(
  "${URL_PREFIX}/${ARCH}/libbroker-dev_${ZEEK_VERSION}_${ARCH}.deb"
  "${URL_PREFIX}/${ARCH}/zeek-core-dev_${ZEEK_VERSION}_${ARCH}.deb"
  "${URL_PREFIX}/${ARCH}/zeek-core_${ZEEK_VERSION}_${ARCH}.deb"
  "${URL_PREFIX}/${ARCH}/zeek-spicy-dev_${ZEEK_VERSION}_${ARCH}.deb"
  "${URL_PREFIX}/${ARCH}/zeek_${ZEEK_VERSION}_${ARCH}.deb"
  "${URL_PREFIX}/${ARCH}/zeekctl_${ZEEK_VERSION}_${ARCH}.deb"
  "${URL_PREFIX}/all/zeek-client_${ZEEK_VERSION}_all.deb"
  "${URL_PREFIX}/all/zeek-zkg_${ZEEK_VERSION}_all.deb"
  "${URL_PREFIX}/all/zeek-btest_${ZEEK_VERSION}_all.deb"
  "${URL_PREFIX}/all/zeek-btest-data_${ZEEK_VERSION}_all.deb"
)

pushd "$OUTPUT_DIR" >/dev/null 2>&1
for URL in ${URLS[@]}; do
  curl -fsSL -O -J "${URL}"
done
popd >/dev/null 2>&1

if [[ -n $VERBOSE ]]; then
  set +x
fi
set +e
