#!/bin/bash

# Copyright (c) 2024 Battelle Energy Alliance, LLC.  All rights reserved.

unset VERBOSE
command -v dpkg >/dev/null 2>&1 && ARCH="$(dpkg --print-architecture)" || ARCH=amd64
DISTRO=Debian_12
OUTPUT_DIR=/tmp
ZEEK_VERSION=6.1.1-0

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

DEB_URL="https://download.zeek.org/binary-packages/${DISTRO}"

pushd "$OUTPUT_DIR" >/dev/null 2>&1
curl --fail-early -fsSL --remote-name-all \
  "${DEB_URL}/${ARCH}/libbroker-dev_${ZEEK_VERSION}_${ARCH}.deb" \
  "${DEB_URL}/${ARCH}/zeek-core-dev_${ZEEK_VERSION}_${ARCH}.deb" \
  "${DEB_URL}/${ARCH}/zeek-core_${ZEEK_VERSION}_${ARCH}.deb" \
  "${DEB_URL}/${ARCH}/zeek-spicy-dev_${ZEEK_VERSION}_${ARCH}.deb" \
  "${DEB_URL}/${ARCH}/zeek_${ZEEK_VERSION}_${ARCH}.deb" \
  "${DEB_URL}/${ARCH}/zeekctl_${ZEEK_VERSION}_${ARCH}.deb" \
  "${DEB_URL}/all/zeek-client_${ZEEK_VERSION}_all.deb" \
  "${DEB_URL}/all/zeek-zkg_${ZEEK_VERSION}_all.deb" \
  "${DEB_URL}/all/zeek-btest_${ZEEK_VERSION}_all.deb" \
  "${DEB_URL}/all/zeek-btest-data_${ZEEK_VERSION}_all.deb"
popd >/dev/null 2>&1

if [[ -n $VERBOSE ]]; then
  set +x
fi
set +e
