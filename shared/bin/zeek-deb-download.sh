#!/bin/bash

# Copyright (c) 2025 Battelle Energy Alliance, LLC.  All rights reserved.

unset VERBOSE
command -v dpkg >/dev/null 2>&1 && ARCH="$(dpkg --print-architecture)" || ARCH=amd64
DISTRO=Debian_13
OUTPUT_DIR=/tmp
ZEEK_VERSION=8.0.4-0
PRESERVE_HIERARCHY=false
ZEEK_DEB_ALTERNATE_DOWNLOAD_URL=${ZEEK_DEB_ALTERNATE_DOWNLOAD_URL:-}
ZEEK_DEB_ALTERNATE_DOWNLOAD_URL_FILE=${ZEEK_DEB_ALTERNATE_DOWNLOAD_URL_FILE:-}

while getopts a:d:f:ho:u:vz: opts; do
   case ${opts} in
      a) ARCH=${OPTARG} ;;
      d) DISTRO=${OPTARG} ;;
      f) ZEEK_DEB_ALTERNATE_DOWNLOAD_URL_FILE=${OPTARG} ;;
      h) PRESERVE_HIERARCHY=true ;;
      o) OUTPUT_DIR=${OPTARG} ;;
      u) ZEEK_DEB_ALTERNATE_DOWNLOAD_URL=${OPTARG} ;;
      v) VERBOSE=1 ;;
      z) ZEEK_VERSION=${OPTARG} ;;
   esac
done

set -e
if [[ -n $VERBOSE ]]; then
  set -x
fi

if [[ -z "${ZEEK_DEB_ALTERNATE_DOWNLOAD_URL}" ]] && [[ -f "${ZEEK_DEB_ALTERNATE_DOWNLOAD_URL_FILE}" ]]; then
  ZEEK_DEB_ALTERNATE_DOWNLOAD_URL="$(head -n 1 "${ZEEK_DEB_ALTERNATE_DOWNLOAD_URL_FILE}")"
fi

URL_PREFIXES=(
  "https://downloadcontentcdn.opensuse.org/repositories/security:/zeek"
)
[[ -n "$ZEEK_DEB_ALTERNATE_DOWNLOAD_URL" ]] && URL_PREFIXES+=( "$ZEEK_DEB_ALTERNATE_DOWNLOAD_URL" )

URL_SUFFIXES=(
  "${DISTRO}/${ARCH}/libbroker-dev_${ZEEK_VERSION}_${ARCH}.deb"
  "${DISTRO}/${ARCH}/zeek-core-dev_${ZEEK_VERSION}_${ARCH}.deb"
  "${DISTRO}/${ARCH}/zeek-core_${ZEEK_VERSION}_${ARCH}.deb"
  "${DISTRO}/${ARCH}/zeek-spicy-dev_${ZEEK_VERSION}_${ARCH}.deb"
  "${DISTRO}/${ARCH}/zeek_${ZEEK_VERSION}_${ARCH}.deb"
  "${DISTRO}/${ARCH}/zeekctl_${ZEEK_VERSION}_${ARCH}.deb"
  "${DISTRO}/all/zeek-client_${ZEEK_VERSION}_all.deb"
  "${DISTRO}/all/zeek-zkg_${ZEEK_VERSION}_all.deb"
  "${DISTRO}/all/zeek-btest_${ZEEK_VERSION}_all.deb"
  "${DISTRO}/all/zeek-btest-data_${ZEEK_VERSION}_all.deb"
)

pushd "$OUTPUT_DIR" >/dev/null 2>&1
for URL_SUFFIX in ${URL_SUFFIXES[@]}; do
  [[ "$PRESERVE_HIERARCHY" == "true" ]] && OUTPUT_DIR_REL="$(dirname "$URL_SUFFIX")" || OUTPUT_DIR_REL=.
  mkdir -p "$OUTPUT_DIR_REL"
  pushd "$OUTPUT_DIR_REL" >/dev/null 2>&1
  for URL_PREFIX in ${URL_PREFIXES[@]}; do
    echo "Downloading \"${URL_PREFIX%/}/${URL_SUFFIX}\"..." >&2
    curl -fsSL -O -J "${URL_PREFIX%/}/${URL_SUFFIX}" && break
  done
  popd >/dev/null 2>&1
done
popd >/dev/null 2>&1

if [[ -n $VERBOSE ]]; then
  set +x
fi
set +e
