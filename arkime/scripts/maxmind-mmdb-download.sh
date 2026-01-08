#!/bin/bash

# Download Maxmind Geo IP Lite mmdb files from the official source (using
#   a free API license key) for from an alternative location specified.
#   see https://dev.maxmind.com/geoip/geoipupdate/#Direct_Downloads
#   see https://github.com/arkime/arkime/issues/1350
#   see https://github.com/arkime/arkime/issues/1352

# Copyright (c) 2025 Battelle Energy Alliance, LLC.  All rights reserved.

unset VERBOSE
MAXMIND_GEOIP_DB_LICENSE_KEY=${MAXMIND_GEOIP_DB_LICENSE_KEY:-}
MAXMIND_GEOIP_DB_LICENSE_KEY_FILE=${MAXMIND_GEOIP_DB_LICENSE_KEY_FILE:-}
MAXMIND_GEOIP_DB_ALTERNATE_DOWNLOAD_URL=${MAXMIND_GEOIP_DB_ALTERNATE_DOWNLOAD_URL:-}
MAXMIND_GEOIP_DB_ALTERNATE_DOWNLOAD_URL_FILE=${MAXMIND_GEOIP_DB_ALTERNATE_DOWNLOAD_URL_FILE:-}
OUTPUT_DIR=/tmp

while getopts k:f:u:r:o:v opts; do
   case ${opts} in
      k) MAXMIND_GEOIP_DB_LICENSE_KEY=${OPTARG} ;;
      f) MAXMIND_GEOIP_DB_LICENSE_KEY_FILE=${OPTARG} ;;
      u) MAXMIND_GEOIP_DB_ALTERNATE_DOWNLOAD_URL=${OPTARG} ;;
      r) MAXMIND_GEOIP_DB_ALTERNATE_DOWNLOAD_URL_FILE=${OPTARG} ;;
      o) OUTPUT_DIR=${OPTARG} ;;
      v) VERBOSE=1 ;;
   esac
done

if [[ -n "${VERBOSE}" ]]; then
  set -x
fi

if [[ -z "${MAXMIND_GEOIP_DB_LICENSE_KEY}" ]] && [[ -f "${MAXMIND_GEOIP_DB_LICENSE_KEY_FILE}" ]]; then
  MAXMIND_GEOIP_DB_LICENSE_KEY="$(head -n 1 "${MAXMIND_GEOIP_DB_LICENSE_KEY_FILE}")"
fi

if [[ -z "${MAXMIND_GEOIP_DB_ALTERNATE_DOWNLOAD_URL}" ]] && [[ -f "${MAXMIND_GEOIP_DB_ALTERNATE_DOWNLOAD_URL_FILE}" ]]; then
  MAXMIND_GEOIP_DB_ALTERNATE_DOWNLOAD_URL="$(head -n 1 "${MAXMIND_GEOIP_DB_ALTERNATE_DOWNLOAD_URL_FILE}")"
fi

if [[ -z "${MAXMIND_GEOIP_DB_LICENSE_KEY}" ]] && [[ -z "${MAXMIND_GEOIP_DB_ALTERNATE_DOWNLOAD_URL}" ]]; then
  echo "No GeoIP DB license key or alternate download location specified" >&2
  exit 1
fi

# create a temporary directory to store our results in
WORKDIR="$(mktemp -d -t dlmmdb-XXXXXX)"

# cleanup - on exit ensure the leftover files cleaned up
function cleanup {
  popd >/dev/null 2>&1
  if ! rm -rf "${WORKDIR}"; then
    echo "Failed to remove temporary directory \"${WORKDIR}\"" >&2
    exit 1
  fi
}

if [[ -d "${WORKDIR}" ]]; then
  pushd "${WORKDIR}" >/dev/null 2>&1
  trap "cleanup" EXIT

  if [[ -n "${MAXMIND_GEOIP_DB_LICENSE_KEY}" ]]; then
    for DB in ASN Country City; do
      curl -f -s -S -L -o "GeoLite2-${DB}.mmdb.tar.gz" "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-${DB}&license_key=${MAXMIND_GEOIP_DB_LICENSE_KEY}&suffix=tar.gz" 2>/dev/null && \
        tar xf "GeoLite2-${DB}.mmdb.tar.gz" --wildcards --no-anchored '*.mmdb' --strip=1 2>/dev/null && \
        chmod 644 "GeoLite2-${DB}.mmdb" && \
        rm -f "GeoLite2-${DB}.mmdb.tar.gz"
    done
  fi

  if [[ -n "${MAXMIND_GEOIP_DB_ALTERNATE_DOWNLOAD_URL}" ]]; then
    for DB in ASN Country City; do
      if [[ ! -s "GeoLite2-${DB}.mmdb" ]]; then
        curl -f -s -S -L -o "GeoLite2-$DB.mmdb.tar.gz" "${MAXMIND_GEOIP_DB_ALTERNATE_DOWNLOAD_URL}/GeoLite2-${DB}.mmdb.tar.gz" 2>/dev/null && \
          tar xf "GeoLite2-${DB}.mmdb.tar.gz" --wildcards --no-anchored '*.mmdb' --strip=1 2>/dev/null && \
          chmod 644 "GeoLite2-${DB}.mmdb" && \
          rm -f "GeoLite2-${DB}.mmdb.tar.gz"
      fi
    done
  fi

  if compgen -G "*.mmdb" >/dev/null 2>&1; then
    mkdir -p "${OUTPUT_DIR}"
    mv *.mmdb "${OUTPUT_DIR}"/ && ( find "${OUTPUT_DIR}" -type f -iname "*.mmdb" | sort )
  fi

else
  echo "Unable to create temporary directory \"$WORKDIR\"" 1>&2
  exit 1
fi
