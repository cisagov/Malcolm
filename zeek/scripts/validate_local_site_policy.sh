#!/usr/bin/env bash

# Runs "zeek -C -r XXXXXX.pcap local" in a temporary directory, and exits with the
#   exit code of Zeek.
#
# -v            turns on verbose execution
# -p            specify a sample PCAP (if unspecified, uses smallest PCAP under the /opt/zeek directory)
# -z            the Zeek policy (defaults to "local")
#
# Any additional arguments besides the above are passed as-is to Zeek.

# Copyright (c) 2025 Battelle Energy Alliance, LLC.  All rights reserved.

set -uo pipefail

ZEEK_DIR=${ZEEK_DIR:-/opt/zeek}
ZEEK_POLICY=local
DUMMY_PCAP=
VERBOSE=0

while getopts p:z:v opts; do
   case ${opts} in
      v) VERBOSE=1 ;;
      p) DUMMY_PCAP=${OPTARG} ;;
      z) ZEEK_POLICY=${OPTARG} ;;
   esac
done
shift "$(($OPTIND -1))"
EXTRA_ARGS=("${@}")

[[ ${VERBOSE} == 1 ]] && set -x

( [[ -z "${DUMMY_PCAP}" ]] || [[ ! -f "${DUMMY_PCAP}" ]] || [[ ! -s "${DUMMY_PCAP}" ]] ) &&
   DUMMY_PCAP="$(find "${ZEEK_DIR}" -type f -iname '*.pcap' -size +128c -print0 | xargs -r -0 ls -la | sort -n -k5 | head -n 1 | awk '{print $9}')"

if [[ -z "${DUMMY_PCAP}" ]] || [[ ! -f "${DUMMY_PCAP}" ]] || [[ ! -s "${DUMMY_PCAP}" ]]; then
   echo "Could not find sample PCAP against which to test" >&2
   exit 1
fi

ZEEK_BIN="${ZEEK_DIR}"/bin/zeek-offline
[[ ! -x "${ZEEK_BIN}" ]] && ZEEK_BIN="${ZEEK_DIR}"/bin/zeek
if [[ ! -x "${ZEEK_BIN}" ]]; then
   echo "Could not determine Zeek executable" >&2
   exit 1
fi

TMP_WORK_DIR="$(mktemp -d)"
pushd "${TMP_WORK_DIR}" >/dev/null 2>&1
"${ZEEK_BIN}" -C -r "${DUMMY_PCAP}" "${ZEEK_POLICY}" "${EXTRA_ARGS[@]}" >&2
ZEEK_RETURN_VAL=$?
[[ -r ./loaded_scripts.log ]] && echo -n "Loaded scripts: " && grep '\.zeek' ./loaded_scripts.log | grep -v '__load__' | wc -l
popd >/dev/null 2>&1
rm -rf "${TMP_WORK_DIR}"

exit ${ZEEK_RETURN_VAL}
