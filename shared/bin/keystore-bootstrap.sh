#!/usr/bin/env bash

find / -type f -name "*-keystore" -executable | while read KEYSTORE_BIN
do
  TOOL_PATH="$(realpath $(dirname "${KEYSTORE_BIN}")/..)"
  KEYSTORE_NAME="$(basename "${KEYSTORE_BIN}" | sed 's/-\(keystore\)/.\1/')"
  pushd "${TOOL_PATH}" >/dev/null 2>&1
  if ( [[ ! -f ./config/"${KEYSTORE_NAME}" ]] || \
       (( $(stat --format=%s ./config/"${KEYSTORE_NAME}" 2>/dev/null || echo 0) < 200 )) ); then
    if [[ -f ./config/bootstrap/"${KEYSTORE_NAME}" ]]; then
      cp ./config/bootstrap/"${KEYSTORE_NAME}" ./config/"${KEYSTORE_NAME}"
    else
      "${KEYSTORE_BIN}" create
    fi
  fi
  popd >/dev/null 2>&1
done
