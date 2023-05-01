#!/usr/bin/env bash

# Copyright (c) 2023 Battelle Energy Alliance, LLC.  All rights reserved.

# make sure the keystore file used by the tool (e.g., foobar) is copied or created
# into the correct location before the tool. starts up.
#
# example:
#   - /usr/share/foobar/config/persist/foobar.keystore
#       - "real" location of keystore file used by foobar
#   - /usr/share/foobar/config/bootstrap/foobar.keystore
#       - if "persist" keystore does't exist, but "bootstrap" keystore
#         does, then copy "bootstrap" keystore to "persist" keystore
#   - /usr/share/foobar/config/foobar.keystore
#       - symlinks to "persist" keystore (foobar requires this
#         to be the file it actually looks at)
#
declare -A KEYSTORE_FILE_MIN_BYTES
KEYSTORE_FILE_MIN_BYTES[opensearch]=196
KEYSTORE_FILE_MIN_BYTES[logstash]=465
KEYSTORE_FILE_MIN_BYTES[none]=128

# for each "*-keystore" executable in the filesystem...
find / -type f -name "*-keystore" -executable 2>/dev/null | while read KEYSTORE_BIN; do

  # TOOL_PATH is parent of keystore bin, e.g., /usr/share/foobar
  TOOL_PATH="$(realpath $(dirname "${KEYSTORE_BIN}")/..)"

  # tool name is just the part before -keystore
  TOOL_NAME="$(basename "${KEYSTORE_BIN}" | sed 's/-keystore$//')"

  # keystore bin is like foobar-keystore, keystore file is foobar.keystore
  KEYSTORE_NAME="${TOOL_NAME}.keystore"

  [[ -z "${KEYSTORE_FILE_MIN_BYTES["${TOOL_NAME}"]+unset}" ]] && MIN_BYTES=${KEYSTORE_FILE_MIN_BYTES[none]} || MIN_BYTES=${KEYSTORE_FILE_MIN_BYTES["${TOOL_NAME}"]}

  # chdir to tool directory
  pushd "${TOOL_PATH}" >/dev/null 2>&1

  # since ./config/foobar.keystore is going to just be a symlink to ./config/persist/foobar.keystore,
  #   get it out of the way now if for some reason it already exists
  rm -f ./config/"${KEYSTORE_NAME}"

  # does ./config/persist/foobar.keystore exist, and is it big enough to be a real keystore file? ...
  if [[ ! -f ./config/persist/"${KEYSTORE_NAME}" ]] || \
     (( $(stat --format=%s ./config/persist/"${KEYSTORE_NAME}" 2>/dev/null || echo 0) < ${MIN_BYTES} )); then

    # ... no, it does not! if there was something there (too small/empty file) remove it
    rm -f ./config/persist/"${KEYSTORE_NAME}"

    # does ./config/bootstrap/foobar.keystore exist, and is it big enough to be copied into ./config/persist? ...
    if [[ -f ./config/bootstrap/"${KEYSTORE_NAME}" ]] && \
       (( $(stat --format=%s ./config/bootstrap/"${KEYSTORE_NAME}" 2>/dev/null || echo 0) >= ${MIN_BYTES} )); then

      # ... yes, it does! bootstrap becomes the new persist keystore
      cp ./config/bootstrap/"${KEYSTORE_NAME}" ./config/persist/"${KEYSTORE_NAME}"

    else
      # ... no, it doe not! create a fresh/empty .keystore file at ./config/foobar.keystore and move it to ./config/persist/
      "${KEYSTORE_BIN}" create
      mv ./config/"${KEYSTORE_NAME}" ./config/persist/"${KEYSTORE_NAME}"
    fi

  fi # check for ./config/persist/foobar.keystore

  # symlink ./config/foobar.keystore to ./config/persist/foobar.keystore
  ln -s -r ./config/persist/"${KEYSTORE_NAME}" ./config/"${KEYSTORE_NAME}"

  popd >/dev/null 2>&1
done # loop over keystore executables (probably just one)

