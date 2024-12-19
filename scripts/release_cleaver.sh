#!/usr/bin/env bash

# Copyright (c) 2025 Battelle Energy Alliance, LLC.  All rights reserved.

# release_cleaver.sh
# Split and join large files into 2 gigabyte chunks. sha256 sum is
#   also calculated and saved on split and checked on join.

if [ -z "$BASH_VERSION" ]; then
  echo "Wrong interpreter, please run \"$0\" with bash"
  exit 1
fi

if ! (command -v basename && command -v sha256sum && command -v split && command -v cat) >/dev/null 2>&1; then
  echo "${BASH_SOURCE[0]} requires split, cat, and sha256sum" >&2
  exit 1
fi

set -euo pipefail
ENCODING="utf-8"

function base () { echo "${1%.*}" ; }
function ext () { echo "${1##*.}" ; }

if (( "$#" <= 0 )); then
  echo "Usage:" >&2
  echo "  $(basename "${BASH_SOURCE[0]}") <file_to_split>" >&2
  echo "OR" >&2
  echo "  $(basename "${BASH_SOURCE[0]}") <file_to_join.00> <file_to_join.01> ... <file_to_join.sha>" >&2
  exit 1

elif (( "$#" > 1 )); then
  # more than one file specified to join (should be .00, .01, .02, etc., and .sha)
  echo "Joining..." >&2

  # the part before the file extension needs to match for all files provided, otherwise bail
  PREV_BASE=
  for FILE in "$@"; do
    CURR_BASE="$(base "$(basename "${FILE}")")"
    if [[ ! -f "${FILE}" ]]; then
      echo "\"${FILE}\" does not exist" >&2
      exit 1
    elif [[ -n "${PREV_BASE}" ]] && [[ "${PREV_BASE}" != "${CURR_BASE}" ]]; then
      echo "File basenames (\"${PREV_BASE}\" and \"${CURR_BASE}\") do not match, giving up" >&2
      exit 1
    else
      PREV_BASE="${CURR_BASE}"
    fi
  done

  # only proceed if we know what we're going to join to and that target doesn't already exist
  OUT_FILE="${PREV_BASE}"
  if [[ -n "${OUT_FILE}" ]] && [[ ! -f "${OUT_FILE}" ]]; then

    # loop over the input files, make note of the .sha file and cat the rest
    > "${OUT_FILE}"
    SHA_FILE=
    for FILE in "$@"; do
      EXT="$(ext "${FILE}")"
      if [[ "${EXT}" == "sha" ]]; then
        SHA_FILE="$FILE"
      else
        cat "${FILE}" >> "${OUT_FILE}"
      fi
    done

    if [[ ! -f "${OUT_FILE}" ]]; then
      # file was not created
      echo "Attempted to join files to ${OUT_FILE}, but could not create the file" >&2
      exit 1

    elif [[ ! -s "${OUT_FILE}" ]]; then
      # file was created but it's empty
      echo "Attempted to join files to ${OUT_FILE}, but an empty file resulted" >&2
      exit 1

    elif [[ -z "${SHA_FILE}" ]] || [[ ! -f "${SHA_FILE}" ]]; then
      echo "Files joined to ${OUT_FILE}, but could not verify file integrity" >&2
      exit 1

    else
      # file was created, is non empty, and sha file exists, verify its integrity
      sha256sum --check "${SHA_FILE}"
    fi

  elif [[ -n "${OUT_FILE}" ]]; then
    echo "Output file \"${OUT_FILE}\" already exists" >&2
    exit 1

  else
    echo "Could not determine output filename" >&2
    exit 1
  fi

else
  echo "Splitting..." >&2
  SHA_FILE="$(basename "${1}").sha"
  sha256sum --binary "${1}" | head --bytes=64 | tee "${SHA_FILE}"
  echo "  $(basename "${1}")" | tee --append "${SHA_FILE}"
  split --bytes=2000000000 --numeric-suffixes=1 --suffix-length=2 "${1}" "$(basename "${1}")."
fi
