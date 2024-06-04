#!/bin/bash

if ! command -v jq >/dev/null 2>&1 || ! command -v evtx >/dev/null 2>&1; then
  echo "$(basename "${BASH_SOURCE[0]}") requires jq and evtx" >&2
  exit 1
fi

VERBOSE=0
DELETE_SRC=0

while getopts vd opts; do
   case ${opts} in
      v) VERBOSE=1 ;;
      d) DELETE_SRC=1 ;;
   esac
done
shift "$(($OPTIND -1))"

if [[ "${VERBOSE}" == "1" ]]; then
  set -x
fi

function processFile() {
   local FNAME="$(realpath "$1")"
   local FNAME_JSON="${FNAME}.json"
   if [[ -f "${FNAME}" ]]; then
      evtx \
         --threads 1 \
         --format jsonl \
         --no-confirm-overwrite \
         --output "${FNAME_JSON}" \
         "${FNAME}" && \
      [[ "${DELETE_SRC}" == "1" ]] && \
      rm -f "${FNAME}"
   fi
}

for INPUT in "$@"; do
   if [[ -d "${INPUT}" ]]; then
      while IFS='' read -r -d '' INPUT_FILE; do
         processFile "${INPUT_FILE}"
      done < <(find "${INPUT}" -xdev -ignore_readdir_race -type f -printf '%p\0' 2>/dev/null | sort -z 2>/dev/null)
   elif [[ -f "${INPUT}" ]]; then
      processFile "${INPUT}"
   fi
done

if [[ "${VERBOSE}" == "1" ]]; then
  set +x
fi