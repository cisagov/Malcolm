#!/bin/bash

###################################################################################################

if ! command -v jq >/dev/null 2>&1 || ! command -v evtx >/dev/null 2>&1; then
  echo "$(basename "${BASH_SOURCE[0]}") requires jq and evtx" >&2
  exit 1
fi

###################################################################################################

# set -x
VERBOSE=0

# delete source evtx file only if conversion worked
DELETE_SRC_ON_SUCCESS=0

# delete source evtx file regardless of conversion success
DELETE_SRC_FORCE=0

while getopts vdf opts; do
   case ${opts} in
      v)
         VERBOSE=1
      ;;
      d)
         DELETE_SRC_ON_SUCCESS=1
      ;;
      f)
         DELETE_SRC_ON_SUCCESS=1
         DELETE_SRC_FORCE=1
      ;;
   esac
done
shift "$(($OPTIND -1))"

if [[ "${VERBOSE}" == "1" ]]; then
  set -x
fi

###################################################################################################
# processFile - convert a single evtx file to JSON

function processFile() {
   local FNAME="$(realpath "$1")"
   if [[ -f "${FNAME}" ]]; then

      # output filespec is input filespec with .evtx.json suffix
      local FNAME_JSON="${FNAME}"
      [[ "${FNAME_JSON}" == *.evtx ]] || FNAME_JSON+=.evtx
      FNAME_JSON+=.json

      evtx \
         --threads 1 \
         --format jsonl \
         --no-confirm-overwrite \
         --output "${FNAME_JSON}" \
         "${FNAME}"
      EVTX_EXIT_CODE=$?

      # delete input file if specified
      ( ( [[ "${EVTX_EXIT_CODE}" == "0" ]] && [[ "${DELETE_SRC_ON_SUCCESS}" == "1" ]] ) || \
        [[ "${DELETE_SRC_FORCE}" == "1" ]] ) && \
         rm -f "${FNAME}"

      # massage output
      if [[ -f "${FNAME_JSON}" ]]; then
         true
      fi

   fi # [[ -f "${FNAME}" ]]
} # processFile

###################################################################################################
# process all input arguments (besides getopts) as evtx file to convert to JSON

for INPUT in "$@"; do
   if [[ -d "${INPUT}" ]]; then
      # argument represents a directory containing evtx files (nested arbitrarily deep), process each
      while IFS='' read -r -d '' INPUT_FILE; do
         processFile "${INPUT_FILE}"
      done < <(find "${INPUT}" -xdev -ignore_readdir_race -type f -printf '%p\0' 2>/dev/null | sort -z 2>/dev/null)
   elif [[ -f "${INPUT}" ]]; then
      # argument represents a single evtx file, process it
      processFile "${INPUT}"
   fi
done # for INPUT in "$@"; do

###################################################################################################

if [[ "${VERBOSE}" == "1" ]]; then
  set +x
fi