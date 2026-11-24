#!/bin/bash

###################################################################################################

# jq implementation to use (e.g., JQ=gojq); defaults to jq
JQ="${JQ:-jq}"

if ! command -v "${JQ}" >/dev/null 2>&1 || ! command -v evtx >/dev/null 2>&1; then
  echo "$(basename "${BASH_SOURCE[0]}") requires ${JQ} and evtx" >&2
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

      # convert the EVTX file to JSON, then pipe it through jq to rename fields with spaces
      #   in the names to have underscores instead, turn integers beyond +/-2^53 into strings
      #   so they keep their exact digits through filebeat, and drop the placeholder that
      #   evtx >= 0.15.0 writes for a FILETIME too large to represent (it isn't a valid date).
      evtx \
         --threads 1 \
         --format jsonl \
         --separate-json-attributes \
         "${FNAME}" 2>/dev/null | "${JQ}" -c 'def walk(f):
                                                . as $in
                                                | if type == "object" then
                                                    reduce keys[] as $key
                                                    ( {}; . + {($key | gsub(" "; "_")): ($in[$key] | walk(f))} )
                                                  elif type == "array" then
                                                    map( walk(f) )
                                                  else
                                                    f
                                                  end;
                                              walk(if type == "number" and (. > 9007199254740991 or . < -9007199254740991) then tostring
                                                   elif . == "0000-00-00T00:00:00.0000000Z" then null
                                                   else . end)' > "${FNAME_JSON}"

      # delete input file if specified
      ( ( [[ -s "${FNAME_JSON}" ]] && [[ "${DELETE_SRC_ON_SUCCESS}" == "1" ]] ) || \
        [[ "${DELETE_SRC_FORCE}" == "1" ]] ) && \
         rm -f "${FNAME}"

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
