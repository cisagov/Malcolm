#!/bin/bash

# Copyright (c) 2021 Battelle Energy Alliance, LLC.  All rights reserved.

# this script returns:
#   0 - an UPGRADE IS NEEDED for Arkime indices
#   1 - an UPGRADE IS NOT NEEDED for Arkime indices
RETURN_CODE=1

set -e

# see Arkime's db.pl (https://github.com/arkime/arkime/blob/master/db/db.pl) near the bottom for this list
 declare -A ARKIME_INDEX_CURRENT_VERSIONS=(
  [dstats_v]=dstats_v4
  [fields_v]=fields_v3
  [files_v]=files_v6
  [hunts_v]=hunts_v2
  [lookups_v]=lookups_v1
  [queries_v]=queries_v3
  [sequence_v]=sequence_v3
  [stats_v]=stats_v4
  [users_v]=users_v7
)

# get a list of all current indices and loop over them
while read INDEX_NAME; do

  # for each current index, check to see if it's one of the Arkime indices (prefixed by
  # the key of ARKIME_INDEX_CURRENT_VERSIONS)
  for INDEX_PREFIX in "${!ARKIME_INDEX_CURRENT_VERSIONS[@]}"; do
    if [[ ${INDEX_NAME} = ${INDEX_PREFIX}* ]]; then

      # if this is a Arkime index, make sure the version matches what we think it should
      if [[ ${INDEX_NAME} != ${ARKIME_INDEX_CURRENT_VERSIONS[$INDEX_PREFIX]} ]]; then
        RETURN_CODE=0
        echo "${INDEX_NAME}:${ARKIME_INDEX_CURRENT_VERSIONS[$INDEX_PREFIX]}" 1>&2
        break
      fi # compare INDEX_NAME vs. full Arkime index name with version

    fi # compare INDEX_NAME vs. INDEX_PREFIX
  done # loop over ARKIME_INDEX_CURRENT_VERSIONS

done <<<$(curl -fsS -H"Content-Type: application/json" -XGET "http://$ES_HOST:$OS_PORT/_cat/indices?v" | tail -n +2 | awk '{print $3}')

exit $RETURN_CODE
