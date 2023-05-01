#!/bin/bash

# Copyright (c) 2023 Battelle Energy Alliance, LLC.  All rights reserved.

OPENSEARCH_URL=${OPENSEARCH_URL:-"http://opensearch:9200"}
OPENSEARCH_LOCAL=${OPENSEARCH_LOCAL:-"true"}
OPENSEARCH_CREDS_CONFIG_FILE=${OPENSEARCH_CREDS_CONFIG_FILE:-"/var/local/curlrc/.opensearch.primary.curlrc"}
if [[ "$OPENSEARCH_LOCAL" == "false" ]] && [[ -r "$OPENSEARCH_CREDS_CONFIG_FILE" ]]; then
  CURL_CONFIG_PARAMS=(
    --config
    "$OPENSEARCH_CREDS_CONFIG_FILE"
    )
else
  CURL_CONFIG_PARAMS=()
fi

# this script returns:
#   0 - an UPGRADE IS NEEDED for Arkime indices
#   1 - an UPGRADE IS NOT NEEDED for Arkime indices
RETURN_CODE=1

set -e

# see Arkime's db.pl (https://github.com/arkime/arkime/blob/master/db/db.pl) near the bottom for this list
 declare -A ARKIME_INDEX_CURRENT_VERSIONS=(
  [arkime_dstats_v]=arkime_dstats_v30
  [arkime_fields_v]=arkime_fields_v30
  [arkime_files_v]=arkime_files_v30
  [arkime_hunts_v]=arkime_hunts_v30
  [arkime_lookups_v]=arkime_lookups_v30
  [arkime_notifiers_v]=arkime_notifiers_v40
  [arkime_queries_v]=arkime_queries_v30
  [arkime_sequence_v]=arkime_sequence_v30
  [arkime_stats_v]=arkime_stats_v30
  [arkime_users_v]=arkime_users_v30
  [arkime_views_v]=arkime_views_v40
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

done <<<$(curl "${CURL_CONFIG_PARAMS[@]}" -fsS -H"Content-Type: application/json" -XGET "${OPENSEARCH_URL}/_cat/indices?v" | tail -n +2 | awk '{print $3}')

exit $RETURN_CODE
