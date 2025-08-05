#!/bin/bash

# Copyright (c) 2025 Battelle Energy Alliance, LLC.  All rights reserved.

MALCOLM_PROFILE=${MALCOLM_PROFILE:-"malcolm"}
OPENSEARCH_URL=${OPENSEARCH_URL:-"https://opensearch:9200"}
OPENSEARCH_PRIMARY=${OPENSEARCH_PRIMARY:-"opensearch-local"}
OPENSEARCH_SSL_CERTIFICATE_VERIFICATION=${OPENSEARCH_SSL_CERTIFICATE_VERIFICATION:-"false"}
OPENSEARCH_CREDS_CONFIG_FILE=${OPENSEARCH_CREDS_CONFIG_FILE:-"/var/local/curlrc/.opensearch.primary.curlrc"}
if [[ -r "$OPENSEARCH_CREDS_CONFIG_FILE" ]]; then
  CURL_CONFIG_PARAMS=(
    --config
    "$OPENSEARCH_CREDS_CONFIG_FILE"
    )
else
  CURL_CONFIG_PARAMS=()
fi
[[ "$OPENSEARCH_SSL_CERTIFICATE_VERIFICATION" != "true" ]] && DB_SSL_FLAG="--insecure" || DB_SSL_FLAG=""
OPENSEARCH_URL_FULL="$(grep -Pi '^elasticsearch\s*=' $ARKIME_DIR/etc/config.ini | cut -d'=' -f2-)"

rm -f /var/run/arkime/initialized /var/run/arkime/runwise

if [[ "${ARKIME_SSL:-true}" != "false" ]]; then
  # make sure TLS certificates exist prior to starting up
  CERT_FILE=$ARKIME_DIR/etc/viewer.crt
  KEY_FILE=$ARKIME_DIR/etc/viewer.key
  if ( [[ ! -f "$CERT_FILE" ]] || [[ ! -f "$KEY_FILE" ]] ) && [[ -x /usr/local/bin/self_signed_key_gen.sh ]]; then
    rm -f "$CERT_FILE" "$KEY_FILE" ./newcerts
    pushd $ARKIME_DIR/etc/ >/dev/null 2>&1
    /usr/local/bin/self_signed_key_gen.sh -n -o ./newcerts >/dev/null 2>&1
    mv ./newcerts/server.crt "$CERT_FILE"
    mv ./newcerts/server.key "$KEY_FILE"
    rm -rf ./newcerts
    popd >/dev/null 2>&1
  fi
fi

if [[ "$MALCOLM_PROFILE" == "malcolm" ]]; then

  # download and/or update geo updates
  $ARKIME_DIR/bin/arkime_update_geo.sh

  echo "Giving ${OPENSEARCH_PRIMARY} time to start..."
  if /usr/local/bin/opensearch_status.sh 2>&1; then
    NODE_COUNT="$(curl "${CURL_CONFIG_PARAMS[@]}" -fs -XGET -H'Content-Type: application/json' "${OPENSEARCH_URL}/_nodes" 2>/dev/null | jq --raw-output '.nodes | length' 2>/dev/null | head -n 1)"
    echo "${OPENSEARCH_PRIMARY} is running! (nodes: ${NODE_COUNT})"
  fi
  [[ -z "${NODE_COUNT}" ]] && NODE_COUNT=1


  DB_INIT_ARGS=()
  if [[ -n "${ARKIME_INIT_SHARDS}" ]]; then
    # cannot set "shards" greater than the number of nodes
    (( ARKIME_INIT_SHARDS > NODE_COUNT )) && ARKIME_INIT_SHARDS=$NODE_COUNT
    DB_INIT_ARGS+=( --shards ) && DB_INIT_ARGS+=( "${ARKIME_INIT_SHARDS}" )
  fi
  [[ -n "${ARKIME_INIT_REPLICAS}" ]] && DB_INIT_ARGS+=( --replicas ) && DB_INIT_ARGS+=( "${ARKIME_INIT_REPLICAS}" )
  [[ -n "${ARKIME_INIT_REFRESH_SEC}" ]] && DB_INIT_ARGS+=( --refresh ) && DB_INIT_ARGS+=( "${ARKIME_INIT_REFRESH_SEC}" )
  [[ -n "${ARKIME_INIT_SHARDS_PER_NODE}" ]] && DB_INIT_ARGS+=( --shardsPerNode ) && DB_INIT_ARGS+=( "${ARKIME_INIT_SHARDS_PER_NODE}" )

  # initialize the contents of the OpenSearch database if it has never been initialized (ie., the users_v# table hasn't been created)
  if (( $(curl "${CURL_CONFIG_PARAMS[@]}" -fs -XGET -H'Content-Type: application/json' "${OPENSEARCH_URL}/_cat/indices/arkime_users_v*" | wc -l) < 1 )); then
    echo "Initializing $OPENSEARCH_PRIMARY database (${DB_INIT_ARGS[*]})"

    $ARKIME_DIR/db/db.pl $DB_SSL_FLAG "${OPENSEARCH_URL_FULL}" initnoprompt "${DB_INIT_ARGS[@]}"
    ARKIME_DID_INIT=1

    if [[ "${INDEX_MANAGEMENT_ENABLED:-false}" == "true" ]]; then
      [[ "${INDEX_MANAGEMENT_HOT_WARM_ENABLED:-false}" == "true" ]] && HOT_WARM_FLAG=--hotwarm || HOT_WARM_FLAG=
      [[ "${OPENSEARCH_PRIMARY}" == "elasticsearch-remote" ]] && LIFECYCLE_POLCY=ilm || LIFECYCLE_POLCY=ism
      $ARKIME_DIR/db/db.pl $DB_SSL_FLAG "${OPENSEARCH_URL_FULL}" ${LIFECYCLE_POLCY} "${INDEX_MANAGEMENT_OPTIMIZATION_PERIOD}" "${INDEX_MANAGEMENT_RETENTION_TIME}" ${HOT_WARM_FLAG} --segments "${INDEX_MANAGEMENT_SEGMENTS}" --replicas "${INDEX_MANAGEMENT_OLDER_SESSION_REPLICAS}" --history "${INDEX_MANAGEMENT_HISTORY_RETENTION_WEEKS}"
      $ARKIME_DIR/db/db.pl $DB_SSL_FLAG "${OPENSEARCH_URL_FULL}" upgradenoprompt --${LIFECYCLE_POLCY} "${DB_INIT_ARGS[@]}"
      echo "${LIFECYCLE_POLCY} created"
    fi

    echo "Creating default user..."

  	# this username/password isn't going to be used by Arkime, nginx will do the auth instead
  	$ARKIME_DIR/bin/arkime_add_user.sh "${MALCOLM_USERNAME}" "${MALCOLM_USERNAME}" "ignored" --admin --webauthonly --webauth $DB_SSL_FLAG >/dev/null 2>&1

    echo "Initializing views..."

    for VIEW_FILE in "$ARKIME_DIR"/etc/views/*.json; do
      TEMP_JSON=$(mktemp --suffix=.json)
      RANDOM_ID="$(openssl rand -base64 14 | sed -E 's/[^[:alnum:][:space:]]+/_/g')"
      echo "Creating view $(jq '.name' < "${VIEW_FILE}")"
      jq ". += {\"user\": \"${MALCOLM_USERNAME}\"}" < "${VIEW_FILE}" >"${TEMP_JSON}"
      curl "${CURL_CONFIG_PARAMS[@]}" -sS --output /dev/null -H'Content-Type: application/json' -XPOST "${OPENSEARCH_URL}/arkime_views/_doc/${RANDOM_ID}" -d "@${TEMP_JSON}"
      rm -f "${TEMP_JSON}"
    done

    # TODO: until Arkime v6.0.0 is out, as per Andy Wick and I's discussion in slack, at the moment not all of the Arkime permissions can be set on roles,
    #   so creating these doesn't really do us any good. For now, then, Arkime roles (the user-defined ones, at least, the ones that start with role: below)
    #   are going to be handled purely based on URI path in the NGINX stuff (nginx/lua/nginx_auth_helpers.lua).
    #   Once all of these permissions are settable at the role level in Arkime, we can uncomment those and revisit it.
    # -SG 2025.06.17
    # echo "Creating user-defined roles..."
    # for ROLE_FILE in "$ARKIME_DIR"/etc/roles/*.json; do
    #   ROLE_NAME=${ROLE_FILE##*/}
    #   ROLE_NAME=${ROLE_NAME#arkime_}
    #   ROLE_NAME=${ROLE_NAME%.json}
    #   PERM_ARGS=()
    #   [[ "$(jq -r '(.doc?.disablePcapDownload) // true' < "${ROLE_FILE}")" == "true" ]] && PERM_ARGS+=( --disablePcapDownload )
    #   [[ "$(jq -r '(.doc?.hideFiles) // true' < "${ROLE_FILE}")" == "true" ]] && PERM_ARGS+=( --hideFiles )
    #   [[ "$(jq -r '(.doc?.hidePcap) // true' < "${ROLE_FILE}")" == "true" ]] && PERM_ARGS+=( --hidePcap )
    #   [[ "$(jq -r '(.doc?.hideStats) // true' < "${ROLE_FILE}")" == "true" ]] && PERM_ARGS+=( --hideStats )
    #   [[ "$(jq -r '(.doc?.packetSearch) // false' < "${ROLE_FILE}")" == "true" ]] && PERM_ARGS+=( --packetSearch )
    #   [[ "$(jq -r '(.doc?.removeEnabled) // false' < "${ROLE_FILE}")" == "true" ]] && PERM_ARGS+=( --removeEnabled )
    #   $ARKIME_DIR/bin/arkime_add_user.sh "role:${ROLE_NAME}" "${ROLE_NAME}" "ignored" --createOnly --roles "" "${PERM_ARGS[@]}" $DB_SSL_FLAG >/dev/null 2>&1
    # done

    echo "Setting defaults..."

    curl "${CURL_CONFIG_PARAMS[@]}" -sS --output /dev/null -H'Content-Type: application/json' -XPOST "${OPENSEARCH_URL}/arkime_users/_update/$MALCOLM_USERNAME" -d "@$ARKIME_DIR/etc/user_settings.json"

    echo -e "\n$OPENSEARCH_PRIMARY database initialized!\n"
  else
    ARKIME_DID_INIT=0
    echo "$OPENSEARCH_PRIMARY database previously initialized! (${DB_INIT_ARGS[*]})"
    echo

    $ARKIME_DIR/db/db.pl $DB_SSL_FLAG "${OPENSEARCH_URL_FULL}" upgradenoprompt --ifneeded "${DB_INIT_ARGS[@]}"
    echo "$OPENSEARCH_PRIMARY database is up-to-date for Arkime version $ARKIME_VERSION!"
  fi # if/else OpenSearch database initialized

  # start and wait patiently for WISE
  if [[ "$WISE" = "on" ]] ; then
    touch /var/run/arkime/runwise
    echo "Giving WISE time to start..."
    sleep 5
    until curl -fsS --output /dev/null "http://localhost:8081/fields?ver=1" 2>/dev/null; do sleep 1; done
    echo "WISE is running!"
    echo
  fi

  if [[ "$ARKIME_DID_INIT" == "1" ]]; then
    echo "Initializing fields..."
    # this is a hacky way to get all of the Arkime-parseable field definitions put into E.S.
    touch /tmp/not_a_packet.pcap
    $ARKIME_DIR/bin/capture-offline $DB_SSL_FLAG --packetcnt 0 -r /tmp/not_a_packet.pcap >/dev/null 2>&1
    rm -f /tmp/not_a_packet.pcap
  fi

  # before running viewer, call _refresh to make sure everything is available for search first
  curl "${CURL_CONFIG_PARAMS[@]}" -sS -XPOST "${OPENSEARCH_URL}/_refresh"

  # the (viewer|wise)_service.sh scripts will start/restart those processes
fi

touch /var/run/arkime/initialized
