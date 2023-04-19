#!/bin/bash

# Copyright (c) 2023 Battelle Energy Alliance, LLC.  All rights reserved.

OPENSEARCH_URL=${OPENSEARCH_URL:-"http://opensearch:9200"}
OPENSEARCH_LOCAL=${OPENSEARCH_LOCAL:-"true"}
OPENSEARCH_SSL_CERTIFICATE_VERIFICATION=${OPENSEARCH_SSL_CERTIFICATE_VERIFICATION:-"false"}
OPENSEARCH_CREDS_CONFIG_FILE=${OPENSEARCH_CREDS_CONFIG_FILE:-"/var/local/curlrc/.opensearch.primary.curlrc"}
if [[ "$OPENSEARCH_LOCAL" == "false" ]] && [[ -r "$OPENSEARCH_CREDS_CONFIG_FILE" ]]; then
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

echo "Giving OpenSearch time to start..."
/opt/opensearch_status.sh 2>&1 && echo "OpenSearch is running!"

# download and/or update geo updates
$ARKIME_DIR/bin/arkime_update_geo.sh

# start and wait patiently for WISE
if [[ "$WISE" = "on" ]] ; then
  touch /var/run/arkime/runwise
  echo "Giving WISE time to start..."
  sleep 5
  until curl -fsS --output /dev/null "http://127.0.0.1:8081/fields?ver=1"
  do
      echo "Waiting for WISE to start"
      sleep 1
  done
  echo "WISE is running!"
  echo
fi

# initialize the contents of the OpenSearch database if it has never been initialized (ie., the users_v# table hasn't been created)
if [[ $(curl "${CURL_CONFIG_PARAMS[@]}" -fs -XGET -H'Content-Type: application/json' "${OPENSEARCH_URL}/_cat/indices/arkime_users_v*" | wc -l) < 1 ]]; then

  echo "Initializing OpenSearch database..."

	$ARKIME_DIR/db/db.pl $DB_SSL_FLAG "${OPENSEARCH_URL_FULL}" initnoprompt

  echo "Creating default user..."

	# this password isn't going to be used by Arkime, nginx will do the auth instead
	$ARKIME_DIR/bin/arkime_add_user.sh "${MALCOLM_USERNAME}" "${MALCOLM_USERNAME}" "ignored" --admin --webauthonly --webauth $DB_SSL_FLAG

  echo "Initializing fields..."

  # this is a hacky way to get all of the Arkime-parseable field definitions put into E.S.
  touch /tmp/not_a_packet.pcap
  $ARKIME_DIR/bin/capture $DB_SSL_FLAG --packetcnt 0 -r /tmp/not_a_packet.pcap >/dev/null 2>&1
  rm -f /tmp/not_a_packet.pcap

  echo "Initializing views..."

  for VIEW_FILE in "$ARKIME_DIR"/etc/views/*.json; do
    TEMP_JSON=$(mktemp --suffix=.json)
    RANDOM_ID="$(openssl rand -base64 14 | sed -E 's/[^[:alnum:][:space:]]+/_/g')"
    echo "Creating view $(jq '.name' < "${VIEW_FILE}")"
    jq ". += {\"user\": \"${MALCOLM_USERNAME}\"}" < "${VIEW_FILE}" >"${TEMP_JSON}"
    curl "${CURL_CONFIG_PARAMS[@]}" -sS --output /dev/null -H'Content-Type: application/json' -XPOST "${OPENSEARCH_URL}/arkime_views/_doc/${RANDOM_ID}" -d "@${TEMP_JSON}"
    rm -f "${TEMP_JSON}"
  done

  echo "Setting defaults..."

  curl "${CURL_CONFIG_PARAMS[@]}" -sS --output /dev/null -H'Content-Type: application/json' -XPOST "${OPENSEARCH_URL}/arkime_users/_update/$MALCOLM_USERNAME" -d "@$ARKIME_DIR/etc/user_settings.json"

  echo -e "\nOpenSearch database initialized!\n"

else
  echo "OpenSearch database previously initialized!"
  echo

  if /opt/arkime-needs-upgrade.sh 2>&1; then
    echo "OpenSearch database needs to be upgraded for $ARKIME_VERSION!"
    $ARKIME_DIR/db/db.pl $DB_SSL_FLAG "${OPENSEARCH_URL_FULL}" upgradenoprompt
    echo "OpenSearch database upgrade complete!"
    echo

  else
    echo "OpenSearch database is up-to-date for Arkime version $ARKIME_VERSION!"
    echo

  fi # if /opt/moloch-needs-upgrade.sh
fi # if/else OpenSearch database initialized

# increase OpenSearch max shards per node from default if desired
if [[ -n $OPENSEARCH_MAX_SHARDS_PER_NODE ]]; then
  # see https://github.com/elastic/elasticsearch/issues/40803
  curl "${CURL_CONFIG_PARAMS[@]}" -sS --output /dev/null -H'Content-Type: application/json' -XPUT "${OPENSEARCH_URL}/_cluster/settings" -d "{ \"persistent\": { \"cluster.max_shards_per_node\": \"$OPENSEARCH_MAX_SHARDS_PER_NODE\" } }"
fi

# before running viewer, call _refresh to make sure everything is available for search first
curl "${CURL_CONFIG_PARAMS[@]}" -sS -XPOST "${OPENSEARCH_URL}/_refresh"

touch /var/run/arkime/initialized

# the (viewer|wise)_service.sh scripts will start/restart those processes

