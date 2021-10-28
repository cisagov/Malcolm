#!/bin/bash

# Copyright (c) 2021 Battelle Energy Alliance, LLC.  All rights reserved.

rm -f /var/run/arkime/initialized /var/run/arkime/runwise

echo "Giving OpenSearch time to start..."
/opt/opensearch_status.sh 2>&1 && echo "OpenSearch is running!"

# download and/or update geo updates
$ARKIMEDIR/bin/arkime_update_geo.sh

# start and wait patiently for WISE
if [[ "$WISE" = "on" ]] ; then
  touch /var/run/arkime/runwise
  echo "Giving WISE time to start..."
  sleep 5
  until curl -sSf --output /dev/null "http://127.0.0.1:8081/fields?ver=1"
  do
      echo "Waiting for WISE to start"
      sleep 1
  done
  echo "WISE is running!"
  echo
fi

# initialize the contents of the OpenSearch database if it has never been initialized (ie., the users_v# table hasn't been created)
if [[ $(curl -fs -XGET -H'Content-Type: application/json' "http://$OS_HOST:$OS_PORT/_cat/indices/arkime_users_v*" | wc -l) < 1 ]]; then

  echo "Initializing OpenSearch database..."

	$ARKIMEDIR/db/db.pl http://$OS_HOST:$OS_PORT initnoprompt

  echo "Creating default user..."

	# this password isn't going to be used by Arkime, nginx will do the auth instead
	$ARKIMEDIR/bin/arkime_add_user.sh "${MALCOLM_USERNAME}" "${MALCOLM_USERNAME}" "ignored" --admin --webauthonly --webauth

  echo "Initializing fields..."

  # this is a hacky way to get all of the Arkime-parseable field definitions put into E.S.
  touch /tmp/not_a_packet.pcap
  $ARKIMEDIR/bin/capture --packetcnt 0 -r /tmp/not_a_packet.pcap >/dev/null 2>&1
  rm -f /tmp/not_a_packet.pcap

  echo "Setting defaults..."

  curl -sS -H'Content-Type: application/json' -XPOST http://$OS_HOST:$OS_PORT/arkime_users/_update/$MALCOLM_USERNAME -d "@$ARKIMEDIR/etc/user_settings.json"

  echo -e "\nOpenSearch database initialized!\n"

else
  echo "OpenSearch database previously initialized!"
  echo

  if /opt/arkime-needs-upgrade.sh 2>&1; then
    echo "OpenSearch database needs to be upgraded for $ARKIME_VERSION!"
    $ARKIMEDIR/db/db.pl http://$OS_HOST:$OS_PORT upgradenoprompt
    echo "OpenSearch database upgrade complete!"
    echo

  else
    echo "OpenSearch database is up-to-date for Arkime version $ARKIME_VERSION!"
    echo

  fi # if /opt/moloch-needs-upgrade.sh
fi # if/else OpenSearch database initialized

# increase OpenSearch max shards per node from default if desired
if [[ -n $OS_MAX_SHARDS_PER_NODE ]]; then
  # see https://github.com/elastic/elasticsearch/issues/40803
  curl -sS -H'Content-Type: application/json' -XPUT http://$OS_HOST:$OS_PORT/_cluster/settings -d "{ \"persistent\": { \"cluster.max_shards_per_node\": \"$OS_MAX_SHARDS_PER_NODE\" } }"
fi

# before running viewer, call _refresh to make sure everything is available for search first
curl -sS -XPOST http://$OS_HOST:$OS_PORT/_refresh

touch /var/run/arkime/initialized

# the (viewer|wise)_service.sh scripts will start/restart those processes
