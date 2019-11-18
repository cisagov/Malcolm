#!/bin/bash

# Copyright (c) 2019 Battelle Energy Alliance, LLC.  All rights reserved.

rm -f $MOLOCHDIR/initialized $MOLOCHDIR/runwise

echo "Giving Elasticsearch time to start..."
/data/elastic_search_status.sh 2>&1 && echo "Elasticsearch is running!"

#Configure Moloch to Run
if [ ! -f $MOLOCHDIR/configured ]; then
	touch $MOLOCHDIR/configured
  if [[ "$WISE" = "on" ]] ; then
    $MOLOCHDIR/bin/Configure --wise
  fi
  $MOLOCHDIR/bin/Configure
fi

if [[ "$WISE" = "on" ]] ; then
  touch $MOLOCHDIR/runwise
  echo "Giving WISE time to start..."
  sleep 5
  until curl -sS --output /dev/null "http://127.0.0.1:8081/fields?ver=1"
  do
      echo "Waiting for WISE to start"
      sleep 1
  done
  echo "WISE is running!"
  echo
fi

# initialize the contents of the Elasticearch database if it has never been initialized (ie., if zeek_template has not been loaded)
if ! curl -fs --output /dev/null -H'Content-Type: application/json' -XGET http://$ES_HOST:$ES_PORT/_template/zeek_template ; then
  echo "Initializing Elasticsearch database..."

	$MOLOCHDIR/db/db.pl http://$ES_HOST:$ES_PORT initnoprompt

	# this password isn't going to be used by Moloch, nginx will do the auth instead
	$MOLOCHDIR/bin/moloch_add_user.sh "${MALCOLM_USERNAME}" "${MALCOLM_USERNAME}" "ignored" --admin --webauthonly --webauth

  # this is a hacky way to get all of the Moloch-parseable field definitions put into E.S.
  touch /tmp/not_a_packet.pcap
  $MOLOCHDIR/bin/moloch-capture --packetcnt 0 -r /tmp/not_a_packet.pcap >/dev/null 2>&1
  rm -f /tmp/not_a_packet.pcap

  #set some default settings I want for moloch
  curl -sS -H'Content-Type: application/json' -XPOST http://$ES_HOST:$ES_PORT/users_v7/user/$MALCOLM_USERNAME/_update -d "@$MOLOCHDIR/etc/user_settings.json"

  # load zeek_template containing a few special-typed fields (the rest are done by Moloch WISE for now)
  curl -sS -H'Content-Type: application/json' -XPOST http://$ES_HOST:$ES_PORT/_template/zeek_template -d "@$MOLOCHDIR/etc/zeek_template.json"

  echo -e "\nElasticsearch database initialized!\n"

else
  echo "Elasticsearch database previously initialized!"
  echo

  if /data/moloch-needs-upgrade.sh 2>&1; then
    echo "Elasticsearch database needs to be upgraded for $MOLOCH_VERSION!"
    $MOLOCHDIR/db/db.pl http://$ES_HOST:$ES_PORT upgradenoprompt
    echo "Elasticsearch database upgrade complete!"
    echo

  else
    echo "Elasticsearch database is up-to-date for Moloch version $MOLOCH_VERSION!"
    echo

  fi # if /data/moloch-needs-upgrade.sh
fi # if/else Elasticsearch database initialized

touch $MOLOCHDIR/initialized

# the (viewer|wise)_service.sh scripts will start/restart those processes
