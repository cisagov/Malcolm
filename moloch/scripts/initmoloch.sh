#!/bin/bash

# Copyright (c) 2019 Battelle Energy Alliance, LLC.  All rights reserved.

rm -f $MOLOCHDIR/initialized $MOLOCHDIR/runwise

echo "Giving ElasticSearch time to start..."
/data/elastic_search_status.sh 2>&1 && echo "ElasticSearch is running!"

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

#Give option to init ElasticSearch
if [ "$INITIALIZEDB" = "true" ] ; then
	echo INIT | $MOLOCHDIR/db/db.pl http://$ES_HOST:$ES_PORT init

	# this password isn't going to be used by Moloch, nginx will do the auth instead
	$MOLOCHDIR/bin/moloch_add_user.sh "${MALCOLM_USERNAME}" "${MALCOLM_USERNAME}" "ignored" --admin --webauthonly --webauth

  #this is a hacky way to get all of the parseable field definitions put into E.S.
  touch /tmp/not_a_packet.pcap
  $MOLOCHDIR/bin/moloch-capture --packetcnt 0 -r /tmp/not_a_packet.pcap >/dev/null 2>&1
  rm -f /tmp/not_a_packet.pcap

  #set some default settings I want for moloch
  curl -H'Content-Type: application/json' -XPOST http://$ES_HOST:$ES_PORT/users_v7/user/$MALCOLM_USERNAME/_update -d "@$MOLOCHDIR/etc/user_settings.json"
  curl -H'Content-Type: application/json' -XPOST http://$ES_HOST:$ES_PORT/_template/zeek_template -d "@$MOLOCHDIR/etc/zeek_template.json"
fi

#Give option to wipe ElasticSearch
if [ "$WIPEDB" = "true" ]; then
	/data/wipemoloch.sh
fi

touch $MOLOCHDIR/initialized

#the (viewer|capture|wise)_service.sh scripts will start/restart those processes
