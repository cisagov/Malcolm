#!/bin/bash

# Copyright (c) 2021 Battelle Energy Alliance, LLC.  All rights reserved.


echo "Checking Elasticsearch..."
/data/elastic_search_status.sh 2>&1 && echo "Elasticsearch is running!"

#Wipe is the same initalize except it keeps users intact
echo WIPE | /opt/arkime/db/db.pl http://$ES_HOST:$ES_PORT wipe

#this is a hacky way to get all of the parseable field definitions put into E.S.
touch /tmp/not_a_packet.pcap
$ARKIMEDIR/bin/moloch-capture --packetcnt 0 -r /tmp/not_a_packet.pcap >/dev/null 2>&1
rm -f /tmp/not_a_packet.pcap
