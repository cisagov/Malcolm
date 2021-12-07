#!/bin/bash

# Copyright (c) 2021 Battelle Energy Alliance, LLC.  All rights reserved.


echo "Checking OpenSearch..."
/opt/opensearch_status.sh 2>&1 && echo "OpenSearch is running!"

#Wipe is the same initalize except it keeps users intact
echo WIPE | /opt/arkime/db/db.pl http://$OS_HOST:$OS_PORT wipe

#this is a hacky way to get all of the parseable field definitions put into O.S.
touch /tmp/not_a_packet.pcap
$ARKIMEDIR/bin/capture --packetcnt 0 -r /tmp/not_a_packet.pcap >/dev/null 2>&1
rm -f /tmp/not_a_packet.pcap
