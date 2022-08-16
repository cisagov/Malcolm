#!/bin/bash

# Copyright (c) 2022 Battelle Energy Alliance, LLC.  All rights reserved.

OPENSEARCH_HOST=${OPENSEARCH_HOST:-"opensearch"}
OPENSEARCH_PORT=${OPENSEARCH_PORT:-"9200"}
OPENSEARCH_PROTOCOL=${OPENSEARCH_PROTOCOL:-"http"}
OPENSEARCH_URL=${OPENSEARCH_URL:-"${OPENSEARCH_PROTOCOL}://${OPENSEARCH_HOST}:${OPENSEARCH_PORT}"}

echo "Checking OpenSearch..."
/opt/opensearch_status.sh 2>&1 && echo "OpenSearch is running!"

#Wipe is the same initalize except it keeps users intact
echo WIPE | /opt/arkime/db/db.pl "${OPENSEARCH_URL}" wipe

#this is a hacky way to get all of the parseable field definitions put into O.S.
touch /tmp/not_a_packet.pcap
$ARKIME_DIR/bin/capture --packetcnt 0 -r /tmp/not_a_packet.pcap >/dev/null 2>&1
rm -f /tmp/not_a_packet.pcap
