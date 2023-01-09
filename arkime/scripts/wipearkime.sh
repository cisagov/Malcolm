#!/bin/bash

# Copyright (c) 2023 Battelle Energy Alliance, LLC.  All rights reserved.

[[ ${OPENSEARCH_SSL_CERTIFICATE_VERIFICATION:-"false"} != "true" ]] && DB_SSL_FLAG="--insecure" || DB_SSL_FLAG=""
OPENSEARCH_URL_FULL="$(grep -Pi '^elasticsearch\s*=' $ARKIME_DIR/etc/config.ini | cut -d'=' -f2-)"

echo "Checking OpenSearch..."
/opt/opensearch_status.sh 2>&1 && echo "OpenSearch is running!"

#Wipe is the same initalize except it keeps users intact
echo WIPE | /opt/arkime/db/db.pl $DB_SSL_FLAG  "${OPENSEARCH_URL_FULL}" wipe

#this is a hacky way to get all of the parseable field definitions put into O.S.
touch /tmp/not_a_packet.pcap
$ARKIME_DIR/bin/capture --insecure --packetcnt 0 -r /tmp/not_a_packet.pcap >/dev/null 2>&1
rm -f /tmp/not_a_packet.pcap
