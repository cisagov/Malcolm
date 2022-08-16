#!/bin/bash

ARKIME_DIR=${ARKIME_DIR:-"/opt/arkime"}
OPENSEARCH_URL=${OPENSEARCH_URL:-"http://opensearch:9200"}

if [[ -r "${ARKIME_DIR}"/etc/config.orig.ini ]]; then
    cp "${ARKIME_DIR}"/etc/config.orig.ini "${ARKIME_DIR}"/etc/config.ini
    sed -i "s/^\(elasticsearch=\).*/\1"${OPENSEARCH_URL}"/" "${ARKIME_DIR}"/etc/config.ini
fi

# start supervisor or whatever the default command is
exec "$@"
