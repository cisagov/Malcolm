#!/bin/sh

echo "Giving OpenSearch time to start..."
"${APP_HOME}"/opensearch_status.sh 2>&1 && echo "OpenSearch is running!"

exec "$@"
