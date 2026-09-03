#!/bin/bash

# Copyright (c) 2026 Battelle Energy Alliance, LLC.  All rights reserved.

sleep ${1:-0}
/usr/local/bin/opensearch_status.sh -w

INDEX_PATTERNS=(MALCOLM_NETWORK_INDEX_PATTERN MALCOLM_OTHER_INDEX_PATTERN)
TEMPLATES=(malcolm_template malcolm_beats_template)

for i in "${!INDEX_PATTERNS[@]}"; do
  /usr/local/bin/opensearch_status.sh -t "${TEMPLATES[$i]}"
  /usr/local/bin/index-refresh.py -vvv \
    --dashboards "${DASHBOARDS_URL}" \
    --opensearch "${OPENSEARCH_URL}" \
    --opensearch-mode "${OPENSEARCH_PRIMARY}" \
    --opensearch-curlrc "${OPENSEARCH_CREDS_CONFIG_FILE}" \
    --opensearch-ssl-verify "${OPENSEARCH_SSL_CERTIFICATE_VERIFICATION}" \
    --index "${INDEX_PATTERNS[$i]}" \
    --template "${TEMPLATES[$i]}" \
    --unassigned
done
