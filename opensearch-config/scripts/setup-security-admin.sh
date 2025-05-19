#!/usr/bin/env bash

/usr/local/bin/opensearch_status.sh 2>&1 && \
    echo "${OPENSEARCH_PRIMARY:-opensearch-local} is running, setting security plugin configuration..." >&2

/usr/share/opensearch/plugins/opensearch-security/tools/securityadmin.sh \
  -cd /usr/share/opensearch/config/opensearch-security \
  -icl \
  -nhnv \
  -cacert /usr/share/opensearch/config/certs/ca.crt \
  -cert /usr/share/opensearch/config/certs/admin.crt \
  -key /usr/share/opensearch/config/certs/admin.key \
  -h opensearch
