#!/usr/bin/env bash

echo "Waiting for OpenSearch to be reponsive..."

until timeout 1 bash -c "</dev/tcp/localhost/9200" 2>/dev/null; do
    sleep 1
done

sleep 5

/usr/share/opensearch/plugins/opensearch-security/tools/securityadmin.sh \
  -cd /usr/share/opensearch/config/opensearch-security \
  -icl \
  -nhnv \
  -cacert /usr/share/opensearch/config/certs/ca.crt \
  -cert /usr/share/opensearch/config/certs/admin.crt \
  -key /usr/share/opensearch/config/certs/admin.key \
  -h opensearch
