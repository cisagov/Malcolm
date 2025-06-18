#!/usr/bin/env bash

echo "Waiting for OpenSearch to be reponsive..." >&2

until timeout 1 bash -c "</dev/tcp/localhost/9200" 2>/dev/null; do
    sleep 1
done
sleep 5

echo "Configuring OpenSearch Security plugin..." >&2
/usr/share/opensearch/plugins/opensearch-security/tools/securityadmin.sh \
  -cd /usr/share/opensearch/config/opensearch-security \
  -icl \
  -nhnv \
  -cacert /usr/share/opensearch/config/certs/ca.crt \
  -cert /usr/share/opensearch/config/certs/admin.crt \
  -key /usr/share/opensearch/config/certs/admin.key \
  -h opensearch

# These settings need to be done with the "admin certificate"
#   ("indices:admin/settings/update for '_all' indices is not allowed for a regular user")
#   so they're done here rather than with the internal service account.
CURL_OUT=$(mktemp)
OPENSEARCH_URL=${OPENSEARCH_URL:-"https://localhost:9200"}
XSRF_HEADER="osd-xsrf"
/usr/local/bin/opensearch_status.sh >/dev/null 2>&1
echo "Setting number_of_replicas for single-node..."
curl --cert /usr/share/opensearch/config/certs/admin.crt \
     --key /usr/share/opensearch/config/certs/admin.key \
     --insecure --location --fail-with-body --silent --output "$CURL_OUT" \
     -XPUT "$OPENSEARCH_URL/_settings" \
     -H "$XSRF_HEADER:true" -H 'Content-type:application/json' \
     -d '{ "index": { "number_of_replicas":0 } }' || ( cat "$CURL_OUT" && echo )
curl --cert /usr/share/opensearch/config/certs/admin.crt \
     --key /usr/share/opensearch/config/certs/admin.key \
     --insecure --location --fail-with-body --silent --output "$CURL_OUT" \
     -XPUT "$OPENSEARCH_URL/_cluster/settings" \
     -H "$XSRF_HEADER:true" -H 'Content-type:application/json' \
     -d '{ "persistent": { "cluster.default_number_of_replicas":0 } }' || ( cat "$CURL_OUT" && echo )
[[ -n "${CLUSTER_MAX_SHARDS_PER_NODE}" ]] && \
     curl --cert /usr/share/opensearch/config/certs/admin.crt \
          --key /usr/share/opensearch/config/certs/admin.key \
          --insecure --location --fail-with-body --silent --output "$CURL_OUT" \
          -XPUT "$OPENSEARCH_URL/_cluster/settings" \
          -H "$XSRF_HEADER:true" -H 'Content-type:application/json' \
          -d "{ \"persistent\": { \"cluster.max_shards_per_node\": \"$CLUSTER_MAX_SHARDS_PER_NODE\" } }" || ( cat "$CURL_OUT" && echo )

rm -f "${CURL_OUT}"
