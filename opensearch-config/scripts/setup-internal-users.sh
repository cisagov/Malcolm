#!/usr/bin/env bash

CREDS_CONFIG_FILE=${OPENSEARCH_CREDS_CONFIG_FILE:-"/var/local/curlrc/.opensearch.primary.curlrc"}
OPENSEARCH_SECURITY_CERTS_DIR=/usr/share/opensearch/config/certs
INTERNAL_USERS_YML=/usr/share/opensearch/config/opensearch-security/internal_users.yml

# get the new username/password from the curl file (I already wrote python code to do this, so sue me)
pushd "$(dirname $(realpath -e "${BASH_SOURCE[0]}"))" >/dev/null 2>&1
INTERNAL_CREDS="$(python3 -c "import malcolm_utils; result=malcolm_utils.ParseCurlFile('$CREDS_CONFIG_FILE'); print(result['user']+'|'+result['password']);")"
INTERNAL_USERNAME="$(echo "$INTERNAL_CREDS" | cut -d'|' -f1)"
INTERNAL_PASSWORD="$(INTERNAL_PASSWORD="$(echo "$INTERNAL_CREDS" | cut -d'|' -f2)" /usr/share/opensearch/plugins/opensearch-security/tools/hash.sh -env INTERNAL_PASSWORD)"
popd >/dev/null 2>&1

if [[ -n "${INTERNAL_USERNAME}" ]] && [[ -n "${INTERNAL_PASSWORD}" ]]; then
  cat <<EOF > "$INTERNAL_USERS_YML"
---
_meta:
  type: "internalusers"
  config_version: 2

${INTERNAL_USERNAME}:
  hash: "${INTERNAL_PASSWORD}"
  reserved: true
  backend_roles:
  - "admin"
  description: "internal Malcolm service account"
EOF
else
  cat <<EOF > "$INTERNAL_USERS_YML"
---
_meta:
  type: "internalusers"
  config_version: 2
EOF
fi

[[ -x /usr/local/bin/self_signed_key_gen.sh ]] && \
  /usr/local/bin/self_signed_key_gen.sh -n \
    -o "${OPENSEARCH_SECURITY_CERTS_DIR}" \
    -s '/CN=opensearch/OU=ca/O=Malcolm/ST=ID/C=US' \
    -d '/CN=opensearch-node/OU=node/O=Malcolm/ST=ID/C=US' \
    -c '/CN=opensearch-admin/OU=admin/O=Malcolm/ST=ID/C=US' >/dev/null 2>&1

# /usr/share/opensearch/plugins/opensearch-security/tools/securityadmin.sh \
#   -cd /usr/share/opensearch/config/opensearch-security \
#   -icl \
#   -nhnv \
#   -cacert /usr/share/opensearch/config/certs/ca.crt \
#   -cert /usr/share/opensearch/config/certs/client.crt \
#   -key /usr/share/opensearch/config/certs/client.key \
#   -h opensearch