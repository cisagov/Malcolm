#!/usr/bin/env bash

CREDS_CONFIG_FILE=${OPENSEARCH_CREDS_CONFIG_FILE:-"/var/local/curlrc/.opensearch.primary.curlrc"}
OPENSEARCH_SECURITY_CERTS_DIR=/usr/share/opensearch/config/certs
INTERNAL_USERS_YML=/usr/share/opensearch/config/opensearch-security/internal_users.yml
ROLE_MAPPING_YML_ORIG=/usr/share/opensearch/config/opensearch-security/roles_mapping.yml.orig
ROLE_MAPPING_YML=/usr/share/opensearch/config/opensearch-security/roles_mapping.yml

# get the new username/password from the curl file (I already wrote python code to do this, so sue me)
pushd "$(dirname $(realpath -e "${BASH_SOURCE[0]}"))" >/dev/null 2>&1
INTERNAL_CREDS="$(python3 -c "import malcolm_utils; result=malcolm_utils.ParseCurlFile('$CREDS_CONFIG_FILE'); print(result['user']+'|'+result['password']);")"
INTERNAL_USERNAME="$(echo "$INTERNAL_CREDS" | cut -d'|' -f1)"
INTERNAL_PASSWORD="$(INTERNAL_PASSWORD="$(echo "$INTERNAL_CREDS" | cut -d'|' -f2)" /usr/share/opensearch/plugins/opensearch-security/tools/hash.sh -env INTERNAL_PASSWORD)"
popd >/dev/null 2>&1

# generate internal_users.yml
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

# do replacers from environment bariables for roles_mapping.yml
if [[ -r "${ROLE_MAPPING_YML_ORIG}" ]]; then
  envsubst < "${ROLE_MAPPING_YML_ORIG}" \
    | yq 'del(.[] | select(.backend_roles and (.backend_roles[] == "")))' \
    > "${ROLE_MAPPING_YML}"
fi

# generate self-signed keys wanted by opensearch security plugin (only used internally)
[[ -x /usr/local/bin/self_signed_key_gen.sh ]] && \
  /usr/local/bin/self_signed_key_gen.sh -n -p \
    -o "${OPENSEARCH_SECURITY_CERTS_DIR}" \
    -s '/CN=opensearch/OU=ca/O=Malcolm/ST=ID/C=US' \
    -d '/CN=opensearch-node/OU=node/O=Malcolm/ST=ID/C=US' \
    -c '/CN=opensearch-admin/OU=admin/O=Malcolm/ST=ID/C=US' >/dev/null 2>&1 && \
    mv "${OPENSEARCH_SECURITY_CERTS_DIR}"/{client,admin}.crt && \
    mv "${OPENSEARCH_SECURITY_CERTS_DIR}"/{client,admin}.key

# background setup processes to run after opensearch starts
[[ -x /usr/local/bin/setup-post-start.sh ]] && \
  ( setsid bash -c '/usr/local/bin/setup-post-start.sh >/dev/null 2>&1 </dev/null &' ) >/dev/null 2>&1 </dev/null
