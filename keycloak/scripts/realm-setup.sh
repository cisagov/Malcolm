#!/usr/bin/env bash

ENCODING="utf-8"
set -uo pipefail

ADM_SCRIPT=/opt/keycloak/bin/kcadm.sh

if [[ "${NGINX_AUTH_MODE:-keycloak}" == "keycloak" ]] && \
   [[ -x "${ADM_SCRIPT}" ]] && \
   [[ -n "${KEYCLOAK_AUTH_REALM}" ]] && \
   [[ -n "${KC_BOOTSTRAP_ADMIN_USERNAME}" ]] && \
   [[ -n "${KC_BOOTSTRAP_ADMIN_PASSWORD}" ]]; then

  echo "Waiting for Keycloak to be ready... " >&2
  until curl -sSLf --output /dev/null "http://localhost:8080${KC_HTTP_RELATIVE_PATH:-}/realms/${KEYCLOAK_AUTH_REALM}" >/dev/null 2>&1; do
    sleep 5
  done
  echo "Keycloak is ready!" >&2

  echo "Logging into Keycloak CLI..." >&2
  if "${ADM_SCRIPT}" config credentials \
        --server "http://localhost:8080${KC_HTTP_RELATIVE_PATH:-}" \
        --realm "${KEYCLOAK_AUTH_REALM}" \
        --user "${KC_BOOTSTRAP_ADMIN_USERNAME}" \
        --password "${KC_BOOTSTRAP_ADMIN_PASSWORD}" >/dev/null 2>&1; then

    echo "Ensuring realm exists: \"${KEYCLOAK_AUTH_REALM}\"..." >&2
    "${ADM_SCRIPT}" create realms -s realm="${KEYCLOAK_AUTH_REALM}" -s enabled=true 2>&1 | grep -v "already exists"

    for ROLE_VAR in $(compgen -e); do
      [[ "$ROLE_VAR" == ROLE_* && "$ROLE_VAR" != "ROLE_BASED_ACCESS" ]] || continue
      ROLE_NAME="${!ROLE_VAR}"
      if [[ -n "${ROLE_NAME}" ]]; then
        echo "Ensuring role exists: \"$ROLE_NAME\"" >&2
        "${ADM_SCRIPT}" create roles -r "${KEYCLOAK_AUTH_REALM}" -s name="${ROLE_NAME}" 2>&1 | grep -v "already exists"
      fi
    done

    if [[ -n "${KEYCLOAK_CLIENT_ID}" ]]; then
      echo "Ensuring client exists: \"${KEYCLOAK_CLIENT_ID}\"..." >&2

      if [[ -n "${KC_HTTP_RELATIVE_PATH:-/keycloak}" && "${KEYCLOAK_AUTH_URL}" == *"${KC_HTTP_RELATIVE_PATH}" ]]; then
        BASE_KEYCLOAK_URL="${KEYCLOAK_AUTH_URL%"${KC_HTTP_RELATIVE_PATH}"}"
      else
        BASE_KEYCLOAK_URL="${KEYCLOAK_AUTH_URL}"
      fi
      BASE_KEYCLOAK_URL="${BASE_KEYCLOAK_URL%/}"

      ATTRIBUTES_JSON_FILE=$(mktemp --suffix=.json)
      jq -c -n \
        --arg clientId "${KEYCLOAK_CLIENT_ID}" \
        --arg url "${BASE_KEYCLOAK_URL}" \
        --arg postLogoutRedirectUri "${KEYCLOAK_AUTH_URL}" \
        --argjson redirectUris '["/*"]' \
        --argjson webOrigins "[\"${BASE_KEYCLOAK_URL}\"]" \
        '{
            clientId: $clientId,
            rootUrl: $url,
            adminUrl: $url,
            baseUrl: $url,
            standardFlowEnabled: true,
            directAccessGrantsEnabled: true,
            enabled: true,
            attributes: {
              "post.logout.redirect.uris": $postLogoutRedirectUri
            },
            redirectUris: $redirectUris,
            webOrigins: $webOrigins
          }' > "${ATTRIBUTES_JSON_FILE}"
      "${ADM_SCRIPT}" create clients -r "${KEYCLOAK_AUTH_REALM}" \
        -f "${ATTRIBUTES_JSON_FILE}" 2>&1 | grep -v "already exists"
      rm -f "${ATTRIBUTES_JSON_FILE}"

      CLIENT_ID=$("${ADM_SCRIPT}" get clients -r "${KEYCLOAK_AUTH_REALM}" \
        --query "clientId=${KEYCLOAK_CLIENT_ID}" \
        --fields id 2>/dev/null| jq -r '.[0].id')
      if [[ -n "${CLIENT_ID}" ]]; then
        echo "Ensuring protocol mappers exist..." >&2
        USER_REALM_ROLE_JSON_FILE=$(mktemp --suffix=.json)
        GROUP_JSON_FILE=$(mktemp --suffix=.json)

        jq -c -n \
          '{
            name: "user_realm_role",
            protocol: "openid-connect",
            protocolMapper: "oidc-usermodel-realm-role-mapper",
            consentRequired: false,
            config: {
              "introspection.token.claim": "true",
              multivalued: "true",
              "userinfo.token.claim": "true",
              "id.token.claim": "true",
              "lightweight.claim": "false",
              "access.token.claim": "true",
              "claim.name": "realm_access.roles",
              "jsonType.label": "String"
            }
          }' > "${USER_REALM_ROLE_JSON_FILE}"

        jq -c -n \
          '{
            name: "group_membership",
            protocol: "openid-connect",
            protocolMapper: "oidc-group-membership-mapper",
            consentRequired: false,
            config: {
              "full.path": true,
              "introspection.token.claim": true,
              "userinfo.token.claim": true,
              "id.token.claim": true,
              "lightweight.claim": false,
              "access.token.claim": true,
              "claim.name": "groups"
            }
          }' > "${GROUP_JSON_FILE}"

        for MAPPER_JSON_FILE in "${USER_REALM_ROLE_JSON_FILE}" "${GROUP_JSON_FILE}"; do
          "${ADM_SCRIPT}" create clients/"$CLIENT_ID"/protocol-mappers/models -r "${KEYCLOAK_AUTH_REALM}" \
            -f "${MAPPER_JSON_FILE}" 2>&1 | grep -v "exists with same name"
          rm -f "${MAPPER_JSON_FILE}"
        done
      fi
    fi

  else
    echo "Failed to log into Keycloak CLI!" >&2
    exit 1
  fi
fi
