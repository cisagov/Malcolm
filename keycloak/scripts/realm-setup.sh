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
        /opt/keycloak/bin/kcadm.sh create roles -r "${KEYCLOAK_AUTH_REALM}" -s name="${ROLE_NAME}" 2>&1 | grep -v "already exists"
      fi
    done

  else
    echo "Failed to log into Keycloak CLI!" >&2
    exit 1
  fi
fi
