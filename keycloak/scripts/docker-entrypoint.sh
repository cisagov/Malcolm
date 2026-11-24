#!/usr/bin/env bash

if [[ "${NGINX_AUTH_MODE:-keycloak}" == "keycloak" ]]; then
  POSTGRES_HOST=${POSTGRES_HOST:-postgres}
  PGPORT=${PGPORT:-5432}
  POSTGRES_KEYCLOAK_DB=${POSTGRES_KEYCLOAK_DB:-keycloak}
  export KC_DB_USERNAME="${POSTGRES_KEYCLOAK_USER:-keycloak}"
  export KC_DB_PASSWORD="${POSTGRES_KEYCLOAK_PASSWORD:-}"
  POSTGRES_JDBC_HOST=${POSTGRES_HOST}
  if [[ "${POSTGRES_JDBC_HOST}" == *:* && "${POSTGRES_JDBC_HOST}" != \[*\] ]]; then
    POSTGRES_JDBC_HOST="[${POSTGRES_JDBC_HOST}]"
  fi
  export KC_DB_URL="jdbc:postgresql://${POSTGRES_JDBC_HOST}:${PGPORT}/${POSTGRES_KEYCLOAK_DB}${KC_DB_URL_PROPERTIES:-}"
  export KC_DB=postgres
  [[ -n "${KC_BOOTSTRAP_ADMIN_USERNAME:-}" ]] && export KC_BOOTSTRAP_ADMIN_USERNAME || unset KC_BOOTSTRAP_ADMIN_USERNAME
  [[ -n "${KC_BOOTSTRAP_ADMIN_PASSWORD:-}" ]] && export KC_BOOTSTRAP_ADMIN_PASSWORD || unset KC_BOOTSTRAP_ADMIN_PASSWORD

  until PGPASSWORD="${KC_DB_PASSWORD}" pg_isready -U "${KC_DB_USERNAME}" \
                                                  -h "${POSTGRES_HOST}" -p "${PGPORT}" -d "${POSTGRES_KEYCLOAK_DB}" >/dev/null 2>&1; do
    sleep 5
  done
  echo "PostgreSQL is responding..."

  # Restricted external accounts may only connect to their application database.
  # Check that connection directly rather than querying the maintenance database.
  until PGPASSWORD="${KC_DB_PASSWORD}" psql -w -U "${KC_DB_USERNAME}" \
                                            -h "${POSTGRES_HOST}" -p "${PGPORT}" \
                                            -d "${POSTGRES_KEYCLOAK_DB}" -tAc 'SELECT 1' >/dev/null 2>&1; do
    sleep 5
  done
  echo "PostgreSQL application database is ready at ${POSTGRES_HOST}:${PGPORT}/${POSTGRES_KEYCLOAK_DB}!"
fi

[[ -x /usr/local/bin/realm-setup.sh ]] && \
  ( setsid bash -c '/usr/local/bin/realm-setup.sh >/dev/null 2>&1 </dev/null &' ) >/dev/null 2>&1 </dev/null

exec "$@"
