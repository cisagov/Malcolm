#!/usr/bin/env bash

if [[ "${NGINX_AUTH_MODE:-keycloak}" == "keycloak" ]]; then
  POSTGRES_HOST=${POSTGRES_HOST:-postgres}
  PGPORT=${PGPORT:-5432}
  POSTGRES_MAIN_DB=${POSTGRES_DB:-postgres}
  POSTGRES_KEYCLOAK_DB=${POSTGRES_KEYCLOAK_DB:-keycloak}
  export KC_DB_USERNAME="${POSTGRES_KEYCLOAK_USER:-keycloak}"
  export KC_DB_PASSWORD="${POSTGRES_KEYCLOAK_PASSWORD:-}"
  export KC_DB_URL="jdbc:postgresql://${POSTGRES_HOST}:${PGPORT}/${POSTGRES_KEYCLOAK_DB}"
  export KC_DB=postgres
  [[ -n "${KC_BOOTSTRAP_ADMIN_USERNAME:-}" ]] && export KC_BOOTSTRAP_ADMIN_USERNAME || unset KC_BOOTSTRAP_ADMIN_USERNAME
  [[ -n "${KC_BOOTSTRAP_ADMIN_PASSWORD:-}" ]] && export KC_BOOTSTRAP_ADMIN_PASSWORD || unset KC_BOOTSTRAP_ADMIN_PASSWORD

  until PGPASSWORD="${KC_DB_PASSWORD}" pg_isready -U "${KC_DB_USERNAME}" \
                                                  -h "${POSTGRES_HOST}" -p ${PGPORT} >/dev/null 2>&1; do
    sleep 5
  done
  echo "PostgreSQL is responding..."

  until PGPASSWORD="${KC_DB_PASSWORD}" psql -U "${KC_DB_USERNAME}" \
                                            -h "${POSTGRES_HOST}" -p ${PGPORT} \
                                            -d "${POSTGRES_MAIN_DB}" -tAc \
      "SELECT 1 FROM pg_database WHERE datname = '${POSTGRES_KEYCLOAK_DB}';" 2>/dev/null | grep -q 1; do
    sleep 5
  done
  echo "PostgreSQL is up and ready at ${KC_DB_URL}!"
fi

exec "$@"
