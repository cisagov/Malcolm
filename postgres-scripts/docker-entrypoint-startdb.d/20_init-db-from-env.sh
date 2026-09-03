#!/usr/bin/env bash

# This script looks at the environment variables named:
# - POSTGRES_XXX_DB
# - POSTGRES_XXX_USER
# - POSTGRES_XXX_PASSWORD
# And, if it finds all three variables where XXX is the same value (e.g.)
#   NETBOX, KEYCLOAK, FOOBAR, etc.) it will create the corresponding user/password and
#   database and grant that user permissions for that database. It's also
#   granting default public schema privileges to the users created.

MAIN_DB=${POSTGRES_DB:-postgres}
MAIN_USER=${POSTGRES_USER:-postgres}

declare -A POSTGRES_DB
declare -A POSTGRES_USER
declare -A POSTGRES_PASSWORD

for var in $(env); do
    if [[ "$var" =~ ^POSTGRES_([A-Za-z0-9_]+)_(DB|USER|PASSWORD)=(.*) ]]; then
        base="${BASH_REMATCH[1]}"
        type="${BASH_REMATCH[2]}"
        value="${BASH_REMATCH[3]}"
        if [[ "$type" == "DB" ]]; then
            POSTGRES_DB["$base"]="$value"
        elif [[ "$type" == "USER" ]]; then
            POSTGRES_USER["$base"]="$value"
        elif [[ "$type" == "PASSWORD" ]]; then
            POSTGRES_PASSWORD["$base"]="$value"
        fi
    fi
done

TEMP_SQL=$(mktemp)
touch "$TEMP_SQL"
PSQL_VAR_ARGS=()
for base in "${!POSTGRES_DB[@]}"; do
    if [[ ${#base} -gt 1 ]] && [[ -n "${POSTGRES_USER[$base]}" ]] && [[ -n "${POSTGRES_PASSWORD[$base]}" ]]; then
        KEYNAME=$(echo "${base,,}")
        PSQL_VAR_ARGS+=( -v )
        PSQL_VAR_ARGS+=( "${KEYNAME}user=${POSTGRES_USER[$base]}" )
        PSQL_VAR_ARGS+=( -v )
        PSQL_VAR_ARGS+=( "${KEYNAME}password=${POSTGRES_PASSWORD[$base]}" )
        PSQL_VAR_ARGS+=( -v )
        PSQL_VAR_ARGS+=( "${KEYNAME}db=${POSTGRES_DB[$base]}" )
        cat >> "$TEMP_SQL" <<EOF
\set ${KEYNAME}_role_exists false
SELECT EXISTS(SELECT 1 FROM pg_roles WHERE rolname = :'${KEYNAME}user') AS ${KEYNAME}_role_exists \gset
\if :${KEYNAME}_role_exists
  \echo :${KEYNAME}user' user already exists'
\else
  CREATE USER :${KEYNAME}user PASSWORD :'${KEYNAME}password';
\endif

ALTER USER :${KEYNAME}user CREATEDB;

\set ${KEYNAME}_db_exists false
SELECT EXISTS(SELECT 1 FROM pg_database WHERE datname = :'${KEYNAME}db') AS ${KEYNAME}_db_exists \gset
\if :${KEYNAME}_db_exists
  \echo :${KEYNAME}db' database already exists'
\else
  CREATE DATABASE :${KEYNAME}db;
\endif

ALTER DATABASE :${KEYNAME}db OWNER TO :${KEYNAME}user;
GRANT ALL PRIVILEGES ON DATABASE :${KEYNAME}db TO :${KEYNAME}user;
GRANT ALL PRIVILEGES ON SCHEMA public TO :${KEYNAME}user;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO :${KEYNAME}user;
EOF
    fi
done

if [[ -s "$TEMP_SQL" ]]; then
    psql -v ON_ERROR_STOP=0 --username "$MAIN_USER" --dbname "$MAIN_DB" "${PSQL_VAR_ARGS[@]}" -f "$TEMP_SQL"
    PSQL_EXIT_CODE=$?
else
    PSQL_EXIT_CODE=0
fi
rm -f "$TEMP_SQL"

exit $PSQL_EXIT_CODE