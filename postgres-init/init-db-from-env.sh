#!/usr/bin/env bash

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
        echo "CREATE USER :${KEYNAME}user PASSWORD :'${KEYNAME}password';" >> "$TEMP_SQL"
        echo "ALTER USER :${KEYNAME}user CREATEDB;" >> "$TEMP_SQL"
        echo "CREATE DATABASE :${KEYNAME}db;" >> "$TEMP_SQL"
        echo "ALTER DATABASE :${KEYNAME}db OWNER TO :${KEYNAME}user;" >> "$TEMP_SQL"
        echo "GRANT ALL PRIVILEGES ON DATABASE :${KEYNAME}db TO :${KEYNAME}user;" >> "$TEMP_SQL"
        echo "GRANT ALL PRIVILEGES ON SCHEMA public TO :${KEYNAME}user;" >> "$TEMP_SQL"
        echo "ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO :${KEYNAME}user;" >> "$TEMP_SQL"
    fi
done

[[ -s "$TEMP_SQL" ]] && psql -v ON_ERROR_STOP=0 --username "$MAIN_USER" --dbname "$MAIN_DB" -f "$TEMP_SQL" "${PSQL_VAR_ARGS[@]}"
rm -f "$TEMP_SQL"