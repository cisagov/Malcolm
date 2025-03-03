#!/usr/bin/env bash

MAIN_DB=${POSTGRES_DB:-postgres}
MAIN_USER=${POSTGRES_USER:-postgres}

NETBOX_DB=${POSTGRES_NETBOX_DB:-netbox}
NETBOX_USER=${POSTGRES_NETBOX_USER:-netbox}
NETBOX_PASSWORD=${POSTGRES_NETBOX_PASSWORD:-}

[[ -n "${NETBOX_PASSWORD}" ]] && \
    psql -v ON_ERROR_STOP=0 --username "$MAIN_USER" --dbname "$MAIN_DB" \
         -v nbuser="$NETBOX_USER" \
         -v nbpassword="$NETBOX_PASSWORD" \
         -v nbdb="$NETBOX_DB" <<-EOSQL
CREATE USER :nbuser PASSWORD :'nbpassword';
ALTER USER :nbuser CREATEDB;
CREATE DATABASE :nbdb;
ALTER DATABASE :nbdb OWNER TO :nbuser;
GRANT ALL PRIVILEGES ON DATABASE :nbdb TO :nbuser;
GRANT ALL PRIVILEGES ON SCHEMA public TO :nbuser;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO :nbuser;
EOSQL
