#!/usr/bin/env bash

# Copyright (c) 2026 Battelle Energy Alliance, LLC. All rights reserved.

set -euo pipefail

# Run in the NetBox container, which has the application credentials, client
# tools and CA mounts even when the embedded PostgreSQL server is disabled.
export PGPASSWORD="${POSTGRES_NETBOX_PASSWORD:-${DB_PASSWORD:-}}"
if [[ -r /run/secrets/db_password ]]; then
  PGPASSWORD=$(head -n 1 /run/secrets/db_password)
fi
# Match the Django connection's explicit SSL override; otherwise libpq uses
# PGSSLMODE and PGSSLROOTCERT from the container environment.
[[ -n "${DB_SSLMODE:-}" ]] && export PGSSLMODE="${DB_SSLMODE}"

exec pg_dump --no-password \
  --host "${POSTGRES_HOST:-${DB_HOST:-postgres}}" \
  --port "${PGPORT:-${DB_PORT:-5432}}" \
  --username "${POSTGRES_NETBOX_USER:-${DB_USER:-netbox}}" \
  --dbname "${POSTGRES_NETBOX_DB:-${DB_NAME:-netbox}}"
