# Using an external PostgreSQL server

NetBox and Malcolm's embedded Keycloak instance can use an externally managed PostgreSQL server. They share the endpoint in `config/postgres.env` and use separate application databases and credentials. This does not affect a remote NetBox or remote Keycloak deployment, which manages its own database configuration.

## Prepare the server

Create the NetBox and Keycloak databases and login roles before starting Malcolm. Each application role must own its database and be able to create and update its schema for migrations. Ordinary startup does not require a superuser role or access to the `postgres` maintenance database. Use the PostgreSQL versions supported by the NetBox and Keycloak versions packaged with your Malcolm release. The database server must also be compatible with the `pg_dump` client included in the NetBox image; a client cannot dump a newer server major version.

A database administrator should provision these resources and restrict inbound access to the Malcolm hosts. Use separate strong passwords and configure verified TLS for connections outside the local container network. The embedded server's initialization scripts do not provision or change accounts on an external server.

## Configure Malcolm

Complete Malcolm's initial authentication setup first. Then edit `config/postgres.env` on the Malcolm host:

```dotenv
POSTGRES_HOST=postgres.example.org
PGPORT=5432
POSTGRES_DISABLED=true
POSTGRES_NETBOX_DB=malcolm_netbox
POSTGRES_NETBOX_USER=malcolm_netbox
POSTGRES_NETBOX_PASSWORD='replace-with-the-provisioned-password'
POSTGRES_KEYCLOAK_DB=malcolm_keycloak
POSTGRES_KEYCLOAK_USER=malcolm_keycloak
POSTGRES_KEYCLOAK_PASSWORD='replace-with-the-other-provisioned-password'
PGSSLMODE=verify-full
PGSSLROOTCERT=/var/local/ca-trust/postgres-ca.crt
```

Place the issuing CA certificate in `nginx/ca-trust/postgres-ca.crt`, which the supplied deployment mounts read-only at `/var/local/ca-trust/` in the application containers. Confirm that the certificate matches the database hostname. Do not place passwords in source control. Preserve the restrictive permissions on the environment files.

Keycloak uses a JDBC driver, so configure its TLS properties separately in `config/keycloak.env`:

```dotenv
KC_DB_URL_PROPERTIES='?sslmode=verify-full&sslrootcert=/var/local/ca-trust/postgres-ca.crt'
```

These properties are appended to the PostgreSQL JDBC URL built from `POSTGRES_HOST`, `PGPORT` and `POSTGRES_KEYCLOAK_DB`. Keep the libpq and JDBC settings consistent. `KEYCLOAK_SSL_VERIFY` controls HTTP access to Keycloak and does not configure its database connection. An explicitly configured NetBox `DB_SSLMODE` overrides `PGSSLMODE`; remove or update a conflicting override.

Restart the affected services through Malcolm's control scripts after saving the settings. `POSTGRES_DISABLED=true` prevents the embedded server from running; its container may remain present in a disabled state. The application clients still connect to `POSTGRES_HOST`. Keycloak tests its application database directly, so the role does not need access to a separate maintenance database.

Do not regenerate the NetBox or Keycloak database passwords through `auth_setup` after this change unless the external server's roles are updated to match. Malcolm cannot synchronize credentials on an externally managed server.

## Back up and restore

Keep the local NetBox container running for backups. The normal [NetBox backup command](asset-interaction-analysis.md#NetBoxBackup) runs `pg_dump` in the NetBox container using its database endpoint, credentials and TLS configuration. It therefore works with the embedded server disabled. Passwords are read inside the container rather than added to the host command line. Media backup remains a separate local archive; the existing Kubernetes limitation on media backup remains unchanged.

The built-in NetBox restore workflow drops and recreates the selected application database. It requires database ownership, `CREATEDB`, and access to a maintenance database. It is unsuitable for a restricted managed-service role without those permissions. In that case, have the database administrator restore the backup using the provider's supported process. Stop application writes and make a recoverable backup before any restore. Custom database names are used explicitly by all restore SQL commands.

Back up Keycloak separately using your database administrator's or provider's procedure. The NetBox backup command does not include Keycloak data.

## Move an existing deployment

Changing the endpoint does not copy data. Back up both application databases, stop their writers, restore into the provisioned destination databases, then update Malcolm's settings and restart. Validate authentication, inventory, migrations and a fresh backup before retiring the original server. Keep the original volumes and backups available until the replacement has been verified. For a provider-managed server, review its supported PostgreSQL versions, extensions, network access and restore restrictions before migration.
