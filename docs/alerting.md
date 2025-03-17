# <a name="Alerting"></a>Alerting

* [Alerting](#Alerting)
    - [Email Sender Accounts](#AlertingEmail)

Malcolm uses the Alerting plugins for [OpenSearch](https://github.com/opensearch-project/alerting) and [OpenSearch Dashboards](https://github.com/opensearch-project/alerting-dashboards-plugin). See [Alerting](https://opensearch.org/docs/latest/monitoring-plugins/alerting/index/) in the OpenSearch documentation for usage instructions.

A fresh installation of Malcolm configures an example [custom webhook destination](https://opensearch.org/docs/latest/monitoring-plugins/alerting/monitors/#create-destinations) named **Malcolm API Loopback Webhook** that directs the triggered alerts back into the [Malcolm API](api.md#API) to be reindexed as a session record with `event.dataset` set to `alerting`. The corresponding monitor **Malcolm API Loopback Monitor** is disabled by default, as users will likely want to configure the trigger conditions to suit individual needs. These examples are provided to illustrate how triggers and monitors can interact with a custom webhook to process alerts.

## <a name="AlertingEmail"></a>Email Sender Accounts

When using an email account to send alerts, users must [authenticate each sender account](https://opensearch.org/docs/latest/monitoring-plugins/alerting/monitors/#authenticate-sender-account) before sending an email. The [`auth_setup`](authsetup.md#AuthSetup) script can be used to securely store the email account credentials:

```
$ ./scripts/auth_setup
1: all - Configure all authentication-related settings
2: method - Select authentication method (currently "basic")
3: admin - Store administrator username/password for basic HTTP authentication
4: webcerts - (Re)generate self-signed certificates for HTTPS access
5: fwcerts - (Re)generate self-signed certificates for a remote log forwarder
6: keycloak - Configure Keycloak
7: remoteos - Configure remote primary or secondary OpenSearch/Elasticsearch instance
8: email - Store username/password for OpenSearch Alerting email sender account
9: netbox - (Re)generate internal passwords for NetBox
10: keycloakdb - (Re)generate internal passwords for Keycloak's PostgreSQL database
11: postgres - (Re)generate internal superuser passwords for PostgreSQL
12: redis - (Re)generate internal passwords for Redis
13: arkime - Store password hash secret for Arkime viewer cluster
14: txfwcerts - Transfer self-signed client certificates to a remote log forwarder
Configure Authentication (all): 7

OpenSearch alerting email sender name: example

Email account username: analyst@example.org
analyst@example.org password: :
analyst@example.org password (again): :
Email alert sender account variables stored: plugins.alerting.destination.email.example.password, plugins.alerting.destination.email.example.username
```

This action should only be performed while Malcolm is [stopped](running.md#StopAndRestart): otherwise the credentials will not be stored correctly.