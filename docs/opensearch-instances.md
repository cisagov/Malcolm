# <a name="OpenSearchInstance"></a>OpenSearch and Elasticsearch instances

* [OpenSearch and Elasticsearch instances](#OpenSearchInstance)
    - [Authentication and authorization for remote data store clusters](#OpenSearchAuth)

Malcolm's default standalone configuration is to use a local [OpenSearch](https://opensearch.org/) instance in a container to index and search network traffic metadata. OpenSearch can also run as a [cluster](https://opensearch.org/docs/latest/opensearch/cluster/) with instances distributed across multiple nodes with dedicated [roles](https://opensearch.org/docs/latest/opensearch/cluster/#nodes) such as cluster manager, data node, ingest node, etc.

As the permutations of OpenSearch cluster configurations are numerous, it is beyond Malcolm's scope to set up multi-node clusters. However, Malcolm can be configured to use a remote OpenSearch cluster rather than its own internal instance.

As an alternative to OpenSearch, Malcolm [may now be configured](https://github.com/idaholab/Malcolm/issues/258) to use a remote [Elasticsearch](https://www.elastic.co/elasticsearch/) cluster with its own instance of [Kibana](https://www.elastic.co/kibana). This configuration is intended for users that already have the Elastic stack deployed in their environments; OpenSearch is recommended for greenfield deployments.

The `OPENSEARCH_…` [environment variables in `opensearch.env`](malcolm-config.md#MalcolmConfigEnvVars) control whether Malcolm uses its own local OpenSearch instance (`opensearch-local`), a remote OpenSearch instance (`opensearch-remote`) or a remote Elasticsearch instance (`elasticsearch-remote`) as its primary data store. The configuration portion of Malcolm install script ([`./scripts/configure`](malcolm-hedgehog-e2e-iso-install.md#MalcolmConfig)) can help users configure these options.

For example, to use the default standalone configuration, select `opensearch-local` for `Primary Document Store`:
```
…
├── 6. Run Profile (current: malcolm)
…
│   ├── 22. OpenSearch Memory (current: 31g)
│   └── 23. Primary Document Store (current: opensearch-local)
…
```

To use a remote OpenSearch cluster:

```
…
├── 6. Run Profile (current: malcolm)
…
│   └── 22. Primary Document Store (current: opensearch-remote)
│       ├── 23. Primary OpenSearch/Elasticsearch URL (current: https://malcolm.home.arpa:9200)
│       └── 24. Verify SSL for Primary Document Store (current: No)
…
```

To use a remote Elasticsearch cluster and Kibana:

```
…
├── 6. Run Profile (current: malcolm)
…
│   └── 22. Primary Document Store (current: elasticsearch-remote)
│       ├── 23. Primary OpenSearch/Elasticsearch URL (current: https://elasticsearch.home.arpa:9200)
│       └── 24. Verify SSL for Primary Document Store (current: No)
…
```

Whether the primary data store is a locally maintained single-node instance or is a remote cluster, Malcolm can additionally be configured to forward logs to a secondary remote OpenSearch or Elasticsearch instance. The `OPENSEARCH_SECONDARY_…` [environment variables in `opensearch.env`](malcolm-config.md#MalcolmConfigEnvVars) control this behavior. Configuration of a remote secondary data store is similar to that of a remote primary data store:


```
…
Forward Logstash logs to a secondary remote document store? (y / N): y

1: opensearch-remote - remote OpenSearch
2: elasticsearch-remote - remote Elasticsearch
Select secondary Malcolm document store: 1

Enter secondary remote OpenSearch connection URL (e.g., https://192.168.1.123:9200) (): https://10.9.0.216:9200

Require SSL certificate validation for communication with secondary remote OpenSearch instance? (y / N): n

You must run auth_setup after configure to store data store connection credentials.
…
```

## <a name="OpenSearchAuth"></a>Authentication and authorization for remote data store clusters

In addition to setting the environment variables in [`opensearch.env`](malcolm-config.md#MalcolmConfigEnvVars) as described above, users must provide Malcolm with credentials for it to communicate with remote OpenSearch and Elasticsearch instances. These credentials are stored in the Malcolm installation directory as `.opensearch.primary.curlrc` and `.opensearch.secondary.curlrc` for the primary and secondary data store connections, respectively, and are bind-mounted into the containers that need to communicate with OpenSearch/Elasticsearch. These [cURL-formatted](https://everything.curl.dev/cmdline/configfile) config files can be generated for you by the [`auth_setup`](authsetup.md#AuthSetup) script as illustrated:

```
$ ./scripts/auth_setup 

…

Store username/password for primary remote OpenSearch/Elasticsearch instance? (y / N): y

OpenSearch/Elasticsearch username: servicedb 
servicedb password:
servicedb password (again):

Additional local accounts can be created at https://localhost/auth/ when Malcolm is running

Require SSL certificate validation for OpenSearch/Elasticsearch communication? (Y / n): n

Will Malcolm be using an existing remote primary or secondary OpenSearch instance? (y / N): y

Store username/password for secondary remote OpenSearch/Elasticsearch instance?? (y / N): y

OpenSearch/Elasticsearch username: remotedb
remotedb password:
remotedb password (again):

Require SSL certificate validation for OpenSearch/Elasticsearch communication? (Y / n): n

…
```

These files are created with permissions such that only the user account running Malcolm can access them:

```
$ ls -la .opensearch.*.curlrc
-rw------- 1 user user 36 Aug 22 14:17 .opensearch.primary.curlrc
-rw------- 1 user user 35 Aug 22 14:18 .opensearch.secondary.curlrc
```

One caveat with Malcolm using a remote OpenSearch as its primary document store is that the accounts used to access Malcolm's [web interfaces](quickstart.md#UserInterfaceURLs), particularly [OpenSearch Dashboards](dashboards.md#Dashboards), are passed directly through to OpenSearch itself. For this reason, both Malcolm and the remote primary OpenSearch instance must have the same account information. The easiest way to accomplish this is to use an Active Directory/LDAP server that both [Malcolm](authsetup.md#AuthLDAP) and [OpenSearch](https://opensearch.org/docs/latest/security-plugin/configuration/ldap/) use as a common authentication backend.

See the OpenSearch documentation on [access control](https://opensearch.org/docs/latest/security-plugin/access-control/index/) or the Elasticsearch documentation on [user authorization](https://www.elastic.co/guide/en/elasticsearch/reference/current/authorization.html) for more information.
