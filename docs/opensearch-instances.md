# <a name="OpenSearchInstance"></a>OpenSearch instances

* [OpenSearch instances](#OpenSearchInstance)
    - [Authentication and authorization for remote OpenSearch clusters](#OpenSearchAuth)

Malcolm's default standalone configuration is to use a local [OpenSearch](https://opensearch.org/) instance in a Docker container to index and search network traffic metadata. OpenSearch can also run as a [cluster](https://opensearch.org/docs/latest/opensearch/cluster/) with instances distributed across multiple nodes with dedicated [roles](https://opensearch.org/docs/latest/opensearch/cluster/#nodes) like cluster manager, data node, ingest node, etc.

As the permutations of OpenSearch cluster configurations are numerous, it is beyond Malcolm's scope to set up multi-node clusters. However, Malcolm can be configured to use a remote OpenSearch cluster rather than its own internal instance.

The `OPENSEARCH_…` [environment variables in `docker-compose.yml`](malcolm-config.md#DockerComposeYml) control whether Malcolm uses its own local OpenSearch instance or a remote OpenSearch instance as its primary data store. The configuration portion of Malcolm install script ([`./scripts/install.py --configure`](malcolm-config.md#ConfigAndTuning)) can help you configure these options.

For example, to use the default standalone configuration, answer `Y` when prompted `Should Malcolm use and maintain its own OpenSearch instance?`.

Or, to use a remote OpenSearch cluster:

```
…
Should Malcolm use and maintain its own OpenSearch instance? (Y/n): n

Enter primary remote OpenSearch connection URL (e.g., https://192.168.1.123:9200): https://192.168.1.123:9200

Require SSL certificate validation for communication with primary OpenSearch instance? (y/N): n

You must run auth_setup after install.py to store OpenSearch connection credentials.
…
```

Whether the primary OpenSearch instance is a locally maintained single-node instance or is a remote cluster, Malcolm can be configured additionally forward logs to a secondary remote OpenSearch instance. The `OPENSEARCH_SECONDARY_…` [environment variables in `docker-compose.yml`](malcolm-config.md#DockerComposeYml) control this behavior. Configuration of a remote secondary OpenSearch instance is similar to that of a remote primary OpenSearch instance:


```
…
Forward Logstash logs to a secondary remote OpenSearch instance? (y/N): y

Enter secondary remote OpenSearch connection URL (e.g., https://192.168.1.123:9200): https://192.168.1.124:9200

Require SSL certificate validation for communication with secondary OpenSearch instance? (y/N): n

You must run auth_setup after install.py to store OpenSearch connection credentials.
…
```

## <a name="OpenSearchAuth"></a>Authentication and authorization for remote OpenSearch clusters

In addition to setting the environment variables in [`docker-compose.yml`](malcolm-config.md#DockerComposeYml) as described above, you must provide Malcolm with credentials for it to be able to communicate with remote OpenSearch instances. These credentials are stored in the Malcolm installation directory as `.opensearch.primary.curlrc` and `.opensearch.secondary.curlrc` for the primary and secondary OpenSearch connections, respectively, and are bind mounted into the Docker containers which need to communicate with OpenSearch. These [cURL-formatted](https://everything.curl.dev/cmdline/configfile) config files can be generated for you by the [`auth_setup`](authsetup.md#AuthSetup) script as illustrated:

```
$ ./scripts/auth_setup 

…

Store username/password for primary remote OpenSearch instance? (y/N): y

OpenSearch username: servicedb 
servicedb password:
servicedb password (again):

Additional local accounts can be created at https://localhost:488/ when Malcolm is running

Require SSL certificate validation for OpenSearch communication? (Y/n): n

Will Malcolm be using an existing remote primary or secondary OpenSearch instance? (y/N): y

Store username/password for secondary remote OpenSearch instance? (y/N): y

OpenSearch username: remotedb
remotedb password:
remotedb password (again):

Require SSL certificate validation for OpenSearch communication? (Y/n): n

…
```

These files are created with permissions such that only the user account running Malcolm can access them:

```
$ ls -la .opensearch.*.curlrc
-rw------- 1 user user 36 Aug 22 14:17 .opensearch.primary.curlrc
-rw------- 1 user user 35 Aug 22 14:18 .opensearch.secondary.curlrc
```

One caveat with Malcolm using a remote OpenSearch cluster as its primary document store is that the accounts used to access Malcolm's [web interfaces](quickstart.md#UserInterfaceURLs), particularly [OpenSearch Dashboards](dashboards.md#Dashboards), are in some instance passed directly through to OpenSearch itself. For this reason, both Malcolm and the remote primary OpenSearch instance must have the same account information. The easiest way to accomplish this is to use an Active Directory/LDAP server that both [Malcolm](authsetup.md#AuthLDAP) and [OpenSearch](https://opensearch.org/docs/latest/security-plugin/configuration/ldap/) use as a common authentication backend.

See the OpenSearch documentation on [access control](https://opensearch.org/docs/latest/security-plugin/access-control/index/) for more information.