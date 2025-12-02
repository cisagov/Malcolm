# <a name="ConfigAndTuning"></a>Malcolm Configuration

Malcolm's runtime settings are stored (with a few exceptions) as environment variables in configuration files ending with a `.env` suffix in the `./config` directory. The `./scripts/configure` script can help users configure and tune these settings. For an in-depth treatment of the configuration script, see the **Configuration** section in [**End-to-end Malcolm and Hedgehog Linux ISO Installation**](malcolm-hedgehog-e2e-iso-install.md#MalcolmConfigItems).

## <a name="MalcolmConfigEnvVars"></a>Environment variable files

Although the configuration script automates many of the following configuration and tuning parameters, some environment variables of particular interest are listed here for reference.

* **`arkime.env`** and **`arkime-secret.env`** - settings for [Arkime](https://arkime.com/)
    - `ARKIME_AUTO_ANALYZE_PCAP_THREADS` – the number of threads available to Arkime for analyzing PCAP files (default `1`)
    - `ARKIME_PASSWORD_SECRET` - the password hash secret for the Arkime viewer cluster (see `passwordSecret` in [Arkime INI Settings](https://arkime.com/settings)) used to secure the connection used when Arkime viewer retrieves a PCAP payload for display in its user interface
    - `ARKIME_ROTATE_INDEX` - how often (based on network traffic timestamp) to [create a new index](https://arkime.com/settings#rotateIndex) in OpenSearch
    - `ARKIME_QUERY_ALL_INDICES` - whether or not Arkime should [query all indices](https://arkime.com/settings#queryAllIndices) instead of trying to calculate which ones pertain to the search time frame (default `false`)
    - `ARKIME_SPI_DATA_MAX_INDICES` - the maximum number of indices for querying SPI data, or set to `-1` to disable any max. The [Arkime documentation](https://arkime.com/settings#spiDataMaxIndices) warns "OpenSearch/Elasticsearch MAY blow up if we ... search too many indices." (default `7`)
    - `MANAGE_PCAP_FILES` and `ARKIME_FREESPACEG` - these variables deal with PCAP [deletion by Arkime](https://arkime.com/faq#pcap-deletion), see [**Managing disk usage**](#DiskUsage) below
    - `MAXMIND_GEOIP_DB_LICENSE_KEY` - Malcolm uses MaxMind's free GeoLite2 databases for GeoIP lookups. As of December 30, 2019, these databases are [no longer available](https://blog.maxmind.com/2019/12/18/significant-changes-to-accessing-and-using-geolite2-databases/) for download via a public URL. Instead, they must be downloaded using a MaxMind license key (available without charge [from MaxMind](https://www.maxmind.com/en/geolite2/signup)). The license key can be specified here for GeoIP database downloads during build- and run-time.
    - `MAXMIND_GEOIP_DB_ALTERNATE_DOWNLOAD_URL` - As an alternative to (or fallback for) `MAXMIND_GEOIP_DB_LICENSE_KEY`, a URL prefix may be specified in this variable (e.g., `https://example.org/foo/bar`) which will be used as a fallback. This URL should serve up `.tar.gz` files in the same format as those provided by the official source (see the example [here](contributing-github-runners.md#GitHubRunners)).
    - The following variables configure [Arkime's use](index-management.md#ArkimeIndexPolicies) of OpenSearch [Index State Management (ISM)](https://opensearch.org/docs/latest/im-plugin/ism/index/) or Elasticsearch [Index Lifecycle Management (ILM)](https://www.elastic.co/guide/en/elasticsearch/reference/current/index-lifecycle-management.html):
        + `INDEX_MANAGEMENT_ENABLED` - if set to `true`, Malcolm's instance of Arkime will [use these features](https://arkime.com/faq#ilm) when indexing data; note that this only takes effect when initializing Malcolm from an [empty state](running.md#Wipe)
        + `INDEX_MANAGEMENT_OPTIMIZATION_PERIOD` - the period in hours or days that Arkime will keep records in the **hot** state (default `30d`)
        + `INDEX_MANAGEMENT_RETENTION_TIME` - the period in hours or days that Arkime will keep records before deleting them (default `90d`)
        + `INDEX_MANAGEMENT_OLDER_SESSION_REPLICAS` - the number of replicas for older sessions indices (default `0`)
        + `INDEX_MANAGEMENT_HISTORY_RETENTION_WEEKS` - the retention time period (weeks) for Arkime history data (default `13`)
        + `INDEX_MANAGEMENT_SEGMENTS` - the number of segments Arlime will use to optimize sessions (default `1`)
        + `INDEX_MANAGEMENT_HOT_WARM_ENABLED` - whether or not Arkime should use a hot/warm design (storing non-session data in a warm index); setting up hot/warm index policies also requires configuration on the local nodes in accordance with the [Arkime documentation](https://arkime.com/faq#ilm)
    - The following variables configure exposing [Arkime's WISE Plugin](https://arkime.com/wise). By default, Malcolm leverages the WISE plugin internally but does not expose the functionality to the end user:
        + `ARKIME_EXPOSE_WISE_GUI` - if set to `true` the WISE interface will be available at: `https://<MALCOLM-IP>/wise`. This defaults to `true`.
        + `ARKIME_ALLOW_WISE_GUI_CONFIG` - if set to `true` the WISE interface can be used to configure the WISE service. This only applies if `ARKIME_EXPOSE_WISE_GUI` is set to `true`. The default value is `true`.
        + `ARKIME_WISE_CONFIG_PIN_CODE` - the WISE service requires a configuration pin. This value will be required to save any WISE configuration changes.  The default value is `WISE2019`.
        + `ARKIME_WISE_SERVICE_URL` - to leverage WISE, arkime-capture needs to be provided a `wiseURL` value. The value of this environment variable is copied into the `wiseURL` value in arkime-live containers.
        + `WISE` - indicates if the WISE service is `on` or `off`. This environment variable defaults to `off`.
* **`arkime-live.env`** - settings for live traffic capture with Arkime
    - See [**Tuning Arkime**](live-analysis.md#LiveAnalysisTuningArkime) for variables related to managing Arkime's performance and resource utilization during live capture.
* **`auth-common.env`** - [authentication](authsetup.md)-related settings
    - `NGINX_AUTH_MODE` - valid values are `basic` (or `true` for legacy compatibility), use [TLS-encrypted HTTP basic](authsetup.md#AuthBasicAccountManagement) authentication (default); `ldap` (or `false` for legacy compatibility), use [Lightweight Directory Access Protocol (LDAP)](authsetup.md#AuthLDAP) authentication; `keycloak` to use [authentication managed by Malcolm's embedded Keycloak](authsetup.md#AuthKeycloakEmbedded) instance;  `keycloak_remote` to use [authentication managed by a remote Keycloak](authsetup.md#AuthKeycloakRemote) instance; `no_authentication` to disable authentication
    - `NGINX_REQUIRE_GROUP` and `NGINX_REQUIRE_ROLE` - When using [Keycloak authentication](authsetup.md#AuthKeycloak), setting these values will require authenticated users to [belong to groups and assigned roles](authsetup.md#AuthKeycloakReqGroupsRoles), respectively. Multiple values may be specified with a comma-separated list. Note that these requirements are cumulative: users must match all of the items specified. An empty value (default) means no group/role restriction is applied. [LDAP authentication](authsetup.md#AuthLDAP) can also require group membership, but that is specified in `nginx_ldap.conf` by setting `require group` rather than in `auth-common.env`.
    - `ROLE…` - variables used to manage [role-based access control](authsetup.md#AuthKeycloakRBAC)
* **`auth.env`** - stores the Malcolm administrator's username and password hash for its nginx reverse proxy
* **`beats-common.env`** - settings for interactions between [Logstash](https://www.elastic.co/products/logstash) and [Filebeat](https://www.elastic.co/products/beats/filebeat)
    - `BEATS_SSL` – if set to `true`, Logstash will use require encrypted communications for any external [Beats](https://www.elastic.co/guide/en/logstash/current/plugins-inputs-beats.html)-based forwarders from which it will accept logs (default `true`)
    - `LOGSTASH_HOST` – the host and port at which Beats-based forwarders will connect to Logstash (default `logstash:5044`); see `MALCOLM_PROFILE` below
* **`dashboards.env`** and **`dashboards-helper.env`** - settings for the containers that configure and maintain [OpenSearch](https://opensearch.org/) and [OpenSearch Dashboards](https://opensearch.org/docs/latest/dashboards/index/)
    - `DASHBOARDS_URL` - used primarily when `OPENSEARCH_PRIMARY` is set to `elasticsearch-remote` (see [OpenSearch and Elasticsearch instances](opensearch-instances.md#OpenSearchInstance)), this variable stores the URL for the [Kibana](https://www.elastic.co/kibana) instance into which Malcolm's dashboard's and index templates will be imported
    - `DASHBOARDS_PREFIX` – a string to prepend to the titles of Malcolm's prebuilt [dashboards](dashboards.md#PrebuiltVisualizations) prior upon import during Malcolm's initialization (default is an empty string)
    - `DASHBOARDS_DARKMODE` – if set to `true`, [OpenSearch Dashboards](dashboards.md#DashboardsVisualizations) will be set to dark mode upon initialization (default `true`)
    - `DASHBOARDS_TIMEPICKER_FROM` and `DASHBOARDS_TIMEPICKER_TO` – sets the "from" and "to" values, respectively, for OpenSearch Dashboard's `timepicker:timeDefaults` [setting](https://docs.opensearch.org/latest/dashboards/management/advanced-settings/#general-settings) (default `now-24h` and `now`, meaning "last 24 hours")
    -  – if set to `true`, [OpenSearch Dashboards](dashboards.md#DashboardsVisualizations) will be set to dark mode upon initialization (default `true`)
    - `OPENSEARCH_INDEX_SIZE_PRUNE_LIMIT` - the maximum cumulative size of OpenSearch indices are allowed to consume before the oldest indices are deleted, see [**Managing disk usage**](#DiskUsage) below
* **`filebeat.env`** - settings specific to [Filebeat](https://www.elastic.co/products/beats/filebeat), particularly for how Filebeat watches for new log files to parse and how it receives and stores [third-Party logs](third-party-logs.md)
    - `LOG_CLEANUP_MINUTES` and `ZIP_CLEANUP_MINUTES` - these variables deal cleaning up already-processed log files, see [**Managing disk usage**](#DiskUsage) below
    - The following variables configure Malcolm's ability to [accept syslog](https://www.elastic.co/guide/en/beats/filebeat/current/syslog.html) messages:
        + `FILEBEAT_SYSLOG_TCP_LISTEN` and `FILEBEAT_SYSLOG_UDP_LISTEN` - if set to `true`, Malcolm will accept syslog messages over TCP and/or UDP, respectively
        + `FILEBEAT_SYSLOG_TCP_PORT` and `FILEBEAT_SYSLOG_UDP_PORT` - the port on which Malcolm will accept syslog messages over TCP and/or UDP, respectively
            * If Malcolm is running in an instance installed via the [Malcolm installer ISO](malcolm-iso.md#ISO), please see also [ISO-installed Desktop Environment Firewall](third-party-logs.md#SyslogISOFirewall).
        + `FILEBEAT_SYSLOG_TCP_FORMAT` and `FILEBEAT_SYSLOG_UDP_FORMAT` - one of `auto`, `rfc3164`, or `rfc5424`, to specify the allowed format for syslog messages over TCP and/or UDP, respectively (default `auto`)
        + `FILEBEAT_SYSLOG_TCP_MAX_MESSAGE_SIZE` and `FILEBEAT_SYSLOG_UDP_MAX_MESSAGE_SIZE` - defines the maximum message size of the message received over TCP and/or UDP, respectively (default: `10KiB` for UDP, `20MiB` for TCP)
        + `FILEBEAT_SYSLOG_TCP_MAX_CONNECTIONS` - specifies the maximum current number of TCP connections for syslog messages
        + `FILEBEAT_SYSLOG_TCP_SSL` - if set to `true`, syslog messages over TCP will require the use of TLS. When [`./scripts/auth_setup`](authsetup.md#AuthSetup) is run, self-signed certificates are generated which may be used by remote log forwarders. Located in the `filebeat/certs/` directory, the certificate authority and client certificate and key files should be copied to the host on which the forwarder is running and used when defining its settings for connecting to Malcolm.
* **`keycloak.env`** - settings specific to [Keycloak](https://www.keycloak.org/)
    - The following variables are used for all [Keycloak](authsetup.md#AuthKeycloak) configurations, be it Malcolm's [embedded instance](authsetup.md#AuthKeycloakEmbedded) or a [remote instance](authsetup.md#AuthKeycloakRemote) (see `NGINX_AUTH_MODE` above):
        + `KEYCLOAK_AUTH_REALM` - specifies the name of the Keycloak [realm](https://www.keycloak.org/docs/latest/server_admin/index.html#_configuring-realms) (default [`master`](https://www.keycloak.org/docs/latest/server_admin/index.html#the-master-realm))
        + `KEYCLOAK_AUTH_REDIRECT_URI` - specifies the relative path which is the Malcolm URI to which Keycloak will redirect users after a successful authentication (default `/index.html`, which will redirect users to the Malcolm landing page)
        + `KEYCLOAK_AUTH_URL` - specifies the Keycloak endpoint URL, or the URL to which Malcolm should direct authentication requests for Keycloak. If a [remote Keycloak](authsetup.md#AuthKeycloakRemote) instance is being used, this would be the URL for that instance (e.g., **https://keycloak.example.com** ). If Malcolm is using its embedded [Keycloak instance](authsetup.md#AuthKeycloakEmbedded), this host portion of the URL should be the hostname or IP address at which Malcolm is available, followed by **/keycloak** (or whatever the value of `KC_HTTP_RELATIVE_PATH` has been set to; see below) (e.g., **https://malcolm.internal.lan/keycloak** or **https://192.168.100.10/keycloak** ).
        + `KEYCLOAK_CLIENT_ID` and `KEYCLOAK_CLIENT_SECRET` - identify the Keycloak client Malcolm will use and the secret associated with that client
    - The following variables are only used for Malcolm's embedded [Keycloak instance](authsetup.md#AuthKeycloakEmbedded) (see [**All configuration**](https://www.keycloak.org/server/all-config) in the Keycloak guide for more details on these values):
        + [`KC_CACHE`](https://www.keycloak.org/server/all-config#category-cache) - defines the cache mechanism for high-availability (default `local` as Malcolm's embedded Keycloak instance is single-node)
        + [`KC_HEALTH_ENABLED`](https://www.keycloak.org/server/all-config#category-health) - if set to `true`, enables the health check endpoint used internally by the container health script
        + [`KC_HOSTNAME`](https://www.keycloak.org/server/all-config#category-hostname_v2) - address at which the Keycloak server is exposed (defaults to blank, as `KC_HOSTNAME_STRICT` below defaults to `false`)
        + [`KC_HOSTNAME_STRICT`](https://www.keycloak.org/server/all-config#category-hostname_v2) - if set to `true`, disables dynamically resolving the hostname from request headers
        + [`KC_HTTP_ENABLED`](https://www.keycloak.org/server/all-config#category-http) - enables the HTTP listener (default `true` as Malcolm is [proxying](https://www.keycloak.org/server/reverseproxy) the embedded Keycloak instance behind nginx)
        + [`KC_HTTP_RELATIVE_PATH`](https://www.keycloak.org/server/all-config#category-http) - specifies the Malcolm path under which Keycloak serves resources (should not be changed from its default value of `/keycloak`)
        + [`KC_METRICS_ENABLED`](https://www.keycloak.org/server/all-config#category-metrics) - specifies if the server should expose metrics (default `false`)
        + [`KC_PROXY_HEADERS`](https://www.keycloak.org/server/all-config#category-proxy) - the proxy headers that should be accepted by Keycloak (should not be changed from its default value of `xforwarded`)
        + `KC_BOOTSTRAP_ADMIN_USERNAME` and `KC_BOOTSTRAP_ADMIN_PASSWORD` - values for boostrapping the temporary Keycloak admin service account (see [Keycloak configuration](authsetup.md#AuthKeycloakEmbedded))
* **`logstash.env`** - settings specific to [Logstash](https://www.elastic.co/products/logstash)
    - `LOGSTASH_OUI_LOOKUP` – if set to `true`, Logstash will map MAC addresses to vendors for all source and destination MAC addresses when analyzing Zeek logs (default `true`)
    - `LOGSTASH_REVERSE_DNS` – if set to `true`, Logstash will perform a reverse DNS lookup for all external source and destination IP address values when analyzing Zeek logs (default `false`)
    - `LOGSTASH_SEVERITY_SCORING` - if set to `true`, Logstash will perform [severity scoring](severity.md#Severity) when analyzing Zeek logs (default `true`)
    - `LS_JAVA_OPTS` - part of LogStash's [JVM settings](https://www.elastic.co/guide/en/logstash/current/jvm-settings.html), the `-Xmx` and `-Xms` values set the size of LogStash's Java heap (we recommend somewhere between `1500m` and `4g`)
    * `pipeline.workers`, `pipeline.batch.size` and `pipeline.batch.delay` - these settings are used to tune the performance and resource utilization of the the `logstash` container; see [Tuning and Profiling Logstash Performance](https://www.elastic.co/guide/en/logstash/current/tuning-logstash.html), [`logstash.yml`](https://www.elastic.co/guide/en/logstash/current/logstash-settings-file.html) and [Multiple Pipelines](https://www.elastic.co/guide/en/logstash/current/multiple-pipelines.html)
* **`lookup-common.env`** - settings for enrichment lookups, including those used for [customizing event severity scoring](severity.md#SeverityConfig)
    - `FREQ_LOOKUP` - if set to `true`, domain names (from DNS queries and SSL server names) will be assigned entropy scores as calculated by [`freq`](https://github.com/MarkBaggett/freq) (default `false`)
    - `FREQ_SEVERITY_THRESHOLD` - when [severity scoring](severity.md#Severity) is enabled, this variable indicates the entropy threshold for assigning severity to events with entropy scores calculated by [`freq`](https://github.com/MarkBaggett/freq); a lower value will only assign severity scores to fewer domain names with higher entropy (e.g., `2.0` for `NQZHTFHRMYMTVBQJE.COM`), while a higher value will assign severity scores to more domain names with lower entropy (e.g., `7.5` for `naturallanguagedomain.example.org`) (default `2.0`)
    - `SENSITIVE_COUNTRY_CODES` - when [severity scoring](severity.md#Severity) is enabled, this variable defines a comma-separated list of sensitive countries (using [ISO 3166-1 alpha-2 codes](https://en.wikipedia.org/wiki/ISO_3166-1_alpha-2#Current_codes)) (default `'AM,AZ,BY,CN,CU,DZ,GE,HK,IL,IN,IQ,IR,KG,KP,KZ,LY,MD,MO,PK,RU,SD,SS,SY,TJ,TM,TW,UA,UZ'`, taken from the U.S. Department of Energy Sensitive Country List)
    - `TOTAL_MEGABYTES_SEVERITY_THRESHOLD` - when [severity scoring](severity.md#Severity) is enabled, this variable indicates the size threshold (in megabytes) for assigning severity to large connections or file transfers (default `1000`)
* **`netbox-common.env`**, `netbox.env` and `netbox-secret.env` - settings related to [NetBox](https://netbox.dev/) and [Asset Interaction Analysis](asset-interaction-analysis.md#AssetInteractionAnalysis)
    - `NETBOX_MODE` - determine whether Malcolm will start and manage a [NetBox](asset-interaction-analysis.md#AssetInteractionAnalysis) instance; valid values are `local` (use an embedded instance NetBox), `remote` (use a remote instance of NetBox), or `disabled` (the default)
    - `NETBOX_ENRICHMENT` - if set to `true`, Logstash will [enrich network traffic metadata](asset-interaction-analysis.md#NetBoxEnrichment) via NetBox API calls
    - `NETBOX_DEFAULT_SITE` - specifies the default NetBox [site name](https://demo.netbox.dev/static/docs/core-functionality/sites-and-racks/) for use when [enriching network traffic metadata via NetBox lookups](asset-interaction-analysis.md#NetBoxEnrichment) if a specific site is not otherwise specified for the source of the data (default `Malcolm`)
    - `NETBOX_AUTO_POPULATE` - if set to `true`, Logstash will [populate the NetBox inventory](asset-interaction-analysis.md#NetBoxPopPassive) based on observed network traffic
    - `NETBOX_AUTO_POPULATE_SUBNETS` - a comma-separated list of private CIDR subnets to control NetBox IP autopopulation (see [**Subnets considered for autopopulation**](asset-interaction-analysis.md#NetBoxAutoPopSubnets); default is an empty string, meaning all private IPv4 and IPv6 ranges are autopopulated)
    - `NETBOX_AUTO_CREATE_PREFIX` - if set to `true`, Logstash will automatically create private subnet prefixes in the [NetBox inventory](asset-interaction-analysis.md#NetBoxPopPassive) based on observed network traffic
    - `NETBOX_DEFAULT_AUTOCREATE_MANUFACTURER` - if set to `true`, new manufacturer entries will be created in the NetBox database when [matching device manufacturers to OUIs](asset-interaction-analysis.md#NetBoxPopPassiveOUIMatch) (default `true`)
    - `NETBOX_DEFAULT_FUZZY_THRESHOLD` - fuzzy-matching threshold for [matching device manufacturers to OUIs](asset-interaction-analysis.md#NetBoxPopPassiveOUIMatch) (default `0.95`)
    - The following variables should only be set if `NETBOX_MODE` is set to `remote`, otherwise they should be blank:
        + `NETBOX_URL` - the URL of the remote NetBox instance (e.g., `https://netbox.example.org` or `https://example.com/netbox`)
        + `NETBOX_TOKEN` - the [API token](https://netboxlabs.com/docs/netbox/en/stable/integrations/rest-api/#tokens) for the remote NetBox instance (40 hexadecimal characters)
* **`nginx.env`** - settings specific to Malcolm's nginx reverse proxy
    - `NGINX_LOG_ACCESS_AND_ERRORS` - if set to `true`, all access to Malcolm via its [web interfaces](quickstart.md#UserInterfaceURLs) will be logged to OpenSearch (default `false`)
    - `NGINX_SSL` - if set to `true`, require HTTPS connections to Malcolm's `nginx-proxy` container (default); if set to `false`, use unencrypted HTTP connections (using unsecured HTTP connections is **NOT** recommended unless you are running Malcolm behind another reverse proxy such as Traefik, Caddy, etc.) Also note: in some circumstances disabling SSL in NGINX while leaving SSL enabled in Arkime can result in a "Missing token" Arkime error. This is due to Arkime's Cross-Site Request Forgery mitigation cookie being passed to the browser with the "secure" flag enabled.
    - `NGINX_X_FORWARDED_PROTO_OVERRIDE`
    - The following variables control nginx's [resolver directive](https://nginx.org/en/docs/http/ngx_http_core_module.html#resolver). Note that these settings do not affect Malcolm's ability to capture or inspect IPv4/IPv6 traffic: they are only used if and when nginx itself needs to resolve hostnames in the network in which Malcolm resides.
        + `NGINX_RESOLVER_OVERRIDE` - if set, overrides automatic detection of the resolver address used (default is unset)
        + `NGINX_RESOLVER_IPV4` - if `false`, sets the `ipv4=off` parameter in the resolver directive (default is `true`)
        + `NGINX_RESOLVER_IPV6` - if `false`, sets the `ipv6=off` parameter in the resolver directive; it is recommended to set this to `false` if your network does not support IPv6 (default is `true`)
* **`opensearch.env`** - settings specific to [OpenSearch](https://opensearch.org/)
    - `OPENSEARCH_JAVA_OPTS` - one of OpenSearch's most [important settings](https://opensearch.org/docs/latest/install-and-configure/install-opensearch/index/#important-settings), the `-Xmx` and `-Xms` values set the size of OpenSearch's Java heap (we recommend setting this value to half of system RAM, up to 32 gigabytes)
    - `OPENSEARCH_PRIMARY` - one of `opensearch-local`, `opensearch-remote`, or `elasticsearch-remote`, to determine the [OpenSearch or Elasticsearch instance](opensearch-instances.md#OpenSearchInstance) Malcolm will use  (default `opensearch-local`)
    - `OPENSEARCH_URL` - when using Malcolm's internal OpenSearch instance (i.e., `OPENSEARCH_PRIMARY` is `opensearch-local`) this should be `https://opensearch:9200`, otherwise this value specifies the primary remote instance URL in the format `protocol://host:port` (default `https://opensearch:9200`)
    - `OPENSEARCH_SSL_CERTIFICATE_VERIFICATION` - if set to `true`, connections to the primary remote OpenSearch instance will require full TLS certificate validation (this may fail if using self-signed certificates) (default `false`)
    - `OPENSEARCH_SECONDARY` - one of `opensearch-local`, `opensearch-remote`, `elasticsearch-remote`, or blank (unset) to indicate that Malcolm should forward logs to a secondary remote OpenSearch instance in addition to the primary OpenSearch instance (default is unset)
    - `OPENSEARCH_SECONDARY_URL` - when forwarding to a secondary remote OpenSearch instance (i.e., `OPENSEARCH_SECONDARY` is set) this value specifies the secondary remote instance URL in the format `protocol://host:port`
    - `OPENSEARCH_SECONDARY_SSL_CERTIFICATE_VERIFICATION` - if set to `true`, connections to the secondary remote OpenSearch instance will require full TLS certificate validation (this may fail if using self-signed certificates) (default `false`)
    - The following variables control the OpenSearch indices to which network traffic metadata are written. Changing them from their defaults may cause logs from non-Arkime data sources (i.e., Zeek, Suricata) to not show up correctly in Arkime.
        + `MALCOLM_NETWORK_INDEX_PATTERN` - Index pattern for network traffic logs written via Logstash (default is `arkime_sessions3-*`)
        + `MALCOLM_NETWORK_INDEX_TIME_FIELD` - Default time field to use for network traffic logs in Logstash and Dashboards (default is `firstPacket`)
        + `MALCOLM_NETWORK_INDEX_SUFFIX` - Suffix used to create index to which network traffic logs are written
            * supports [Ruby `strftime`](https://docs.ruby-lang.org/en/3.2/strftime_formatting_rdoc.html) strings in `％{}`) (e.g., hourly: `％{％y％m％dh％H}`, twice daily: `％{％P％y％m％d}`, daily (default): `％{％y％m％d}`, weekly: `％{％yw％U}`, monthly: `％{％ym％m}`
            * supports expanding dot-delimited field names in `｛｛ ｝｝` (e.g., `｛｛event.provider｝｝％{％y％m％d}`)
    - The following variables control the OpenSearch indices to which other logs ([third-party logs](third-party-logs.md), resource utilization reports from network sensors, etc.) are written.
        + `MALCOLM_OTHER_INDEX_PATTERN` - Index pattern for other logs written via Logstash (default is `malcolm_beats_*`)
        + `MALCOLM_OTHER_INDEX_TIME_FIELD` - Default time field to use for other logs in Logstash and Dashboards (default is `@timestamp`)
        + `MALCOLM_OTHER_INDEX_SUFFIX` - Suffix used to create index to which other logs are written (with the same rules as `MALCOLM_NETWORK_INDEX_SUFFIX` above) (default is `％{％y％m％d}`)
* **`pcap-capture.env`** - settings specific to capturing traffic for [live traffic analysis](live-analysis.md#LocalPCAP)
    - `PCAP_ENABLE_NETSNIFF` – if set to `true`, Malcolm will capture network traffic on the local network interface(s) indicated in `PCAP_IFACE` using [netsniff-ng](http://netsniff-ng.org/)
    - `PCAP_ENABLE_TCPDUMP` – if set to `true`, Malcolm will capture network traffic on the local network interface(s) indicated in `PCAP_IFACE` using [tcpdump](https://www.tcpdump.org/); there is no reason to enable *both* `PCAP_ENABLE_NETSNIFF` and `PCAP_ENABLE_TCPDUMP`
    - `PCAP_FILTER` – specifies a tcpdump-style filter expression for local packet capture; leave blank to capture all traffic
    - `PCAP_IFACE` – used to specify the network interface(s) for local packet capture if `PCAP_ENABLE_NETSNIFF`, `PCAP_ENABLE_TCPDUMP`, `ZEEK_LIVE_CAPTURE` or `SURICATA_LIVE_CAPTURE` are enabled; for multiple interfaces, separate the interface names with a comma (e.g., `'enp0s25'` or `'enp10s0,enp11s0'`)
    - `PCAP_IFACE_TWEAK` - if set to `true`, Malcolm will [use `ethtool`]({{ site.github.repository_url }}/blob/{{ site.github.build_revision }}/shared/bin/nic-capture-setup.sh) to disable NIC hardware offloading features and adjust ring buffer sizes for capture interface(s); this should be `true` if the interface(s) are being used for capture only, `false` if they are being used for management/communication
    - `PCAP_ROTATE_MEGABYTES` – used to specify how large a locally captured PCAP file can become (in megabytes) before it is closed for processing and a new PCAP file created
    - `PCAP_ROTATE_MINUTES` – used to specify a time interval (in minutes) after which a locally-captured PCAP file will be closed for processing and a new PCAP file created
    - `PCAP_IFACE_STATS_CRON_EXPRESSION` - Specifies a [cron expression](https://en.wikipedia.org/wiki/Cron#CRON_expression) (using [`cronexpr`](https://github.com/aptible/supercronic/tree/master/cronexpr#implementation)-compatible syntax) indicating the refresh interval for collecting kernel-level statistics for network interfaces. An empty value for this variable means these statistics will not be generated.
* **`postgres.env`** - Settings related to the PostgreSQL relational database
* **`process.env`** - settings for how the processes running inside Malcolm containers are executed
    - `PUID` and `PGID` - Docker runs all its containers as the privileged `root` user by default. For better security, Malcolm immediately drops to non-privileged user accounts for executing internal processes wherever possible. The `PUID` (**p**rocess **u**ser **ID**) and `PGID` (**p**rocess **g**roup **ID**) environment variables allow Malcolm to map internal non-privileged user accounts to a corresponding [user account](https://en.wikipedia.org/wiki/User_identifier) on the host. Note a few (including the `logstash` and `netbox` containers) may take a few extra minutes during startup if `PUID` and `PGID` are set to values other than the default `1000`. This is expected and should not affect operation after the initial startup.
    - `MALCOLM_PROFILE` - Specifies the [profile](https://docs.docker.com/compose/profiles/) which determines the Malcolm containers to run (`malcolm` to run all containers, `hedgehog` to run only [capture-related containers](https://github.com/idaholab/Malcolm/issues/254))
* **`redis.env`** - Settings related to the Redis in-memory database
* **`ssl.env`** - TLS-related settings used by many containers
* **`suricata.env`**, **`suricata-live.env`** and **`suricata-offline.env`** - settings for [Suricata](https://suricata.io/)
    - `SURICATA_AUTO_ANALYZE_PCAP_FILES` – if set to `true`, all PCAP files imported into Malcolm will automatically be analyzed by Suricata, and the resulting logs will also be imported (default `false`)
    - `SURICATA_AUTO_ANALYZE_PCAP_PROCESSES` – the number of processes available to Malcolm for processing PCAP files with Suricata (default `1`)
    - `SURICATA_AUTO_ANALYZE_PCAP_THREADS` – the number of threads to use per Suricata process (default `0`, meaning Suricata will use its default behavior)
    - `SURICATA_CUSTOM_RULES_ONLY` – if set to `true`, Malcolm will bypass the default [Suricata ruleset](https://github.com/OISF/suricata/tree/master/rules) and use only [user-defined rules](custom-rules.md#Suricata) (`./suricata/rules/*.rules`).
    - `SURICATA_UPDATE_RULES` – if set to `true`, Suricata signatures will periodically be updated (default `false`)
    - `SURICATA_LIVE_CAPTURE` - if set to `true`, Suricata will monitor live traffic on the local interface(s) defined by `PCAP_FILTER`
    - `SURICATA_ROTATED_PCAP` - if set to `true`, Suricata can analyze PCAP files captured by `netsniff-ng` or `tcpdump` (see `PCAP_ENABLE_NETSNIFF` and `PCAP_ENABLE_TCPDUMP`, as well as `SURICATA_AUTO_ANALYZE_PCAP_FILES`); if `SURICATA_LIVE_CAPTURE` is `true`, this should be `false`; otherwise Suricata will see duplicate traffic
    - `SURICATA_DISABLE_ICS_ALL` - if set to `true`, this variable can be used to disable Malcolm's [built-in Suricata rules for Operational Technology/Industrial Control Systems (OT/ICS) vulnerabilities and exploits]({{ site.github.repository_url }}/blob/{{ site.github.build_revision }}/suricata/rules-default/OT)
    - `SURICATA_STATS_ENABLED`, `SURICATA_STATS_EVE_ENABLED`, and `SURICATA_STATS_INTERVAL` - these variables control the generation of [live traffic capture](live-analysis.md#LocalPCAP) statistics for [Suricata](https://docs.suricata.io/en/latest/configuration/suricata-yaml.html#stats), which data is used to populate the **Packet Capture Statistics** dashboard
    - See [**Tuning Suricata**](live-analysis.md#LiveAnalysisTuningSuricata) for other variables related to managing Suricata's performance and resource utilization.    
* **`upload-common.env`** - settings for dealing with PCAP files [uploaded](upload.md#Upload) to Malcolm for analysis
    - `AUTO_TAG` – if set to `true`, Malcolm will automatically create Arkime sessions and Zeek logs with tags based on the filename, as described in [Tagging](upload.md#Tagging) (default `true`)
    - `EXTRA_TAGS` – a comma-separated list of default tags for data generated by Malcolm (default is an empty string)
    - `PCAP_NODE_NAME` - specifies the node name to associate with network traffic metadata
    - `PCAP_UPLOAD_MAX_FILE_GB` - specifies the maximum uploadable file size in whole gigabytes (default `50`)
* **`zeek.env`**, **`zeek-secret.env`**, **`zeek-live.env`** and **`zeek-offline.env`** - settings for [Zeek](https://www.zeek.org/index.html) and for scanning [extracted files](file-scanning.md#ZeekFileExtraction) Zeek observes in network traffic
    - `EXTRACTED_FILE_CAPA_VERBOSE` – if set to `true`, all Capa rule hits will be logged; otherwise (`false`) only [MITRE ATT&CK® technique](https://attack.mitre.org/techniques) classifications will be logged
    - `EXTRACTED_FILE_ENABLE_CAPA` – if set to `true`, [Zeek-extracted files](file-scanning.md#ZeekFileExtraction) determined to be PE (portable executable) files will be scanned with [Capa](https://github.com/fireeye/capa)
    - `EXTRACTED_FILE_ENABLE_CLAMAV` – if set to `true`, [Zeek-extracted files](file-scanning.md#ZeekFileExtraction) will be scanned with [ClamAV](https://www.clamav.net/)
    - `EXTRACTED_FILE_ENABLE_YARA` – if set to `true`, [Zeek-extracted files](file-scanning.md#ZeekFileExtraction) will be scanned with [Yara](https://github.com/VirusTotal/yara)
    - `EXTRACTED_FILE_HTTP_SERVER_ENABLE` – if set to `true`, the directory containing [Zeek-extracted files](file-scanning.md#ZeekFileExtraction) will be served over HTTP at `./extracted-files/` (e.g., **https://localhost/extracted-files/** if connecting locally)
    - `EXTRACTED_FILE_HTTP_SERVER_ZIP` – if to `true`, the Zeek-extracted files will be archived in a ZIP file upon download
    - `EXTRACTED_FILE_HTTP_SERVER_KEY` – specifies the password for the ZIP archive if `EXTRACTED_FILE_HTTP_SERVER_ZIP` is `true`; otherwise, this specifies the decryption password for encrypted Zeek-extracted files in an `openssl enc`-compatible format (e.g., `openssl enc -aes-256-cbc -d -in example.exe.encrypted -out example.exe`)
    - `EXTRACTED_FILE_IGNORE_EXISTING` – if set to `true`, files extant in `./zeek-logs/extract_files/`  directory will be ignored on startup rather than scanned
    - `EXTRACTED_FILE_PRESERVATION` – determines behavior for preservation of [Zeek-extracted files](file-scanning.md#ZeekFileExtraction)
    - `EXTRACTED_FILE_UPDATE_RULES` – if set to `true`, file scanner engines (e.g., ClamAV, Capa, Yara) will periodically update their rule definitions (default `false`)
    - `EXTRACTED_FILE_YARA_CUSTOM_ONLY` – if set to `true`, Malcolm will bypass the default Yara rulesets ([Neo23x0/signature-base](https://github.com/Neo23x0/signature-base), [reversinglabs/reversinglabs-yara-rules](https://github.com/reversinglabs/reversinglabs-yara-rules), and [bartblaze/Yara-rules](https://github.com/bartblaze/Yara-rules)) and use only [user-defined rules](custom-rules.md#YARA) in `./yara/rules`
    - `VTOT_API2_KEY` – used to specify a [VirusTotal Public API v.20](https://www.virustotal.com/en/documentation/public-api/) key, which, if specified, will be used to submit hashes of [Zeek-extracted files](file-scanning.md#ZeekFileExtraction) to VirusTotal
    - `ZEEK_AUTO_ANALYZE_PCAP_FILES` – if set to `true`, all PCAP files imported into Malcolm will automatically be analyzed by Zeek, and the resulting logs will also be imported (default `false`)
    - `ZEEK_AUTO_ANALYZE_PCAP_THREADS` – the number of threads available to Malcolm for analyzing Zeek logs (default `1`)
    - `ZEEK_JSON` - whether Zeek should generate [JSON format logs](https://docs.zeek.org/en/master/log-formats.html#zeek-json-format-logs) (`true`) or [TSV format logs](https://docs.zeek.org/en/master/log-formats.html#zeek-tsv-format-logs) (`false`)
    - `ZEEK_DISABLE_…` - if set to `true`, each of these variables can be used to disable a certain Zeek function when it analyzes PCAP files (for example, setting `ZEEK_DISABLE_LOG_PASSWORDS` to `true` to disable logging of cleartext passwords)
    - `ZEEK_…_PORTS` - used to specify non-default ports to register certain Zeek analyzers (e.g., `ZEEK_SYNCHROPHASOR_PORTS` for the [ICSNPP-Synchrophasor analyzer](https://github.com/cisagov/icsnpp-synchrophasor/), `ZEEK_GENISYS_PORTS` for the [ICSNPP-Genisys analyzer](https://github.com/cisagov/icsnpp-genisys/), and `ZEEK_ENIP_PORTS` for the [ICSNPP-Ethernet/IP analyzer](https://github.com/cisagov/icsnpp-enip/)) formatted as a comma-separated list of [Zeek ports](https://docs.zeek.org/en/master/scripting/basics.html#port) (e.g., `12345/tcp` or `4041/tcp,4042/udp`)
    - `ZEEK_DISABLE_ICS_ALL` and `ZEEK_DISABLE_ICS_…` - if set to `true`, these variables can be used to disable Zeek's protocol analyzers for Operational Technology/Industrial Control Systems (OT/ICS) protocols
    - `ZEEK_DISABLE_BEST_GUESS_ICS` - see ["Best Guess" Fingerprinting for ICS Protocols](ics-best-guess.md#ICSBestGuess)
    - `ZEEK_EXTRACTOR_MODE` – determines the file extraction behavior for file transfers detected by Zeek; see [Automatic file extraction and scanning](file-scanning.md#ZeekFileExtraction) for more details
    - `ZEEK_INTEL_FEED_SINCE` - when querying a [TAXII](zeek-intel.md#ZeekIntelSTIX), [MISP](zeek-intel.md#ZeekIntelMISP), [Google](zeek-intel.md#ZeekIntelGoogle), or [Mandiant](zeek-intel.md#ZeekIntelMandiant) threat intelligence feed, only process threat indicators created or modified since the time represented by this value; it may be either a fixed date/time (`01/01/2025`) or relative interval (`24 hours ago`). Note that this value can be overridden per-feed by adding a `since:` value to each feed's respective configuration YAML file.
    - `ZEEK_INTEL_ITEM_EXPIRATION` - specifies the value for Zeek's [`Intel::item_expiration`](https://docs.zeek.org/en/current/scripts/base/frameworks/intel/main.zeek.html#id-Intel::item_expiration) timeout as used by the [Zeek Intelligence Framework](zeek-intel.md#ZeekIntel) (default `-1min`, which disables item expiration)
    - `ZEEK_INTEL_REFRESH_CRON_EXPRESSION` - Specifies a [cron expression](https://en.wikipedia.org/wiki/Cron#CRON_expression) (using [`cronexpr`](https://github.com/aptible/supercronic/tree/master/cronexpr#implementation)-compatible syntax) indicating the refresh interval for generating the [Zeek Intelligence Framework](zeek-intel.md#ZeekIntel) files (defaults to empty, which disables automatic refresh)
    - `ZEEK_JA4SSH_PACKET_COUNT` - the Zeek [JA4+ plugin](https://github.com/FoxIO-LLC/ja4) calculates the JA4SSH value once for every *x* SSH packets; *x* is set here (default `200`)
    - The following variables configure Malcolm's use of the [zeek-long-connections](https://github.com/corelight/zeek-long-connections) plugin:
        + `ZEEK_LONG_CONN_DURATIONS` - a comma-separated list of durations, in seconds, at which point "long connections" will be logged (default `300,600,1800,3600,43200,86400`)
        + `ZEEK_LONG_CONN_DO_NOTICE` - if set to `true`, a `notice.log` entry will be created when the zeek-long-connections plugin discovers what it considers to be a long connection (default `true`)
        + `ZEEK_LONG_CONN_REPEAT_LAST_DURATION` - if set to `true`, logging will be repeated at the last interval specified in `ZEEK_LONG_CONN_DURATIONS` (default `true`)
    - `ZEEK_LIVE_CAPTURE` - if set to `true`, Zeek will monitor live traffic on the local interface(s) defined by `PCAP_FILTER`
        + See [**Tuning Zeek**](live-analysis.md#LiveAnalysisTuningZeek) for other variables related to managing Zeek's performance and resource utilization.
    - `ZEEK_DISABLE_STATS` - if `ZEEK_LIVE_CAPTURE` is `true` and this variable is set to `false` or blank, Malcolm will enable [capture statistics Zeek](https://docs.zeek.org/en/master/scripts/policy/misc/stats.zeek.html#type-Stats::Info), which data is used to populate the **Packet Capture Statistics** dashboard
    - `ZEEK_LOCAL_NETS` - specifies the value for Zeek's [`Site::local_nets`](https://docs.zeek.org/en/master/scripts/base/utils/site.zeek.html#id-Site::local_nets) variable (and `networks.cfg` for live capture) (e.g., `1.2.3.0/24,5.6.7.0/24`); note that by default, Zeek considers IANA-registered private address space such as `10.0.0.0/8` and `192.168.0.0/16` site-local
    - `ZEEK_ROTATED_PCAP` - if set to `true`, Zeek can analyze captured PCAP files captured by `netsniff-ng` or `tcpdump` (see `PCAP_ENABLE_NETSNIFF` and `PCAP_ENABLE_TCPDUMP`, as well as `ZEEK_AUTO_ANALYZE_PCAP_FILES`); if `ZEEK_LIVE_CAPTURE` is `true`, this should be `false`; otherwise Zeek will see duplicate traffic
    - See [**Managing disk usage**](#DiskUsage) below for a discussion of the variables control automatic threshold-based deletion of the oldest [Zeek-extracted files](file-scanning.md#ZeekFileExtraction).

## <a name="CommandLineConfig"></a>Command-line arguments

The `./scripts/configure` script can also be run noninteractively which can be useful for scripting Malcolm setup. This behavior can be selected by supplying the `-d` or `--defaults` option on the command line. Running with the `--help` option will list the arguments accepted by the script:

```
usage: configure [-h] [--debug [true|false]] [--quiet] [--configure [true|false]] [--dry-run] [--log-to-file [filename]] [--skip-splash] [--tui | --dui | --gui | --non-interactive] [--compose-file <string>] [--environment-dir-input <string>] [--environment-dir-output <string>]
                 [--export-malcolm-config-file [<path>]] [--import-malcolm-config-file <path> | --load-existing-env [true|false] | --defaults] [--malcolm-file <string>] [--image-file <string>] [--extra [EXTRASETTINGS ...]]

Malcolm Installer

options:
  -h, --help            show this help message and exit

Installer Options:
  --debug, --verbose [true|false]
                        Enable debug output including tracebacks and debug utilities
  --quiet, --silent     Suppress console logging output during installation
  --configure, -c [true|false]
                        Only write configuration and ancillary files; skip installation steps
  --dry-run             Log planned actions without writing files or making system changes
  --log-to-file [filename]
                        Log output to file. If no filename provided, creates timestamped log file.
  --skip-splash         Skip the splash screen prompt on startup

Interface Mode (mutually exclusive):
  --tui                 Run in command-line text-based interface mode (default)
  --dui                 Run in python dialogs text-based user interface mode (if available - requires python dialogs)
  --gui                 Run in graphical user interface mode (if available - requires customtkinter)
  --non-interactive     Run in non-interactive mode for unattended installations (suppresses all user prompts)

Configuration File Options:
  --compose-file, --configure-file, --kube-file, -f <string>
                        Path to docker-compose.yml (for compose) or kubeconfig (for Kubernetes)

Environment Config Options:
  --environment-dir-input <string>
                        Input directory containing Malcolm's .env and .env.example files
  --environment-dir-output, -e <string>
                        Target directory for writing Malcolm's .env files
  --export-malcolm-config-file, --export-mc-file [<path>]
                        Export configuration to JSON/YAML settings file (auto-generates filename if not specified)
  --import-malcolm-config-file, --import-mc-file <path>
                        Import configuration from JSON/YAML settings file
  --load-existing-env, -l [true|false]
                        Automatically load provided config/ .env files from the input directory when present. Can be used in conjunction with --environment-dir-input
  --defaults, -d        Use built-in default configuration values and skip loading from the config directory

Installation Files:
  --malcolm-file, -m <string>
                        Malcolm .tar.gz file for installation
  --image-file, -i <string>
                        Malcolm container images .tar.xz file for installation

Additional Configuration Options:
  --extra [EXTRASETTINGS ...]
                        Extra environment variables to set (e.g., foobar.env:VARIABLE_NAME=value)
…
```

Once Malcolm is configured correctly, the `--export-malcolm-config-file` option can be used to export the configuration to a file that can be used with `--import-malcolm-config-file` to restore it later or transfer it to another Malcolm instance for import.

To modify Malcolm settings programatically in scripting, a tool like [`jq`](https://jqlang.org/) can be used with `--export-malcolm-config-file` and `--import-malcolm-config-file`, as illustrated here:
```bash
# export the current configuration to a JSON file without modifying anything in ./config/
SETTINGS_FILE="$(mktemp --suffix=.json)"
./scripts/configure --dry-run --non-interactive --export-malcolm-config-file "${SETTINGS_FILE}"

# use JQ To set whatever options in the exported JSON configuration file you wish to change
JQ_FILE="$(mktemp --suffix=.jq)"
tee "${JQ_FILE}" >/dev/null <<EOF
  .configuration.dashboardsDarkMode = true
  | .configuration.reverseDns = true
  | .configuration.pcapNodeName = "Engineering Workstation"
EOF
jq -f "${JQ_FILE}" "${SETTINGS_FILE}" | sponge "${SETTINGS_FILE}"

# import the modified configuration
./scripts/configure --non-interactive --import-malcolm-config-file "${SETTINGS_FILE}"

# clean up
rm -f "${SETTINGS_FILE}" "${JQ_FILE}"
```

Similarly, [authentication](authsetup.md#AuthSetup)-related settings can also be set noninteractively by using the [command-line arguments](authsetup.md#CommandLineConfig) for `./scripts/auth_setup`.

## <a name="DiskUsage"></a>Managing disk usage

In instances where Malcolm is deployed with the intention of running indefinitely, eventually the question arises of what to do when the file systems used for storing Malcolm's artifacts (e.g., PCAP files, raw logs, [OpenSearch indices](index-management.md), [extracted files](file-scanning.md#ZeekFileExtraction), etc.). Malcolm provides [options](#MalcolmConfigEnvVars) for tuning the "aging out" (deletion) of old artifacts to make room for newer data.

* PCAP deletion is configured by environment variables in **`arkime.env`**:
    - `MANAGE_PCAP_FILES` – if set to `true`, all PCAP files imported into Malcolm will be marked as available for [deletion by Arkime](https://arkime.com/faq#pcap-deletion) if available storage space becomes too low (default `false`)
    - `ARKIME_FREESPACEG` - when `MANAGE_PCAP_FILES` is `true`, this value is [used by Arkime](https://arkime.com/settings#freespaceg) to determine when to delete the oldest PCAP files. Note that this variable represents the amount of free/unused/available desired on the file system: e.g., a value of `5%` means "delete PCAP files if the amount of unused storage on the file system falls below 5%" (default `10%`).
* Zeek logs and Suricata logs are temporarily stored on disk as they are parsed, enriched, and indexed, and afterwards are periodically [pruned]({{ site.github.repository_url }}/blob/{{ site.github.build_revision }}/filebeat/scripts/clean-processed-folder.py) from the file system as they age, based on these variables in **`filebeat.env`**:
    - `LOG_CLEANUP_MINUTES` - specifies the age, in minutes, at which already-processed log files should be deleted
    - `ZIP_CLEANUP_MINUTES` - specifies the age, in minutes, at which the compressed archives containing already-processed log files should be deleted
* Files [extracted by Zeek](file-scanning.md#ZeekFileExtraction) stored in the `./zeek-logs/extract_files/` directory can be periodically [pruned]({{ site.github.repository_url }}/blob/{{ site.github.build_revision }}/shared/bin/prune_files.sh) based on the following variables in **`zeek.env`**. If either of the two threshold limits defined here are met, the oldest extracted files will be deleted until the limit is no longer met. Setting either of the threshold limits to `0` disables that check.
    - `EXTRACTED_FILE_PRUNE_THRESHOLD_MAX_SIZE` - specifies the maximum size, specified either in gigabytes or as a human-readable data size (e.g., `250G`), that the  `./zeek-logs/extract_files/` directory is allowed to contain before the prune condition triggers
    - `EXTRACTED_FILE_PRUNE_THRESHOLD_TOTAL_DISK_USAGE_PERCENT` - specifies a maximum fill percentage for the file system containing the `./zeek-logs/extract_files/`; in other words, if the disk is more than this percentage utilized, the prune condition triggers
    - `EXTRACTED_FILE_PRUNE_INTERVAL_SECONDS` - the interval between checking the prune conditions, in seconds (default `300`)
* [Index management policies](index-management.md) can be handled via plugins provided as part of the OpenSearch and Elasticsearch platforms, respectively. In addition to those tools, the `OPENSEARCH_INDEX_SIZE_PRUNE_LIMIT` variable in **`dashboards-helper.env`** defines a maximum cumulative that OpenSearch indices are allowed to consume before the oldest indices [are deleted]({{ site.github.repository_url }}/blob/{{ site.github.build_revision }}/dashboards/scripts/opensearch_index_size_prune.py), specified as either as a human-readable data size (e.g., `250G`) or as a percentage of the total disk size (e.g., `70%`): e.g., a value of `500G` means "delete the oldest OpenSearch indices if the total space consumed by Malcolm's indices exceeds five hundred gigabytes."
