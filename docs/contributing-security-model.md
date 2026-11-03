# Malcolm Security Model

The purpose of this document is to describe how Malcolm's components trust one another, where its security boundaries are, and which configuration choices move them. It is written for people reading Malcolm's source code with security questions in mind: contributors adding a service, operators deciding how to deploy, and researchers evaluating Malcolm for vulnerabilities.

This document describes how Malcolm is *designed*. If something in the code contradicts what is written here, that is a bug worth reporting. See [**Reporting a vulnerability**](#ReportingAVulnerability).

* [Reporting a vulnerability](#ReportingAVulnerability)
* [Trust boundaries](#TrustBoundaries)
    - [The internal container network](#InternalNetwork)
    - [What is exposed to the outside](#Exposure)
    - [The aggregator and sensor enclave](#SensorEnclave)
    - [The host](#HostBoundary)
* [Authentication and authorization](#AuthModel)
    - [nginx is the authentication layer](#NginxAuthLayer)
    - [Identity headers](#IdentityHeaders)
    - [Role-based access control](#RBACModel)
    - [The RBAC normalization problem](#RBACNormalization)
* [Data ingestion is a trusted operation](#IngestionTrust)
    - [Why uploaded artifacts are not a privilege boundary](#UploadTrust)
    - [Uploaded content is never served back](#UploadReadback)
* [Expensive queries are a user capability](#QueryCost)
* [Secrets](#Secrets)
    - [Placeholders in the repository](#SecretPlaceholders)
    - [Build-time credentials](#BuildSecrets)
* [Deployment choices that change the model](#DeploymentChoices)
* [What is not in scope](#NotInScope)

## <a name="ReportingAVulnerability"></a>Reporting a vulnerability

See [`SECURITY.md`]({{ site.github.repository_url }}/blob/{{ site.github.build_revision }}/SECURITY.md) for how to report a suspected vulnerability, what happens after a report is filed, and how CVEs are assigned for Malcolm.

Reports are most useful when they establish the following:

* **Which deployment model and authentication mode.** Many findings depend on the [authentication mode](authsetup.md) used. Several reports have described privilege escalation between roles in a configuration where Malcolm has no roles (e.g., when `NGINX_AUTH_MODE=basic` in [`auth-common.env`]({{ site.github.repository_url }}/blob/{{ site.github.build_revision }}/config/auth-common.env.example)).
* **Reachability in a shipped configuration.** Whether the affected port or path is reachable through `nginx-proxy`, or requires an administrator to have exposed something, or requires a position on the internal container network.
* **Runtime configuration rather than repository contents.** Many values in Malcolm's configuration files are placeholders substituted at container startup. See [**Placeholders in the repository**](#SecretPlaceholders).
* **What the finding adds to the position it requires.** If exploitation presupposes code execution in a Malcolm container, the relevant question is what the finding grants beyond what that position already grants.

A report that gets the mechanism wrong is still worth filing. Several of Malcolm's published advisories describe real problems that were found while investigating a report whose stated mechanism did not hold up.

## <a name="TrustBoundaries"></a>Trust boundaries

### <a name="InternalNetwork"></a>The internal container network

**Malcolm's internal container network is a single trust domain.** Every container on it is trusted to contribute data to the data store and to call the internal APIs of other Malcolm services. There is no privilege separation between containers, and none is intended.

This is the single most important thing to understand about Malcolm's security model, because a large fraction of apparent vulnerabilities in Malcolm's internal services follow from not assuming it.

Two mechanisms carry that trust:

* Containers that write to OpenSearch directly (`logstash`, `filebeat`, `arkime`, `arkime-live`, `pcap-monitor`, `dashboards`, `dashboards-helper`, `api`) have the data store credential bind-mounted at `/var/local/curlrc/.opensearch.primary.curlrc`. Code execution in any of them yields authenticated read and write access to every index.
* Containers on the ingestion path (`upload`, `zeek`, `suricata`, `filescan`, the Strelka services) do not hold that credential, because they do not need it. They write into shared volumes that the pipeline consumes. For example, a file placed in `./pcap/upload` is parsed by Zeek, Suricata, and Arkime and indexed, with pipeline-generated provenance.

Both paths put documents in the data store. The credential tracks *how* a container writes, not *whether* it is trusted to.

A consequence worth stating plainly: an attacker with code execution in any Malcolm container can write to the data store, and the internal APIs are generally a less capable path to that outcome than the one the container already has. This is why reports of the form "a compromised container can call the API without credentials" are treated as describing the trust domain rather than a boundary crossing.

Internal services are not individually hardened against each other, and hardening them would not change what a compromised container can accomplish. The boundary that matters is **network access to the internal container network**.

### <a name="Exposure"></a>What is exposed to the outside

Which ports a Malcolm deployment publishes is an installer-time decision, so there is no single answer that holds for every deployment. [`./scripts/configure`](malcolm-hedgehog-e2e-iso-install.md#MalcolmConfig) writes the `ports` entries in the `docker-compose` files from the operator's answers, and re-running it rewrites them. **The `docker-compose.yml` in the repository is a starting point, not a description of any particular deployment.**

Reading the `ports` sections of the `docker-compose` files on the host is the only reliable way to know what a given Malcolm instance publishes.

#### Always published

One port is published regardless of the exposure selections, unless Malcolm is running the [Hedgehog run profile](live-analysis.md#Profiles) or is configured to sit behind [Traefik](https://doc.traefik.io/traefik/) instead of publishing ports directly:

| Service | Published | Notes |
|---|---|---|
| `nginx-proxy` | `0.0.0.0:443` | The Malcolm user interface, and the intended external entry point. |

#### Published only by operator selection

The **Expose Malcolm Service Ports** setting ("Should Malcolm accept logs and metrics from a Hedgehog sensor or other forwarder?") has three values, and defaults to **no**, which publishes none of the ports below.

Selecting **yes** publishes the Logstash, Filebeat TCP, and OpenSearch ports. Selecting **customize** presents each of the following individually, and is the only way to reach the SFTP and syslog options:

| Service | Published when selected | Selection | What it accepts |
|---|---|---|---|
| `logstash` | `0.0.0.0:5044` | yes, or customize | Beats input from forwarders. Requires a client certificate issued by Malcolm's CA |
| `filebeat` | `0.0.0.0:5045` | yes, or customize | Filebeat TCP/JSON input. Requires a client certificate issued by Malcolm's CA |
| `nginx-proxy` | `0.0.0.0:9200` | yes, or customize | OpenSearch API passthrough, authenticated by nginx. Offered only when the primary data store is a local OpenSearch instance. |
| `upload` | `0.0.0.0:8022` | customize only | SFTP for artifact upload, authenticated by the upload service |
| `filebeat` | `0.0.0.0:<port>/tcp` | customize only | Syslog over TCP. No authentication. Not published unless a port is specified |
| `filebeat` | `0.0.0.0:<port>/udp` | customize only | Syslog over UDP. No authentication. Not published unless a port is specified |

Two properties of this are worth stating explicitly, because they are easy to assume incorrectly in either direction:

* **An exposed service binds `0.0.0.0`, not loopback.** These selections exist specifically to accept traffic from other hosts, so a selected service is reachable from every network the host is attached to. There is no "publish to localhost only" option for them.
* **A service that is not exposed has its `ports` entry removed entirely** rather than bound to loopback. It is then reachable only from within the internal container network.

The syslog options deserve separate mention: they are the only exposure selections with no authentication of any kind, because the protocol provides none. Anything able to reach a syslog port can submit records that enter the pipeline and are indexed. Enabling one means trusting every host that can route to it, and placing a network control in front of it if that trust is not warranted.

#### Hedgehog run profile

As [Hedgehog Linux](hedgehog.md) (i.e., when Malcolm runs the [Hedgehog run profile](live-analysis.md#Profiles) acts as a sensor rather than an aggregator, it's layout is different. `nginx-proxy`, Logstash, Filebeat, and SFTP publish nothing as those containers do not run under that profile. Instead, when a reachback request ACL has been configured, `filescan` publishes `0.0.0.0:8006` and either `arkime` or `arkime-live` publishes `0.0.0.0:8005`, depending on where Arkime viewer is running. These are the [Hedgehog reachback ports](malcolm-hedgehog-e2e-iso-install.md#HedgehogMalcolmPorts) described in [**The aggregator and sensor enclave**](#SensorEnclave), and the ACL is enforced with UFW.

#### Never published

No other service publishes a port in any configuration the installer writes. The API (`api:5000`), the extracted-files server on an aggregator (`filescan:8006`), Dashboards (`dashboards:5601`), OpenSearch itself (`opensearch:9200`), NetBox, PostgreSQL, Keycloak, and Valkey are reachable only from within the internal container network.

Note that the OpenSearch exposure option publishes an nginx passthrough on 9200, which applies Malcolm's authentication. The data store's own listener is never published.

Contributors adding a service should use `expose` rather than `ports`, and route user-facing interfaces through `nginx-proxy`. See [**Networking and firewall**](contributing-new-image.md#NewImageFirewall). A new service that genuinely needs a published port should be wired into the exposure selections rather than given an unconditional `ports` entry, so that an operator who selected **no** gets what they asked for.

#### Kubernetes

Kubernetes deployments have their own exposure model and the reasoning above does not carry over. The example ingress manifests expose the forwarder ports through load balancers, which in a cloud deployment means they are internet-facing unless restricted. A Kubernetes cluster may also run workloads that are not part of Malcolm and are therefore outside the trust domain described above, so restricting access to Malcolm's internal services with a `NetworkPolicy`, such that only `nginx-proxy` and Malcolm's own services can reach them, is recommended.

### <a name="SensorEnclave"></a>The aggregator and sensor enclave

[Hedgehog Linux](hedgehog.md) sensors [expose two ports](malcolm-hedgehog-e2e-iso-install.md#HedgehogMalcolmPorts) to the Malcolm aggregator, and these are not side doors around an authentication layer. There is no nginx reverse proxy on a sensor. These ports are the intended interface:

* **8005** — Arkime viewer reachback, so the aggregator can retrieve PCAP session data for display. Access control is Arkime's server-to-server (`authMode=s2s`) authentication, a shared secret plus timestamp, because there is no per-user database on a sensor to authenticate against.
* **8006** — extracted file retrieval.

Both are additionally restricted by a UFW access control list configured during Hedgehog setup, which permits only the aggregator addresses the sensor is configured to trust. The ACL limits which hosts may attempt a connection; `s2s` ensures that a host within the ACL still presents a valid shared secret.

One known limitation lives here. The `hh-extracted-files` location in `nginx.conf` builds its upstream from a caller-supplied hostname, because Malcolm does not maintain a sensor inventory and so cannot validate the destination against an allowlist. This is tracked as accepted risk. Because the destination cannot be validated, that location strips the caller's `Authorization` header, cookies, and the `X-Forwarded-User`, `X-Forwarded-Groups`, and `X-Forwarded-Roles` identity headers before proxying, so a caller-named host never receives Malcolm credentials or identity. A complete fix requires sensor registration, which is an architectural change.

### <a name="HostBoundary"></a>The host

#### Containers do not run service code as root

Every Malcolm container starts as root and drops to an unprivileged user before any service code executes. Root is used only for container initialization, and nothing that handles network traffic, uploaded artifacts, or user requests runs with it. Note that for [rootless Podman](quickstart.md#DockerVPodman) the container does not actually start as root from the host's perspective, thanks to UID mapping.

The startup work that needs root is in [`shared/bin/docker-uid-gid-setup.sh`]({{ site.github.repository_url }}/blob/{{ site.github.build_revision }}/shared/bin/docker-uid-gid-setup.sh), which runs in the entrypoint of every Malcolm image. It exists because the container has to reconcile itself with the host before it can be useful:

* `usermod`/`groupmod` the image's default account to the `PUID` and `PGID` the operator configured, so that files written into bind-mounted host directories are owned by the right user on the host side.
* `chown` files that belonged to the image's build-time UID over to the configured one, and create directories named in `PUSER_MKDIR`.
* Copy any CA certificates from `PUSER_CA_TRUST` into the image's trust store and run `update-ca-certificates`, which writes to root-owned paths.
* Apply `ulimit` values that cannot be raised after privileges are dropped.
* Rsync Kubernetes configmap directories into their parent directories, since configmap mounts are read-only and several services need to write alongside their configuration files.

None of that is reachable by an attacker: it happens before the service starts, and it does not process attacker-controlled input.

How the drop happens depends on `PUSER_PRIV_DROP`, and the distinction is worth understanding because it determines *when* in startup the privileged window closes.

#### `PUSER_PRIV_DROP=true`: the entrypoint drops immediately

Most images set this. `docker-uid-gid-setup.sh` finishes its setup work and then `exec`s the entrypoint command as `PUSER`, so the service's first instruction already runs unprivileged. There is no root-owned process left in the container afterward.

The drop uses whichever of `setpriv --reuid --regid --init-groups`, `gosu`, `su-exec`, or `su` is available, in that order of preference. All of them `exec` directly rather than opening a session of their own, to ensure correct signal handling on container shutdown.

Images in this group include `api`, `dashboards`, `dashboards-helper`, `dirinit`, `filescan`, `freq`, `keycloak`, `logstash`, `netbox`, `opensearch`, `postgresql`, the three `strelka` images, and `valkey`.

#### `PUSER_PRIV_DROP=false`: supervisord or the service drops per process

Nine images cannot drop everything at the entrypoint, because something in them genuinely needs a capability or a privileged operation at the moment it starts. These run `supervisord` as root and drop per program instead, either with `user=` on the program or by letting the service perform its own drop. The result is the same, but the privileged window extends to service startup rather than closing at the entrypoint.

There are four reasons for it, and the Dockerfiles state them at the `PUSER_PRIV_DROP=false` line:

**Traffic capture needs to retain file capabilities.** `zeek`, `suricata`, `arkime`, and `pcap-capture` set capabilities such as `CAP_NET_RAW` and `CAP_NET_ADMIN` on their capture binaries with `setcap` at build time. The `chown` pass in `docker-uid-gid-setup.sh` clears file capabilities as a side effect, so each of these re-applies `setcap` in its entrypoint before starting anything, which requires root at that point. Their supervisord programs then run as `PUSER`: Zeek's `pcap-zeek`, `live-zeek` and `intel-initialization`, Suricata's `pcap-suricata` and `live-suricata`, and Arkime's `viewer`, `wise`, `pcap-arkime` and `initialize` all carry `user=%(ENV_PUSER)s`. Capture then works through the file capabilities rather than through root.

Arkime's `live-arkime` program is the exception that proves the pattern: it is declared `user=root`, with the inline comment `; fear not, capture will dropUser/dropGroup to PUSER`. Arkime's `capture` reads its `dropUser` and `dropGroup` settings and drops privileges itself after opening the capture interface, which is the standard pattern for packet capture tools.

**A privileged helper has to chown uploaded files.** `pcap-monitor` and `filebeat` each run exactly one program as root, because taking ownership of a file an uploader created requires it: `watch-pcap-uploads-folder.py` in `pcap-monitor` and `filebeat-watch-zeeklogs-uploads-folder.py` in `filebeat`. Every other program in both containers runs as `PUSER`, including all six Filebeat instances and `pcap-monitor`'s `pcap-publisher`. These two root processes are the ones that handle untrusted filenames, which is why they are written the way the next section describes.

**A server needs to bind a privileged port or manage worker users itself.** `nginx-proxy` and `htadmin` keep a root master process because that is how nginx and php-fpm work: the master binds the listener and spawns workers as an unprivileged user. In `nginx-proxy`, nginx is compiled with `--user=nginx --group=nginx`, so its worker processes, which are the ones that actually handle requests, run as `nginx`. The same applies to php-fpm in `htadmin`, whose workers run as `www-data`. In both cases the root process binds sockets and supervises workers; it does not parse request bodies.

`nginx-proxy`'s `stunnel` program follows the same shape. It is started by supervisord without a `user=` line, but only when `NGINX_LDAP_TLS_STUNNEL=true`, and it drops privileges itself: the configuration that `nginx/scripts/docker_entrypoint.sh` generates sets `setuid = nginx` and `setgid = nginx`, so the process handling the TLS connection runs as `nginx` rather than root. stunnel is used in client mode to issue StartTLS toward the remote LDAP server, listening on `localhost` only, and it verifies the server certificate at `verify = 2` against the CA bundle assembled from `nginx/ca-trust/` when one is present. `NGINX_LDAP_TLS_STUNNEL_CHECK_HOST` and `NGINX_LDAP_TLS_STUNNEL_CHECK_IP` add hostname and address checks on top of that. See [**LDAP connection security**](authsetup.md#AuthLDAPSecurity).

**An SFTP server needs root to authenticate.** `file-upload` runs `sshd` as root, which is required for it to authenticate users and set up sessions. php-fpm and nginx in the same container drop their workers to `www-data`, which is also the container's `PUSER`.

#### What this means for a finding

Two things follow, and both have come up in reports:

* **"The container runs as root" is not by itself a finding.** The relevant question is whether a specific process that handles attacker-controlled input is running as root. In almost every case, it is not, and `grep` for `user=` in the relevant `supervisord.conf` will show which account a given program runs under.
* **The processes that legitimately stay root are a small, enumerable set**, and they are the ones worth scrutinizing: the two upload watchers, the nginx and php-fpm masters, `sshd` in `file-upload`, and the capture entrypoints during their `setcap` window. A defect in one of those is a real privilege-boundary problem.

#### Privileged file handling

The root-owned upload watchers consume files created by whoever can write to the upload directory, so entries there are treated as untrusted. `pcap-monitor`'s watcher inspects each entry with `lstat()` and removes symlinks and other non-regular entries rather than processing them; opens regular files once with `O_NOFOLLOW`; performs the ownership change, file type detection, and size check through that descriptor rather than by path; and confirms a path still refers to the same file before moving or decompressing it.

Contributors writing code that handles uploaded files as a privileged user should follow the same pattern: operate on file descriptors rather than paths, refuse to follow links, and re-confirm identity between a check and the operation that depends on it. A time-of-check/time-of-use gap in a root-owned watcher is exploitable by anyone who can create entries in the directory it watches.

## <a name="AuthModel"></a>Authentication and authorization

### <a name="NginxAuthLayer"></a>nginx is the authentication layer

All user authentication happens in the `nginx-proxy` container. Backend services do not authenticate users. They receive the authenticated identity from nginx and act on it.

This means a backend service reached directly, bypassing nginx, applies no user authentication. That is by design and follows from [the internal network being a single trust domain](#InternalNetwork): the only callers that can reach a backend directly are other Malcolm containers.

### <a name="IdentityHeaders"></a>Identity headers

nginx communicates the authenticated user to backends through request headers:

| Header | Contents |
|---|---|
| `X-Forwarded-User` | authenticated username |
| `X-Forwarded-Groups` | group list, Keycloak modes |
| `X-Forwarded-Roles` | effective role list |

In every authentication mode, nginx overwrites or clears these headers on requests it forwards, so a client-supplied value never reaches a backend. nginx also always sets `X-Forwarded-For`.

Backends trust these headers. A caller that can reach a backend port directly can set them freely, which is the same statement as the trust domain above.

Two related notes for anyone reading the [API source]({{ site.github.repository_url }}/blob/{{ site.github.build_revision }}/api:

* `is_internal_request()` in the API identifies the Dashboards Alerting loopback by `Host` and the absence of `X-Forwarded-For`, and `/mapi/event` skips the role check when it matches. It cannot be satisfied through nginx, and a caller with direct access does not need it, since such a caller could present roles directly. With `ROLE_BASED_ACCESS=false`, the default, the role check it bypasses returns true for everyone anyway.
* The `event.submitter` field recorded on documents indexed through `/mapi/event` is provenance, not an authentication control. It records `internal` for the Alerting loopback and the authenticated username otherwise. For a caller with direct network access, that value is caller-chosen in the same way `X-Forwarded-User` is.

### <a name="RBACModel"></a>Role-based access control

Role-based access control is available only when `NGINX_AUTH_MODE` is `keycloak` or `keycloak_remote` and `ROLE_BASED_ACCESS=true`. See [**Role-based access control**](authsetup.md#AuthKeycloakRBAC).

**In every other mode, all Malcolm users effectively have administrator privileges.** Under `basic`, `ldap`, or `no_authentication`, there is no privilege separation between authenticated users. A finding describing escalation from one role to another does not apply to those modes, because the roles do not exist there.

RBAC is therefore not an optional hardening layer on top of an already-separated deployment. It *is* the privilege separation. Any deployment with more than one privilege level has it enabled, and any deployment without it has no role boundary to cross.

Role enforcement happens in two places, and both matter:

* The nginx Lua layer ([`nginx/lua/nginx_auth_helpers.lua`]({{ site.github.repository_url }}/blob/{{ site.github.build_revision }}/nginx/lua/nginx_auth_helpers.lua)) gates role-restricted paths before proxying.
* Backends that understand roles re-check them. The API, the extracted-files server, Arkime, Dashboards, and OpenSearch each enforce roles independently. The `upload` and `htadmin` components do not (although `htamin` does have its own separate authentication for [creating service accounts](authsetup.md#AuthBasicAccountManagement), so for those two, nginx is the only gate.

### <a name="RBACNormalization"></a>The RBAC normalization problem

The nginx RBAC layer matches role rules against the request URI, while nginx itself selects a location block using its own normalized URI. Any disagreement between the two could mean an authorization bypass, because an unmatched path is currently granted rather than denied.

When the RBAC layer was introduced this normalization was the source of several vulnerabilities, with four separate findings in the same mechanism covering percent-encoding, doubled slashes, case variation, `..` traversal, and `.` segments. The current implementation resolves the path by walking its segments the way nginx's `ngx_http_parse_complex_uri()` does, rather than by applying successive regular expression substitutions, which is what produced the earlier gaps.

Contributors changing `normalize_uri_for_rbac()` or adding entries to `path_role_envs` should be aware that:

* [`nginx/lua/test_normalize_uri.lua`]({{ site.github.repository_url }}/blob/{{ site.github.build_revision }}/nginx/lua/test_normalize_uri.lua) contains regression tests for this function and the image build fails if they do not pass. Add cases rather than only changing behavior.
* Testing this by hand is easy to get wrong in two specific ways. A test server using `return 200` never invokes the access phase, so every request appears allowed; use `content_by_lua_block`. And `curl` normalizes dot segments client-side unless invoked with `--path-as-is`, which produces a reassuring and meaningless 403.
* Patterns in `path_role_envs` are anchored with `^`, so anything that shifts the path by one segment defeats all of them simultaneously.

## <a name="IngestionTrust"></a>Data ingestion is a trusted operation

### <a name="UploadTrust"></a>Why uploaded artifacts are not a privilege boundary

Any user who can submit an artifact to Malcolm can influence what appears in the data store. This is the function of the product, not a flaw in it.

A user who can upload a PCAP can craft one that triggers genuine Suricata signatures or Zeek notices. The resulting alerts come out of the real detection pipeline and carry real provenance, so nothing in their content distinguishes them from alerts generated by live observed traffic. The same is true of logs submitted through the Beats inputs.

This has a specific consequence for reports about alert fabrication: constrained write endpoints are a *weaker* fabrication primitive than the upload path, not a stronger one. The `/mapi/event` webhook, for example, stamps `event.provider` as `malcolm` and `event.dataset` as `alerting` before merging any caller-supplied body, and records `event.submitter`. A crafted PCAP has none of those markers.

`/mapi/event` deliberately accepts arbitrary fields. It exists to receive OpenSearch Alerting loopback results and alert data from other tools, so restricting its body to a fixed schema or an ECS allowlist would defeat its purpose. See [**Event Logging**](api-event-logging.md).

Deployments needing finer control over who may submit data should enable [RBAC](#RBACModel), which separates `ROLE_UPLOAD` from read-only roles.

What is *not* in this category: uploaded artifacts are untrusted input to the parsers that consume them. [Archive extraction]({{ site.github.repository_url }}/blob/{{ site.github.build_revision }}/scripts/safe-extract.py) enforces entry-count, depth, and total-size limits, and rejects entries resolving outside the destination, for both container archives and single-stream compressed files. A parser crash, a resource exhaustion path that bypasses those limits, or a traversal in extraction is a vulnerability.

### <a name="UploadReadback"></a>Uploaded content is never served back

Malcolm's upload page writes artifacts; it never reads them back. The upload container's nginx returns 404 by default and serves only the upload page, its static assets, and two PHP entrypoints which accept only `POST` and `DELETE`. The vendored FilePond server's `fetch`, `restore`, `load`, and `patch` handlers are removed at build time, and the build fails if any remain.

This is deliberate: if uploaded files were readable through the origin, an uploaded HTML or SVG file could be executed as script in the session of any user who opened its URL. Content-type sniffing from file contents means an extension deny-list does not address this: a renamed HTML payload is still served as `text/html` by a handler that derives the type with `mime_content_type()`.

Contributors touching the upload component should preserve the property that no path serves uploaded bytes back to a browser on the Malcolm origin.

## <a name="QueryCost"></a>Expensive queries are a user capability

Malcolm intentionally allows authorized analysts to run expensive queries against their own data. A user with a read role can build arbitrary aggregations in Dashboards, run large queries in Arkime, and request large result sets from the API.

Capping a `limit` parameter in the API would not remove that capability, only move it to a different interface. The data store enforces its own bounds in any case: `search.max_buckets` limits aggregation buckets and fails the request when exceeded, `index.max_result_window` bounds document queries, and request circuit breakers sit behind both. The API validates that `limit` and `offset` are non-negative integers and reports the data store's `_shards` and `timed_out` status so a partially failed search is visible as such rather than appearing as a normal result.

A report in this area is more likely to describe a vulnerability if it identifies an unbounded operation reachable by a user who could not otherwise perform it, or one that is not bounded by the data store.

## <a name="Secrets"></a>Secrets

### <a name="SecretPlaceholders"></a>Placeholders in the repository

**Credential-looking values in Malcolm's configuration files are generally build-time placeholders, not deployed secrets.** `auth_setup` requires the operator to supply real values, and container entrypoint scripts substitute them into configuration files at startup, before the service reads them.

`arkime/etc/config.ini` is the clearest example: `passwordSecret` in the repository is replaced from `ARKIME_PASSWORD_SECRET` by `docker_entrypoint.sh` at container start. A report treating the repository value as live will not reproduce.

Entrypoint scripts also change behavior by deployment mode. In the Hedgehog live-capture profile, `docker_entrypoint.sh` comments out `userNameHeader`, `userAuthIps`, and `userAutoCreateTmpl` entirely, so the header-trust and auto-provisioning logic visible in the file is not active on a sensor.

Reading the rendered configuration from a running container, rather than the file in the Malcolm source code repository, is the reliable way to check claims in this area.

Separately, values that ship as a usable default are treated as a real problem. `ARKIME_WISE_CONFIG_PIN_CODE` previously shipped as a known value; it now ships empty, generates a random PIN at startup when unset, and migrates existing installations away from the published default.

### <a name="BuildSecrets"></a>Build-time credentials

Credentials used by Malcolm's own build (a GitHub token, MaxMind license credentials) are passed as BuildKit secrets rather than build arguments, so they appear in neither image layer history nor the `docker compose` command line. Build arguments declared in a final build stage are recorded in published image history, which is a way to leak a credential to anyone who pulls the image.

Contributors adding a build-time credential should use a BuildKit secret, and should not declare it with `ARG` in a final stage. Scripts writing credentials to files during a build should create them in a private temporary directory with restrictive permissions and register cleanup before writing.

## <a name="DeploymentChoices"></a>Deployment choices that change the model

These are supported configuration options whose security consequences are the operator's to accept:

| Choice | Effect |
|---|---|
| `NGINX_AUTH_MODE=no_authentication` | removes user authentication entirely; every path is reachable unauthenticated |
| `NGINX_AUTH_MODE=basic` or `ldap` | all authenticated users have administrator-equivalent access |
| `ROLE_BASED_ACCESS=false` (default) | no role enforcement; all authenticated users are equivalent |
| `KEYCLOAK_SSL_VERIFY=false` (default) | the remote Keycloak certificate is not verified, so an attacker positioned between Malcolm and the identity provider can impersonate it. The default accommodates internally issued certificates; CA certificates placed in `nginx/ca-trust/` are added to the trust bundle, and nginx logs a startup warning in `keycloak_remote` mode when verification is off |
| **Expose Malcolm Service Ports** set to `yes` or `customize` | publishes the selected forwarder ports on `0.0.0.0`. See [**What is exposed to the outside**](#Exposure) |
| exposing Logstash (5044) or Filebeat TCP (5045) | reachable by anything that can present a [client certificate issued by Malcolm's CA](malcolm-hedgehog-e2e-iso-install.md#HedgehogCommConfig) |
| exposing the OpenSearch passthrough (9200) | the data store API is reachable off-host, subject to Malcolm's authentication |
| exposing SFTP (8022) | allows remote creation of entries in the upload directory, subject to the upload service's authentication |
| specifying a syslog TCP or UDP port | accepts unauthenticated log records from any host able to reach the port |
| **Require HTTPS Connections** set to `No` | Malcolm expects something else to terminate TLS; `nginx-proxy` is not reachable off-host on its own |
| editing `ports` entries by hand | moves internal services outside the internal network boundary. Re-running `./scripts/configure` overwrites manual `ports` edits |
| Kubernetes without `NetworkPolicy` | internal services may be reachable by other workloads in the cluster |

## <a name="NotInScope"></a>What is not in scope

The following are not treated as vulnerabilities in Malcolm, though specific improvements in these areas are still welcome as issues or pull requests.

**Build and distribution practice**, which is documented in detail in [**Malcolm code provenance and software supply chain**](contributing-guide-code-provenance.md). Reports in this area are usually generic observations about building from third-party sources, and they tend to assume Malcolm does less verification than it does. The current state:

* **Third-party release assets are pinned by version and verified by SHA-256.** Expected digests live in [`shared/checksums/binaries.sha256`]({{ site.github.repository_url }}/blob/{{ site.github.build_revision }}/shared/checksums/binaries.sha256), covering both `amd64` and `arm64` artifacts, and are enforced at build time by [`shared/bin/install-verified-binary.sh`]({{ site.github.repository_url }}/blob/{{ site.github.build_revision }}/shared/bin/install-verified-binary.sh), which fifteen [Dockerfiles]({{ site.github.repository_url }}/blob/{{ site.github.build_revision }}/Dockerfiles) mount and use. A digest mismatch fails the build.
* **Files fetched by URL are verified in the Dockerfile itself.** `nginx.Dockerfile` uses `ADD --checksum=sha256:...` for 28 fetched files. Sources fetched as tarballs carry an explicit digest argument checked with `sha256sum -c`, including the vendored FilePond server (`FILEPOND_SERVER_SHA256`), OpenResty (`OPENRESTY_SHA256`), freq (`FREQ_SOURCE_SHA256`, alongside a pinned `FREQ_SOURCE_COMMIT`), htadmin, and the ECS source.
* **Externally fetched web assets are verified against a manifest.** `htadmin.Dockerfile` compares the set of downloaded files against [`shared/checksums/htadmin-assets.sha256`]({{ site.github.repository_url }}/blob/{{ site.github.build_revision }}/shared/checksums/htadmin-assets.sha256) with `diff`, so an unexpected *or* missing file fails the build, and then runs `sha256sum -c --strict`.
* **Zeek packages are resolved to commits in a lock file.** [`zeek/zeek-packages.lock`]({{ site.github.repository_url }}/blob/{{ site.github.build_revision }}/zeek/zeek-packages.lock) pins every one of the ~70 Zeek plugins to an exact commit, generated from `zeek-packages.list` by `scripts/zeek_packages_lock_refresh.sh`. The build installs only what the lock file names, so a branch moving upstream does not change a build, and a refresh produces a reviewable diff.
* **Python dependencies are pinned to exact versions** with `==` in each component's `requirements.txt`.
* **Third-party package repositories are verified by signing key.** The EPEL signing key is shipped in [`shared/keys/`]({{ site.github.repository_url }}/tree/{{ site.github.build_revision }}/shared/keys) and imported with `rpm --import` rather than trusted on fetch.
* **Base images are pinned**, and the images Malcolm controls are pinned by digest rather than tag (`ghcr.io/idaholab/strelka/*@sha256:...`).
* **Published images are built by Malcolm's CI at release time** and scanned with Trivy, so a later change to an upstream artifact does not alter an already-published image.

Given that, a report here is actionable when it identifies a *specific* unpinned reference or unverified artifact in the current build, since those get fixed as ordinary issues. What is out of scope is the general observation that building from upstream sources carries supply-chain risk: exploitation requires compromising an upstream project, registry, or release first, there is no single flaw to patch or version to mark as fixed, and everything involved is visible in the public Dockerfiles. Deployments with their own verification and attestation requirements can also use the [Iron Bank](https://repo1.dso.mil/dsop/afdco/malcolm) hardened images.

**Capabilities available to an already-compromised container.** See [the internal container network](#InternalNetwork).

**Capabilities already available to the authenticated user through another interface.** See [data ingestion](#IngestionTrust) and [query cost](#QueryCost).

**Vulnerabilities in third-party components**, which should be reported to the component's own project. Malcolm scans its images with Trivy and receives Dependabot alerts; see [**Security Vulnerability Scanning**](contributing-guide-code-provenance.md#SecurityVulnerabilityScanning).

**Base operating system compliance findings** for the Malcolm and Hedgehog ISO environments, which are documented as [compliance exceptions](hardening.md#ComplianceExceptions).
