# <a name="AuthSetup"></a>Configure authentication

* [Configure authentication](#AuthSetup)
    - [Local account management](#AuthBasicAccountManagement)
    - [Lightweight Directory Access Protocol (LDAP) authentication](#AuthLDAP)
        + [LDAP connection security](#AuthLDAPSecurity)
    - [TLS certificates](#TLSCerts)

Malcolm requires authentication to access the [user interface](quickstart.md#UserInterfaceURLs). [Nginx](https://nginx.org/) can authenticate users with either local TLS-encrypted HTTP basic authentication or using a remote Lightweight Directory Access Protocol (LDAP) authentication server.

With the local basic authentication method, user accounts are managed by Malcolm and can be created, modified, and deleted using a [user management web interface](#AuthBasicAccountManagement). This method is suitable in instances where accounts and credentials do not need to be synced across many Malcolm installations.

LDAP authentication are managed on a remote directory service, such as a [Microsoft Active Directory Domain Services](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/get-started/virtual-dc/active-directory-domain-services-overview) or [OpenLDAP](https://www.openldap.org/).

Malcolm's authentication method is defined in the [`auth-common.env` configuration file](malcolm-config.md#MalcolmConfigEnvVars) file with the `NGINX_BASIC_AUTH` environment variable: `true` for local TLS-encrypted HTTP basic authentication, `false` for LDAP authentication and `no_authentication` to disable authentication completely.

In either case, you **must** run `./scripts/auth_setup` before starting Malcolm for the first time in order to:

* define the local Malcolm administrator account username and password (although these credentials will only be used for basic authentication, not LDAP authentication)
* specify whether or not to (re)generate the self-signed certificates used for HTTPS access
    * key and certificate files are located in the `nginx/certs/` directory
* specify whether or not to (re)generate the self-signed certificates used by a remote log forwarder (see the `BEATS_SSL` environment variable above)
    * certificate authority, certificate, and key files for Malcolm's Logstash instance are located in the `logstash/certs/` directory
    * certificate authority, certificate, and key files to be copied to and used by the remote log forwarder are located in the `filebeat/certs/` directory; if using [Hedgehog Linux](live-analysis.md#Hedgehog), these certificates should be copied to the `/opt/sensor/sensor_ctl/logstash-client-certificates` directory on the sensor
* specify whether or not to [store the username/password](https://opensearch.org/docs/latest/monitoring-plugins/alerting/monitors/#authenticate-sender-account) for [email alert senders](https://opensearch.org/docs/latest/monitoring-plugins/alerting/monitors/#create-destinations)
    * these parameters are stored securely in the OpenSearch keystore file `opensearch/opensearch.keystore`

# <a name="AuthBasicAccountManagement"></a>Local account management

[`auth_setup`](#AuthSetup) is used to define the username and password for the administrator account. Once Malcolm is running, the administrator account can be used to manage other user accounts via a **Malcolm User Management** page at [https://localhost/auth](https://localhost/auth/) if you are connecting locally)

Malcolm user accounts can be used to access the [interfaces](quickstart.md#UserInterfaceURLs) of all of its [components](components.md#Components), including Arkime. Arkime uses its own internal database of user accounts, so when a Malcolm user account logs in to Arkime for the first time Malcolm creates a corresponding Arkime user account automatically. This being the case, it is *not* recommended to use the Arkime **Users** settings page or change the password via the **Password** form under the Arkime **Settings** page, as those settings would not be consistently used across Malcolm.

Users may change their passwords via the **Malcolm User Management** page by clicking **User Self Service**.

## <a name="AuthLDAP"></a>Lightweight Directory Access Protocol (LDAP) authentication

The [nginx-auth-ldap](https://github.com/kvspb/nginx-auth-ldap) module serves as the interface between Malcolm's [Nginx](https://nginx.org/) web server and a remote LDAP server. When you run [`auth_setup`](#AuthSetup) for the first time, a sample LDAP configuration file is created at `nginx/nginx_ldap.conf`. 

```
# This is a sample configuration for the ldap_server section of nginx.conf.
# Yours will vary depending on how your Active Directory/LDAP server is configured.
# See https://github.com/kvspb/nginx-auth-ldap#available-config-parameters for options.

ldap_server ad_server {
  url "ldap://ds.example.com:3268/DC=ds,DC=example,DC=com?sAMAccountName?sub?(objectClass=person)";

  binddn "bind_dn";
  binddn_passwd "bind_dn_password";

  group_attribute member;
  group_attribute_is_dn on;
  require group "CN=Malcolm,CN=Users,DC=ds,DC=example,DC=com";
  require valid_user;
  satisfy all;
}

auth_ldap_cache_enabled on;
auth_ldap_cache_expiration_time 10000;
auth_ldap_cache_size 1000;
```

This file is mounted into the `nginx` container when Malcolm is started to provide connection information for the LDAP server.

The contents of `nginx_ldap.conf` will vary depending on how the LDAP server is configured. Some of the [avaiable parameters](https://github.com/kvspb/nginx-auth-ldap#available-config-parameters) in that file include:

* **`url`** - the `ldap://` or `ldaps://` connection URL for the remote LDAP server, which has the [following syntax](https://www.ietf.org/rfc/rfc2255.txt): `ldap[s]://<hostname>:<port>/<base_dn>?<attributes>?<scope>?<filter>`
* **`binddn`** and **`binddn_password`** - the account credentials used to query the LDAP directory
* **`group_attribute`** - the group attribute name which contains the member object (e.g., `member` or `memberUid`)
* **`group_attribute_is_dn`** - whether or not to search for the user's full distinguished name as the value in the group's member attribute
* **`require`** and **`satisfy`** - `require user`, `require group` and `require valid_user` can be used in conjunction with `satisfy any` or `satisfy all` to limit the users that are allowed to access the Malcolm instance

Before starting Malcolm, edit `nginx/nginx_ldap.conf` according to the specifics of your LDAP server and directory tree structure. Using a LDAP search tool such as [`ldapsearch`](https://www.openldap.org/software/man.cgi?query=ldapsearch) in Linux or [`dsquery`](https://social.technet.microsoft.com/wiki/contents/articles/2195.active-directory-dsquery-commands.aspx) in Windows may be of help as you formulate the configuration. Your changes should be made within the curly braces of the `ldap_server ad_server { … }` section. You can troubleshoot configuration file syntax errors and LDAP connection or credentials issues by running `./scripts/logs` (or `docker-compose logs nginx`) and examining the output of the `nginx` container.

The **Malcolm User Management** page described above is not available when using LDAP authentication.

# <a name="AuthLDAPSecurity"></a>LDAP connection security

Authentication over LDAP can be done using one of three ways, [two of which](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/8e73932f-70cf-46d6-88b1-8d9f86235e81) offer data confidentiality protection: 

* **StartTLS** - the [standard extension](https://tools.ietf.org/html/rfc2830) to the LDAP protocol to establish an encrypted SSL/TLS connection within an already established LDAP connection
* **LDAPS** - a commonly used (though unofficial and considered deprecated) method in which SSL negotiation takes place before any commands are sent from the client to the server
* **Unencrypted** (cleartext) (***not recommended***)

In addition to the `NGINX_BASIC_AUTH` environment variable being set to `false` in the [`auth-common.env` configuration file](malcolm-config.md#MalcolmConfigEnvVars) file, the `NGINX_LDAP_TLS_STUNNEL` and `NGINX_LDAP_TLS_STUNNEL` environment variables are used in conjunction with the values in `nginx/nginx_ldap.conf` to define the LDAP connection security level. Use the following combinations of values to achieve the connection security methods above, respectively:

* **StartTLS**
    - `NGINX_LDAP_TLS_STUNNEL` set to `true` in [`auth-common.env`](malcolm-config.md#MalcolmConfigEnvVars)
    - `url` should begin with `ldap://` and its port should be either the default LDAP port (389) or the default Global Catalog port (3268) in `nginx/nginx_ldap.conf` 
* **LDAPS**
    - `NGINX_LDAP_TLS_STUNNEL` set to `false` in [`auth-common.env`](malcolm-config.md#MalcolmConfigEnvVars)
    - `url` should begin with `ldaps://` and its port should be either the default LDAPS port (636) or the default LDAPS Global Catalog port (3269) in `nginx/nginx_ldap.conf` 
* **Unencrypted** (clear text) (***not recommended***)
    - `NGINX_LDAP_TLS_STUNNEL` set to `false` in [`auth-common.env`](malcolm-config.md#MalcolmConfigEnvVars)
    - `url` should begin with `ldap://` and its port should be either the default LDAP port (389) or the default Global Catalog port (3268) in `nginx/nginx_ldap.conf` 

For encrypted connections (whether using **StartTLS** or **LDAPS**), Malcolm will require and verify certificates when one or more trusted CA certificate files are placed in the `nginx/ca-trust/` directory. Otherwise, any certificate presented by the domain server will be accepted.

# <a name="TLSCerts"></a>TLS certificates

When you [set up authentication](#AuthSetup) for Malcolm a set of unique [self-signed](https://en.wikipedia.org/wiki/Self-signed_certificate) TLS certificates are created which are used to secure the connection between clients (e.g., your web browser) and Malcolm's browser-based interface. This is adequate for most Malcolm instances as they are often run locally or on internal networks, although your browser will most likely require you to add a security exception for the certificate the first time you connect to Malcolm.

Another option is to generate your own certificates (or have them issued to you) and have them placed in the `nginx/certs/` directory. The certificate and key file should be named `cert.pem` and `key.pem`, respectively.

A third possibility is to use a third-party reverse proxy (e.g., [Traefik](https://doc.traefik.io/traefik/) or [Caddy](https://caddyserver.com/docs/quick-starts/reverse-proxy)) to handle the issuance of the certificates for you and to broker the connections between clients and Malcolm. Reverse proxies such as these often implement the [ACME](https://datatracker.ietf.org/doc/html/rfc8555) protocol for domain name authentication and can be used to request certificates from certificate authorities like [Let's Encrypt](https://letsencrypt.org/how-it-works/). In this configuration, the reverse proxy will be encrypting the connections instead of Malcolm, so you'll need to set the `NGINX_SSL` environment variable to `false` in [`nginx.env`](malcolm-config.md#MalcolmConfigEnvVars) (or answer `no` to the "Require encrypted HTTPS connections?" question posed by `./scripts/configure`). If you are setting `NGINX_SSL` to `false`, **make sure** you understand what you are doing and ensure that external connections cannot reach ports over which Malcolm will be communicating without encryption, including verifying your local firewall configuration.