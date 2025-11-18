#!/bin/bash
set -e

NGINX_LANDING_INDEX_HTML=/usr/share/nginx/html/index.html

NGINX_CONF_DIR=/etc/nginx
NGINX_CONF=${NGINX_CONF_DIR}/nginx.conf
NGINX_TEMPLATES_DIR=${NGINX_CONF_DIR}/templates
NGINX_CONFD_DIR=${NGINX_CONF_DIR}/conf.d

# set up for HTTPS/HTTP and NGINX HTTP basic vs. LDAP/LDAPS/LDAP+StartTLS auth vs. keycloak, etc.

# "include" file that indicates the locations of the PEM files
NGINX_SSL_ON_CONF=${NGINX_CONF_DIR}/nginx_ssl_on_config.conf

# "include" symlink name which, at runtime, will point to either the ON or OFF file
NGINX_SSL_LINK=${NGINX_CONF_DIR}/nginx_ssl_config.conf

# a blank file just to use as an "include" placeholder for the nginx's LDAP config when LDAP is not used
NGINX_BLANK_CONF=${NGINX_CONF_DIR}/nginx_blank.conf

# "include" file for resolver directive
NGINX_RESOLVER_CONF=${NGINX_CONF_DIR}/nginx_system_resolver.conf

# "include" file for /auth endpoint location
NGINX_AUTH_LOCATION_LINK=${NGINX_CONF_DIR}/nginx_auth_location.conf

# "include" file for /keycloak endpoint location
NGINX_KEYCLOAK_LOCATION_LINK=${NGINX_CONF_DIR}/nginx_keycloak_location_rt.conf
NGINX_KEYCLOAK_LOCATION_CONF=${NGINX_CONF_DIR}/nginx_keycloak_location.conf

# "include" file for embedded keycloak upstream
NGINX_KEYCLOAK_UPSTREAM_LINK=${NGINX_CONF_DIR}/nginx_keycloak_upstream_rt.conf
NGINX_KEYCLOAK_UPSTREAM_CONF=${NGINX_CONF_DIR}/nginx_keycloak_upstream.conf

# "include" file for /netbox endpoint location
NGINX_NETBOX_LOCATION_LINK=${NGINX_CONF_DIR}/nginx_netbox_location_rt.conf
NGINX_NETBOX_LOCATION_CONF=${NGINX_CONF_DIR}/nginx_netbox_location.conf

# "include" file for embedded netbox upstream
NGINX_NETBOX_UPSTREAM_LINK=${NGINX_CONF_DIR}/nginx_netbox_upstream_rt.conf
NGINX_NETBOX_UPSTREAM_CONF=${NGINX_CONF_DIR}/nginx_netbox_upstream.conf

# "include" file for auth_basic, prompt, and htpasswd location
NGINX_BASIC_AUTH_CONF=${NGINX_CONF_DIR}/nginx_auth_basic.conf
NGINX_AUTH_BASIC_LOCATION_CONF=${NGINX_CONF_DIR}/nginx_auth_basic_location.conf

# "include" file for htadmin upstream
NGINX_HTADMIN_UPSTREAM_LINK=${NGINX_CONF_DIR}/nginx_htadmin_upstream_rt.conf
NGINX_HTADMIN_UPSTREAM_CONF=${NGINX_CONF_DIR}/nginx_htadmin_upstream.conf

# "include" file for Arkime WISE if enabled
NGINX_ARKIME_WISE_LINK=${NGINX_CONF_DIR}/nginx_arkime_wise_rt.conf
NGINX_ARKIME_WISE_CONF=${NGINX_CONF_DIR}/nginx_arkime_wise.conf

# "include" file for auth_ldap, prompt, and "auth_ldap_servers" name
NGINX_LDAP_AUTH_CONF=${NGINX_CONF_DIR}/nginx_auth_ldap.conf

# "include" file for KeyCloak authentication
NGINX_KEYCLOAK_AUTH_CONF=${NGINX_CONF_DIR}/nginx_auth_keycloak.conf
# experimental HTTP Basic Auth translation layer handling OAuth2 token exchange transparently
NGINX_KEYCLOAK_AUTH_BASIC_TRANSLATE_CONF=${NGINX_CONF_DIR}/nginx_auth_keycloak_basic.conf

# "include" file for fully disabling authentication
NGINX_NO_AUTH_CONF=${NGINX_CONF_DIR}/nginx_auth_disabled.conf

# volume-mounted user configuration containing "ldap_server ad_server" section with URL, binddn, etc.
NGINX_LDAP_USER_CONF=${NGINX_CONF_DIR}/nginx_ldap.conf

# runtime "include" file for auth method (link to NGINX_BASIC_AUTH_CONF, NGINX_LDAP_AUTH_CONF, NGINX_KEYCLOAK_AUTH_CONF, or NGINX_NO_AUTH_CONF)
NGINX_RUNTIME_AUTH_LINK=${NGINX_CONF_DIR}/nginx_auth_rt.conf

# "include" files and links for embedded opensearch, if used
NGINX_OPENSEARCH_UPSTREAM_LINK=${NGINX_CONF_DIR}/nginx_opensearch_upstream_rt.conf
NGINX_OPENSEARCH_UPSTREAM_CONF=${NGINX_CONF_DIR}/nginx_opensearch_upstream.conf
NGINX_OPENSEARCH_MAPI_LINK=${NGINX_CONF_DIR}/nginx_opensearch_mapi_rt.conf
NGINX_OPENSEARCH_MAPI_CONF=${NGINX_CONF_DIR}/nginx_opensearch_mapi.conf
NGINX_OPENSEARCH_API_LINK=${NGINX_CONF_DIR}/nginx_opensearch_api_rt.conf
NGINX_OPENSEARCH_API_CONF=${NGINX_CONF_DIR}/nginx_opensearch_api.conf
NGINX_OPENSEARCH_API_501_CONF=${NGINX_CONF_DIR}/nginx_opensearch_api_501.conf

# runtime "include" file for endpoints for service accounts that have to use a simpler auth method
#   (link to NGINX_BASIC_AUTH_CONF, NGINX_LDAP_AUTH_CONF, or NGINX_NO_AUTH_CONF)
NGINX_RUNTIME_AUTH_SERVICE_ACCT_LINK=${NGINX_CONF_DIR}/nginx_auth_service_acct_rt.conf

# runtime "include" file for ldap config (link to either NGINX_BLANK_CONF or (possibly modified) NGINX_LDAP_USER_CONF)
NGINX_RUNTIME_LDAP_LINK=${NGINX_CONF_DIR}/nginx_ldap_rt.conf

# "include" files and links for embedded opensearch dashboards, if used
NGINX_DASHBOARDS_UPSTREAM_LINK=${NGINX_CONF_DIR}/nginx_dashboards_upstream_rt.conf
NGINX_DASHBOARDS_UPSTREAM_CONF=${NGINX_CONF_DIR}/nginx_dashboards_upstream.conf
# "include" files for idark2dash rewrite using opensearch dashboards, kibana, and runtime copy, respectively
NGINX_DASHBOARDS_IDARK2DASH_REWRITE_CONF=${NGINX_CONF_DIR}/nginx_idark2dash_rewrite_dashboards.conf
NGINX_KIBANA_IDARK2DASH_REWRITE_CONF=${NGINX_CONF_DIR}/nginx_idark2dash_rewrite_kibana.conf
NGINX_RUNTIME_IDARK2DASH_REWRITE_LINK=${NGINX_CONF_DIR}/nginx_idark2dash_rewrite_rt.conf
# do the same thing for /dashboards URLs, send to kibana if they're using elasticsearch
NGINX_DASHBOARDS_DASHBOARDS_REWRITE_CONF=${NGINX_CONF_DIR}/nginx_dashboards_rewrite_dashboards.conf
NGINX_KIBANA_DASHBOARDS_REWRITE_CONF=${NGINX_CONF_DIR}/nginx_dashboards_rewrite_kibana.conf
NGINX_RUNTIME_DASHBOARDS_REWRITE_LINK=${NGINX_CONF_DIR}/nginx_dashboards_rewrite_rt.conf

# logging
NGINX_LOGGING_CONF=${NGINX_CONF_DIR}/nginx_logging.conf

# config file for stunnel if using stunnel to issue LDAP StartTLS function
STUNNEL_CONF=/etc/stunnel/stunnel.conf

CA_TRUST_HOST_DIR=/var/local/ca-trust
CA_TRUST_RUN_DIR=/var/run/ca-trust

# copy trusted CA certs to runtime directory and c_rehash them to create symlinks
STUNNEL_CA_PATH_LINE=""
STUNNEL_VERIFY_LINE=""
STUNNEL_CHECK_HOST_LINE=""
STUNNEL_CHECK_IP_LINE=""
NGINX_LDAP_CA_PATH_LINE=""
NGINX_LDAP_CHECK_REMOTE_CERT_LINE=""
mkdir -p "$CA_TRUST_RUN_DIR"
# attempt to make sure trusted CA certs dir is readable by unprivileged nginx worker
chmod 755 "$CA_TRUST_RUN_DIR" || true
CA_FILES=$(shopt -s nullglob dotglob; echo "$CA_TRUST_HOST_DIR"/*)
if (( ${#CA_FILES} )) ; then
  rm -f "$CA_TRUST_RUN_DIR"/*
  pushd "$CA_TRUST_RUN_DIR" >/dev/null 2>&1
  if cp "$CA_TRUST_HOST_DIR"/* ./ ; then

    # attempt to make sure trusted CA certs are readable by unprivileged nginx worker
    chmod 644 * || true

    # create hash symlinks
    c_rehash -compat .

    # variables for stunnel config
    STUNNEL_CA_PATH_LINE="CApath = $CA_TRUST_RUN_DIR"
    [[ -n $NGINX_LDAP_TLS_STUNNEL_VERIFY_LEVEL ]] && STUNNEL_VERIFY_LINE="verify = $NGINX_LDAP_TLS_STUNNEL_VERIFY_LEVEL" || STUNNEL_VERIFY_LINE="verify = 2"
    [[ -n $NGINX_LDAP_TLS_STUNNEL_CHECK_HOST ]] && STUNNEL_CHECK_HOST_LINE="checkHost = $NGINX_LDAP_TLS_STUNNEL_CHECK_HOST"
    [[ -n $NGINX_LDAP_TLS_STUNNEL_CHECK_IP ]] && STUNNEL_CHECK_IP_LINE="checkIP = $NGINX_LDAP_TLS_STUNNEL_CHECK_IP"

    # variables for nginx config
    NGINX_LDAP_CA_PATH_LINE="  ssl_ca_dir $CA_TRUST_RUN_DIR;"
    ( [[ -n $NGINX_LDAP_TLS_STUNNEL_CHECK_HOST ]] || [[ -n $NGINX_LDAP_TLS_STUNNEL_CHECK_IP ]] ) && NGINX_LDAP_CHECK_REMOTE_CERT_LINE="  ssl_check_cert on;" || NGINX_LDAP_CHECK_REMOTE_CERT_LINE="  ssl_check_cert off;"
  fi
  popd >/dev/null 2>&1
fi

if [[ -z $NGINX_SSL ]] || [[ "$NGINX_SSL" != "false" ]]; then
  # doing encrypted HTTPS
  ln -sf "$NGINX_SSL_ON_CONF" "$NGINX_SSL_LINK"
  SSL_FLAG=" ssl"

  # generate dhparam.pem if missing
  if [[ ! -f ${NGINX_CONF_DIR}/dhparam/dhparam.pem ]]; then
    mkdir -p ${NGINX_CONF_DIR}/dhparam
    echo "Generating DH parameters" >&2 && \
      ( openssl dhparam -out ${NGINX_CONF_DIR}/dhparam/dhparam.pem 2048 >/dev/null 2>&1 || \
        echo "Failed to generate DH parameters" >&2 )
    if [[ -f ${NGINX_CONF_DIR}/dhparam/dhparam.pem ]]; then
      [[ -n ${PUID} ]] && chown -f ${PUID} ${NGINX_CONF_DIR}/dhparam/dhparam.pem
      [[ -n ${PGID} ]] && chown -f :${PGID} ${NGINX_CONF_DIR}/dhparam/dhparam.pem
      chmod 600 ${NGINX_CONF_DIR}/dhparam/dhparam.pem
    fi
  fi

  # generate self-signed TLS certificate if missing
  if [[ ! -f ${NGINX_CONF_DIR}/certs/cert.pem ]] && [[ ! -f ${NGINX_CONF_DIR}/certs/key.pem ]]; then
    mkdir -p ${NGINX_CONF_DIR}/certs
    echo "Generating self-signed certificate" >&2 && \
      ( openssl req -subj /CN=localhost -x509 -newkey rsa:4096 -nodes -keyout ${NGINX_CONF_DIR}/certs/key.pem -out ${NGINX_CONF_DIR}/certs/cert.pem -days 3650 || \
        echo "Failed to generate self-signed certificate" >&2 )
    if [[ -f ${NGINX_CONF_DIR}/certs/cert.pem ]]; then
      [[ -n ${PUID} ]] && chown -f ${PUID} ${NGINX_CONF_DIR}/certs/cert.pem
      [[ -n ${PGID} ]] && chown -f :${PGID} ${NGINX_CONF_DIR}/certs/cert.pem
      chmod 644 ${NGINX_CONF_DIR}/certs/cert.pem
    fi
    if [[ -f ${NGINX_CONF_DIR}/certs/key.pem ]]; then
      [[ -n ${PUID} ]] && chown -f ${PUID} ${NGINX_CONF_DIR}/certs/key.pem
      [[ -n ${PGID} ]] && chown -f :${PGID} ${NGINX_CONF_DIR}/certs/key.pem
      chmod 600 ${NGINX_CONF_DIR}/certs/key.pem
    fi
  fi

else
  # doing unencrypted HTTP (not recommended)
  ln -sf "$NGINX_BLANK_CONF" "$NGINX_SSL_LINK"
  SSL_FLAG=""
fi

# generate listen_####.conf files with appropriate SSL flag (since the NGINX
#   listen directive doesn't allow using variables)
if [[ -f "${NGINX_CONF}" ]]; then
  LISTEN_PORT_CONF_PATTERN="^\s*include\s+(${NGINX_CONF_DIR}/listen_([0-9]+)\.conf)\s*;\s*$"
  while IFS= read -r LINE; do
    if [[ "${LINE}" =~ ${LISTEN_PORT_CONF_PATTERN} ]]; then
      IFILE=${BASH_REMATCH[1]}
      PORT=${BASH_REMATCH[2]}
      [[ ! -f "${IFILE}" ]] && echo "listen ${PORT}${SSL_FLAG};" > "${IFILE}"
    fi
  done < "${NGINX_CONF}"
fi
# generate upload_max_body_size_incl since we can't use variables in client_max_body_size either
echo "client_max_body_size ${PCAP_UPLOAD_MAX_FILE_GB:-50}G;" > /etc/nginx/nginx_upload_max_body_size_incl.conf

# set logging level for error.log
echo "error_log /var/log/nginx/error.log ${NGINX_ERROR_LOG_LEVEL:-error};" > "${NGINX_LOGGING_CONF}"

# set up config links for whether there's an embedded opensearch instance or not
if [[ "${OPENSEARCH_PRIMARY:-opensearch-local}" == "opensearch-local" ]]; then
  ln -sf "$NGINX_OPENSEARCH_UPSTREAM_CONF" "$NGINX_OPENSEARCH_UPSTREAM_LINK"
  ln -sf "$NGINX_DASHBOARDS_UPSTREAM_CONF" "$NGINX_DASHBOARDS_UPSTREAM_LINK"
  ln -sf "$NGINX_OPENSEARCH_MAPI_CONF" "$NGINX_OPENSEARCH_MAPI_LINK"
  ln -sf "$NGINX_OPENSEARCH_API_CONF" "$NGINX_OPENSEARCH_API_LINK"
else
  ln -sf "$NGINX_BLANK_CONF" "$NGINX_OPENSEARCH_UPSTREAM_LINK"
  ln -sf "$NGINX_BLANK_CONF" "$NGINX_DASHBOARDS_UPSTREAM_LINK"
  ln -sf "$NGINX_BLANK_CONF" "$NGINX_OPENSEARCH_MAPI_LINK"
  ln -sf "$NGINX_OPENSEARCH_API_501_CONF" "$NGINX_OPENSEARCH_API_LINK"
fi

if [[ "${NETBOX_MODE:-local}" == "local" ]]; then
  # /netbox location points to embedded netbox container
  ln -sf "$NGINX_NETBOX_LOCATION_CONF" "$NGINX_NETBOX_LOCATION_LINK"
  ln -sf "$NGINX_NETBOX_UPSTREAM_CONF" "$NGINX_NETBOX_UPSTREAM_LINK"
else
  # /netbox location isn't used
  ln -sf "$NGINX_BLANK_CONF" "$NGINX_NETBOX_LOCATION_LINK"
  ln -sf "$NGINX_BLANK_CONF" "$NGINX_NETBOX_UPSTREAM_LINK"
fi

# NGINX_AUTH_MODE basic|ldap|keycloak|keycloak_remote|no_authentication
if [[ -z $NGINX_AUTH_MODE ]] || [[ "$NGINX_AUTH_MODE" == "basic" ]] || [[ "$NGINX_AUTH_MODE" == "true" ]]; then
  # doing HTTP basic auth

  # point nginx_auth_rt.conf to nginx_auth_basic.conf
  ln -sf "$NGINX_BASIC_AUTH_CONF" "$NGINX_RUNTIME_AUTH_LINK"
  ln -sf "$NGINX_BASIC_AUTH_CONF" "$NGINX_RUNTIME_AUTH_SERVICE_ACCT_LINK"

  # ldap configuration is empty
  ln -sf "$NGINX_BLANK_CONF" "$NGINX_RUNTIME_LDAP_LINK"

  # /auth location handling for htpasswd
  ln -sf "$NGINX_AUTH_BASIC_LOCATION_CONF" "$NGINX_AUTH_LOCATION_LINK"
  ln -sf "$NGINX_HTADMIN_UPSTREAM_CONF" "$NGINX_HTADMIN_UPSTREAM_LINK"

  # /keycloak location isn't used
  ln -sf "$NGINX_BLANK_CONF" "$NGINX_KEYCLOAK_LOCATION_LINK"
  ln -sf "$NGINX_BLANK_CONF" "$NGINX_KEYCLOAK_UPSTREAM_LINK"

elif [[ "$NGINX_AUTH_MODE" == "no_authentication" ]] || [[ "$NGINX_AUTH_MODE" == "none" ]] || [[ "$NGINX_AUTH_MODE" == "no" ]]; then
  # completely disabling authentication (not recommended)

  # point nginx_auth_rt.conf to nginx_auth_disabled.conf
  ln -sf "$NGINX_NO_AUTH_CONF" "$NGINX_RUNTIME_AUTH_LINK"
  ln -sf "$NGINX_NO_AUTH_CONF" "$NGINX_RUNTIME_AUTH_SERVICE_ACCT_LINK"

  # ldap configuration is empty
  ln -sf "$NGINX_BLANK_CONF" "$NGINX_RUNTIME_LDAP_LINK"

  # /auth and /keycloak locations are empty
  ln -sf "$NGINX_BLANK_CONF" "$NGINX_AUTH_LOCATION_LINK"
  ln -sf "$NGINX_BLANK_CONF" "$NGINX_HTADMIN_UPSTREAM_LINK"
  ln -sf "$NGINX_BLANK_CONF" "$NGINX_KEYCLOAK_LOCATION_LINK"
  ln -sf "$NGINX_BLANK_CONF" "$NGINX_KEYCLOAK_UPSTREAM_LINK"

elif [[ "$NGINX_AUTH_MODE" == "keycloak_remote" ]]; then
  # Keycloak (remote) authentication

  # point nginx_auth_rt.conf to nginx_auth_keycloak.conf
  ln -sf "$NGINX_KEYCLOAK_AUTH_CONF" "$NGINX_RUNTIME_AUTH_LINK"

  # TODO: we can't yet handle proxying client API requests to some endpoints
  #   with Keycloak so we have to use basic for now
  if [[ "${NGINX_KEYCLOAK_BASIC_AUTH:-false}" == "true" ]]; then
    # experimental
    ln -sf "$NGINX_KEYCLOAK_AUTH_BASIC_TRANSLATE_CONF" "$NGINX_RUNTIME_AUTH_SERVICE_ACCT_LINK"
  else
    ln -sf "$NGINX_BASIC_AUTH_CONF" "$NGINX_RUNTIME_AUTH_SERVICE_ACCT_LINK"
  fi

  # ldap configuration is empty
  ln -sf "$NGINX_BLANK_CONF" "$NGINX_RUNTIME_LDAP_LINK"

  # /auth location handling for htpasswd
  ln -sf "$NGINX_AUTH_BASIC_LOCATION_CONF" "$NGINX_AUTH_LOCATION_LINK"
  ln -sf "$NGINX_HTADMIN_UPSTREAM_CONF" "$NGINX_HTADMIN_UPSTREAM_LINK"

  # /keycloak location isn't used
  ln -sf "$NGINX_BLANK_CONF" "$NGINX_KEYCLOAK_LOCATION_LINK"
  ln -sf "$NGINX_BLANK_CONF" "$NGINX_KEYCLOAK_UPSTREAM_LINK"

elif [[ "$NGINX_AUTH_MODE" == "keycloak" ]]; then
  # Keycloak (embedded) authentication

  # point nginx_auth_rt.conf to nginx_auth_keycloak.conf
  ln -sf "$NGINX_KEYCLOAK_AUTH_CONF" "$NGINX_RUNTIME_AUTH_LINK"

  # TODO: we can't yet handle proxying client API requests to some endpoints
  #   with Keycloak so we have to use basic for now
  if [[ "${NGINX_KEYCLOAK_BASIC_AUTH:-false}" == "true" ]]; then
    # experimental
    ln -sf "$NGINX_KEYCLOAK_AUTH_BASIC_TRANSLATE_CONF" "$NGINX_RUNTIME_AUTH_SERVICE_ACCT_LINK"
  else
    ln -sf "$NGINX_BASIC_AUTH_CONF" "$NGINX_RUNTIME_AUTH_SERVICE_ACCT_LINK"
  fi

  # ldap configuration is empty
  ln -sf "$NGINX_BLANK_CONF" "$NGINX_RUNTIME_LDAP_LINK"

  # /auth location handling for htpasswd
  ln -sf "$NGINX_AUTH_BASIC_LOCATION_CONF" "$NGINX_AUTH_LOCATION_LINK"
  ln -sf "$NGINX_HTADMIN_UPSTREAM_CONF" "$NGINX_HTADMIN_UPSTREAM_LINK"

  # /keycloak location points to embedded keycloak container
  ln -sf "$NGINX_KEYCLOAK_LOCATION_CONF" "$NGINX_KEYCLOAK_LOCATION_LINK"
  ln -sf "$NGINX_KEYCLOAK_UPSTREAM_CONF" "$NGINX_KEYCLOAK_UPSTREAM_LINK"

elif [[ "$NGINX_AUTH_MODE" == "ldap" ]] || [[ "$NGINX_AUTH_MODE" == "false" ]]; then
  # ldap authentication

  # point nginx_auth_rt.conf to nginx_auth_ldap.conf
  ln -sf "$NGINX_LDAP_AUTH_CONF" "$NGINX_RUNTIME_AUTH_LINK"
  ln -sf "$NGINX_LDAP_AUTH_CONF" "$NGINX_RUNTIME_AUTH_SERVICE_ACCT_LINK"

  # /auth and /keycloak locations are empty
  ln -sf "$NGINX_BLANK_CONF" "$NGINX_AUTH_LOCATION_LINK"
  ln -sf "$NGINX_BLANK_CONF" "$NGINX_HTADMIN_UPSTREAM_LINK"
  ln -sf "$NGINX_BLANK_CONF" "$NGINX_KEYCLOAK_LOCATION_LINK"
  ln -sf "$NGINX_BLANK_CONF" "$NGINX_KEYCLOAK_UPSTREAM_LINK"

  # parse URL information out of user ldap configuration
  # example:
  #   url "ldap://localhost:3268/DC=ds,DC=example,DC=com?sAMAccountName?sub?(objectClass=person)";
  #             "url"    quote protocol h/p    uri
  #             ↓        ↓     ↓        ↓      ↓
  PATTERN='^(\s*url\s+)([''"]?)(\w+)://([^/]+)(/.*)$'

  unset HEADER
  unset OPEN_QUOTE
  unset PROTOCOL
  unset REMOTE_HOST
  unset REMOTE_PORT
  unset URI_TO_END

  URL_LINE_NUM=0
  READ_LINE_NUM=0
  while IFS= read -r LINE; do
    READ_LINE_NUM=$((READ_LINE_NUM+1))
    if [[ $LINE =~ $PATTERN ]]; then
      URL_LINE_NUM=$READ_LINE_NUM
      HEADER=${BASH_REMATCH[1]}
      OPEN_QUOTE=${BASH_REMATCH[2]}
      PROTOCOL=${BASH_REMATCH[3]}
      REMOTE=${BASH_REMATCH[4]}
      REMOTE_ARR=(${REMOTE//:/ })
      [[ -n ${REMOTE_ARR[0]} ]] && REMOTE_HOST=${REMOTE_ARR[0]}
      [[ -n ${REMOTE_ARR[1]} ]] && REMOTE_PORT=${REMOTE_ARR[1]} || REMOTE_PORT=3268
      URI_TO_END=${BASH_REMATCH[5]}
      break
    fi
  done < "$NGINX_LDAP_USER_CONF"

  if [[ "$NGINX_LDAP_TLS_STUNNEL" == "true" ]]; then
    # user provided LDAP configuration, but we need to tweak it and set up stunnel to issue StartTLS

    if [[ -z $REMOTE_HOST ]]; then
      # missing LDAP info needed to configure tunnel, abort
      exit 1
    fi

    # pick a random local port to listen on for the client side of the tunnel
    read PORT_LOWER POWER_UPPER < /proc/sys/net/ipv4/ip_local_port_range
    LOCAL_PORT=$(shuf -i $PORT_LOWER-$POWER_UPPER -n 1)

    # create PEM key for stunnel (this key doesn't matter as we're only using stunnel in client mode)
    pushd /tmp >/dev/null 2>&1
    openssl genrsa -out key.pem 2048
    openssl req -new -x509 -key key.pem -out cert.pem -days 3650 -subj "/CN=$(hostname)/O=Malcolm/C=US"
    cat key.pem cert.pem > /etc/stunnel/stunnel.pem
    chmod 600 /etc/stunnel/stunnel.pem
    rm -f key.pem cert.pem
    popd >/dev/null 2>&1

    # configure stunnel
    cat <<EOF > "$STUNNEL_CONF"
setuid = nginx
setgid = nginx
pid = /tmp/stunnel.pid
socket = l:TCP_NODELAY=1
socket = r:TCP_NODELAY=1
client = yes
foreground = yes
cert = /etc/stunnel/stunnel.pem
$STUNNEL_CA_PATH_LINE
$STUNNEL_VERIFY_LINE
$STUNNEL_CHECK_HOST_LINE
$STUNNEL_CHECK_IP_LINE

[stunnel.ldap_start_tls]
accept = localhost:$LOCAL_PORT
connect = $REMOTE_HOST:$REMOTE_PORT
protocol = ldap
EOF

    # rewrite modified copy of user ldap configuration to point to local end of tunnel instead of remote
    rm -f "$NGINX_RUNTIME_LDAP_LINK"
    touch "$NGINX_RUNTIME_LDAP_LINK"
    chmod 600 "$NGINX_RUNTIME_LDAP_LINK"
    READ_LINE_NUM=0
    while IFS= read -r LINE; do
      READ_LINE_NUM=$((READ_LINE_NUM+1))
      if (( $URL_LINE_NUM == $READ_LINE_NUM )); then
        echo "${HEADER}${OPEN_QUOTE}ldap://localhost:${LOCAL_PORT}${URI_TO_END}" >> "$NGINX_RUNTIME_LDAP_LINK"
      else
        echo "$LINE" >> "$NGINX_RUNTIME_LDAP_LINK"
      fi
    done < "$NGINX_LDAP_USER_CONF"

  else
    # we're doing either LDAP or LDAPS, but not StartTLS, so we don't need to use stunnel.
    # however, we do want to set SSL CA trust stuff if specified, so do that
    rm -f "$NGINX_RUNTIME_LDAP_LINK"
    touch "$NGINX_RUNTIME_LDAP_LINK"
    chmod 600 "$NGINX_RUNTIME_LDAP_LINK"
    READ_LINE_NUM=0
    while IFS= read -r LINE; do
      READ_LINE_NUM=$((READ_LINE_NUM+1))
      echo "$LINE" >> "$NGINX_RUNTIME_LDAP_LINK"
      if (( $URL_LINE_NUM == $READ_LINE_NUM )); then
        echo "$NGINX_LDAP_CHECK_REMOTE_CERT_LINE" >> "$NGINX_RUNTIME_LDAP_LINK"
        echo "$NGINX_LDAP_CA_PATH_LINE" >> "$NGINX_RUNTIME_LDAP_LINK"
      fi
    done < "$NGINX_LDAP_USER_CONF"

  fi # stunnel/starttls vs. ldap/ldaps

fi # basic vs. ldap

# if the runtime htpasswd file doesn't exist but the "preseed" does, copy the preseed over for runtime
if [[ ! -f ${NGINX_CONF_DIR}/auth/htpasswd ]] && [[ -f /tmp/auth/default/htpasswd ]]; then
  cp /tmp/auth/default/htpasswd ${NGINX_CONF_DIR}/auth/htpasswd
  [[ -n ${PUID} ]] && chown -f ${PUID} ${NGINX_CONF_DIR}/auth/htpasswd
  [[ -n ${PGID} ]] && chown -f :${PGID} ${NGINX_CONF_DIR}/auth/htpasswd
  rm -rf /tmp/auth/* || true
fi

# do environment variable substitutions from $NGINX_TEMPLATES_DIR to $NGINX_CONFD_DIR
# NGINX_DASHBOARDS_... are a special case as they have to be crafted a bit based on a few variables
set +e

if [[ "${OPENSEARCH_PRIMARY:-opensearch-local}" == "elasticsearch-remote" ]]; then
  ln -sf "$NGINX_KIBANA_IDARK2DASH_REWRITE_CONF" "$NGINX_RUNTIME_IDARK2DASH_REWRITE_LINK"
  ln -sf "$NGINX_KIBANA_DASHBOARDS_REWRITE_CONF" "$NGINX_RUNTIME_DASHBOARDS_REWRITE_LINK"
else
  ln -sf "$NGINX_DASHBOARDS_IDARK2DASH_REWRITE_CONF" "$NGINX_RUNTIME_IDARK2DASH_REWRITE_LINK"
  ln -sf "$NGINX_DASHBOARDS_DASHBOARDS_REWRITE_CONF" "$NGINX_RUNTIME_DASHBOARDS_REWRITE_LINK"
fi

# first parse DASHBOARDS_URL and assign the resultant urlsplit named tuple to an associative array
#   going to use Python to do so as urllib will do a better job at parsing DASHBOARDS_URL than bash
DASHBOARDS_URL_PARSED="$( ( /usr/bin/env python3 -c "import sys; import json; from urllib.parse import urlsplit; [ sys.stdout.write(json.dumps(urlsplit(line)._asdict()) + '\n') for line in sys.stdin ]" 2>/dev/null <<< "${DASHBOARDS_URL:-http://dashboards:5601/dashboards}" ) | head -n 1 )"
declare -A DASHBOARDS_URL_DICT
for KEY in $(jq -r 'keys[]' 2>/dev/null <<< $DASHBOARDS_URL_PARSED); do
  DASHBOARDS_URL_DICT["$KEY"]=$(jq -r ".$KEY" 2>/dev/null <<< $DASHBOARDS_URL_PARSED)
done

# the "path" from the parsed URL is the dashboards prefix
[[ -z "${NGINX_DASHBOARDS_PREFIX:-}" ]] && \
  [[ -v DASHBOARDS_URL_DICT[path] ]] && \
  NGINX_DASHBOARDS_PREFIX="${DASHBOARDS_URL_DICT[path]}"
# if we failed to get it, use the default
[[ -z "${NGINX_DASHBOARDS_PREFIX:-}" ]] && \
  [[ "${OPENSEARCH_PRIMARY:-opensearch-local}" != "elasticsearch-remote" ]] && \
  NGINX_DASHBOARDS_PREFIX=/dashboards

# the "path" from the parsed URL is the dashboards prefix
if [[ -z "${NGINX_DASHBOARDS_PROXY_PASS:-}" ]]; then
  # if Malcolm is running in anything other than "elasticsearch-remote" mode, then
  #   the dashboards service is already defined in the upstream
  if [[ "${OPENSEARCH_PRIMARY:-opensearch-local}" == "elasticsearch-remote" ]] && [[ -v DASHBOARDS_URL_DICT[scheme] ]] && [[ -v DASHBOARDS_URL_DICT[netloc] ]]; then
    NGINX_DASHBOARDS_PROXY_PASS="${DASHBOARDS_URL_DICT[scheme]}://${DASHBOARDS_URL_DICT[netloc]}"
  else
    NGINX_DASHBOARDS_PROXY_PASS=http://dashboards
  fi
fi
# if we failed to get it, use the default
[[ -z "${NGINX_DASHBOARDS_PROXY_PASS:-}" ]] && \
  [[ "${OPENSEARCH_PRIMARY:-opensearch-local}" != "elasticsearch-remote" ]] && \
  NGINX_DASHBOARDS_PROXY_PASS=http://dashboards

export NGINX_DASHBOARDS_PREFIX
export NGINX_DASHBOARDS_PROXY_PASS
export NGINX_DASHBOARDS_PROXY_URL="$(echo "$(echo "$NGINX_DASHBOARDS_PROXY_PASS" | sed 's@/$@@')/$(echo "$NGINX_DASHBOARDS_PREFIX" | sed 's@^/@@')" | sed 's@/$@@')"

# now process the environment variable substitutions
for TEMPLATE in "$NGINX_TEMPLATES_DIR"/*.conf.template; do
  DOLLAR=$ envsubst < "$TEMPLATE" > "$NGINX_CONFD_DIR/$(basename "$TEMPLATE"| sed 's/\.template$//')"
done

if [[ -z "${NGINX_RESOLVER_OVERRIDE:-}" ]]; then
  # put the DNS resolver (nameserver from /etc/resolv.conf) into NGINX_RESOLVER_CONF
  DNS_SERVER="$(grep -i '^nameserver' /etc/resolv.conf | head -n1 | cut -d ' ' -f2)"
else
  DNS_SERVER=${NGINX_RESOLVER_OVERRIDE}
fi
[[ -z "${DNS_SERVER:-}" ]] && DNS_SERVER="127.0.0.11"
export DNS_SERVER
echo -n "resolver ${DNS_SERVER}" > "${NGINX_RESOLVER_CONF}"
[[ "${NGINX_RESOLVER_IPV4:-true}" == "false" ]] && echo -n " ipv4=off" >> "${NGINX_RESOLVER_CONF}"
[[ "${NGINX_RESOLVER_IPV6:-true}" == "false" ]] && echo -n " ipv6=off" >> "${NGINX_RESOLVER_CONF}"
echo ";" >> "${NGINX_RESOLVER_CONF}"

set -e

# insert some build and runtime information into the landing page
if [[ -f "${NGINX_LANDING_INDEX_HTML}" ]]; then
  if [[ "${OPENSEARCH_PRIMARY:-opensearch-local}" == "elasticsearch-remote" ]]; then
    MALCOLM_DASHBOARDS_NAME=Kibana
    MALCOLM_DASHBOARDS_URL="$NGINX_DASHBOARDS_PROXY_URL"
    MALCOLM_DASHBOARDS_ICON=elastic.svg
  else
    MALCOLM_DASHBOARDS_NAME=Dashboards
    MALCOLM_DASHBOARDS_URL="$(echo "$NGINX_DASHBOARDS_PREFIX" | sed 's@/$@@')/"
    MALCOLM_DASHBOARDS_ICON=opensearch_mark_default.svg
  fi
  if [[ "$NGINX_AUTH_MODE" == "ldap" ]]; then
    AUTH_TITLE="LDAP Authentication"
    AUTH_DESC="Malcolm is using <a href=\"readme/docs/authsetup.html#AuthLDAP\">LDAP</a> for authentication"
    AUTH_LINK="/readme/docs/authsetup.html#AuthLDAP"
  elif [[ "$NGINX_AUTH_MODE" == "keycloak" ]]; then
    AUTH_TITLE="Keycloak Authentication"
    AUTH_DESC="Malcolm is using <a href=\"readme/docs/authsetup.html#AuthKeycloak\">Keycloak</a> for authentication"
    AUTH_LINK="/keycloak/"
  elif [[ "$NGINX_AUTH_MODE" == "keycloak_remote" ]]; then
    AUTH_TITLE="Keycloak Authentication"
    AUTH_DESC="Malcolm is using a remote <a href=\"readme/docs/authsetup.html#AuthKeycloakRemote\">Keycloak</a> for authentication"
    AUTH_LINK="${KEYCLOAK_AUTH_URL:-}"
  elif [[ "$NGINX_AUTH_MODE" == "no_authentication" ]] || [[ "$NGINX_AUTH_MODE" == "none" ]] || [[ "$NGINX_AUTH_MODE" == "no" ]]; then
    AUTH_TITLE="Authentication is Disabled"
    AUTH_DESC="<a href=\"/readme/docs/authsetup.html\">Authentication for Malcolm</a> is disabled"
    AUTH_LINK="/readme/docs/authsetup.html"
  else
    AUTH_TITLE="Local Account Management"
    AUTH_DESC="Manage the <a href=\"/readme/docs/authsetup.html#AuthBasicAccountManagement\">local user accounts</a> maintained by Malcolm"
    AUTH_LINK="/auth/"
  fi
  if [[ "${NETBOX_MODE:-local}" == "disabled" ]]; then
    NETBOX_TITLE="NetBox"
    NETBOX_DESC="<a href=\"/readme/docs/asset-interaction-analysis.html\">NetBox</a> is disabled"
    NETBOX_LINK="/readme/docs/asset-interaction-analysis.html"
  elif [[ "${NETBOX_MODE:-local}" == "remote" ]]; then
    NETBOX_TITLE="NetBox"
    NETBOX_DESC="Model and document your <a href=\"/readme/docs/asset-interaction-analysis.html\">network infrastructure</a>"
    NETBOX_LINK="${NETBOX_URL:-#}"
  else
    NETBOX_TITLE="NetBox"
    NETBOX_DESC="Model and document your <a href=\"/readme/docs/asset-interaction-analysis.html\">network infrastructure</a>"
    NETBOX_LINK="/netbox/"
  fi
  for HTML in "$(dirname "$(realpath "${NGINX_LANDING_INDEX_HTML}")")"/*.html; do
    sed -i "s@MALCOLM_DASHBOARDS_NAME_REPLACER@${MALCOLM_DASHBOARDS_NAME}@g" "${HTML}" || true
    sed -i "s@MALCOLM_DASHBOARDS_URL_REPLACER@${MALCOLM_DASHBOARDS_URL}@g" "${HTML}" || true
    sed -i "s@MALCOLM_DASHBOARDS_ICON_REPLACER@${MALCOLM_DASHBOARDS_ICON}@g" "${HTML}" || true
    sed -i "s/MALCOLM_VERSION_REPLACER/v${MALCOLM_VERSION:-unknown} (${VCS_REVISION:-} @ ${BUILD_DATE:-})/g" "${HTML}" || true
    sed -i "s@MALCOLM_AUTH_TITLE_REPLACER@${AUTH_TITLE}@g" "${HTML}" || true
    sed -i "s@MALCOLM_AUTH_DESC_REPLACER@${AUTH_DESC}@g" "${HTML}" || true
    sed -i "s@MALCOLM_AUTH_URL_REPLACER@${AUTH_LINK}@g" "${HTML}" || true
    sed -i "s@MALCOLM_NETBOX_TITLE_REPLACER@${NETBOX_TITLE}@g" "${HTML}" || true
    sed -i "s@MALCOLM_NETBOX_DESC_REPLACER@${NETBOX_DESC}@g" "${HTML}" || true
    sed -i "s@MALCOLM_NETBOX_URL_REPLACER@${NETBOX_LINK}@g" "${HTML}" || true
  done
fi

if [[ "${ARKIME_EXPOSE_WISE_GUI:-true}"  == "true" ]]; then
  ln -sf "$NGINX_ARKIME_WISE_CONF" "$NGINX_ARKIME_WISE_LINK"
else
  ln -sf "$NGINX_BLANK_CONF" "$NGINX_ARKIME_WISE_LINK"
fi

# some cleanup, if necessary
rm -rf /var/log/nginx/* || true

# start supervisor (which will spawn nginx, stunnel, etc.) or whatever the default command is
exec "$@"
