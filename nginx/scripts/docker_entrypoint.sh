#!/bin/bash
set -e

# Warn if the DOCKER_HOST socket does not exist
if [[ $DOCKER_HOST = unix://* ]]; then
  socket_file=${DOCKER_HOST#unix://}
  if ! [ -S $socket_file ]; then
    cat >&2 <<-EOT
  ERROR: you need to share your Docker host socket with a volume at $socket_file
  Typically you should run your container with: \`-v /var/run/docker.sock:$socket_file:ro\`
  See the jwilder/nginx-proxy documentation at http://git.io/vZaGJ
EOT
    socketMissing=1
  fi
fi

# Compute the DNS resolvers for use in the templates - if the IP contains ":", it's IPv6 and must be enclosed in []
export RESOLVERS=$(awk '$1 == "nameserver" {print ($2 ~ ":")? "["$2"]": $2}' ORS=' ' /etc/resolv.conf | sed 's/ *$//g')
if [ "x$RESOLVERS" = "x" ]; then
    echo "Warning: unable to determine DNS resolvers for nginx" >&2
    unset RESOLVERS
fi

# If the user has run the default command and the socket doesn't exist, fail
if [ "$socketMissing" = 1 -a "$1" = 'supervisord' -a "$2" = '-c' -a "$3" = '/etc/supervisord.conf' ]; then
  exit 1
fi

# set up for NGINX HTTP basic vs. LDAP/LDAPS/LDAP+StartTLS auth

# a blank file just to use as an "include" placeholder for the nginx's LDAP config when LDAP is not used
NGINX_BLANK_CONF=/etc/nginx/nginx_blank.conf

# "include" file for auth_basic, prompt, and .htpasswd location
NGINX_BASIC_AUTH_CONF=/etc/nginx/nginx_auth_basic.conf

# "include" file for auth_ldap, prompt, and "auth_ldap_servers" name
NGINX_LDAP_AUTH_CONF=/etc/nginx/nginx_auth_ldap.conf

# volume-mounted user configuration containing "ldap_server ad_server" section with URL, binddn, etc.
NGINX_LDAP_USER_CONF=/etc/nginx/nginx_ldap.conf

# runtime "include" file for auth method (link to either NGINX_BASIC_AUTH_CONF or NGINX_LDAP_AUTH_CONF)
NGINX_RUNTIME_AUTH_CONF=/etc/nginx/nginx_auth_rt.conf

# runtime "include" file for ldap config (link to either NGINX_BLANK_CONF or (possibly modified) NGINX_LDAP_USER_CONF)
NGINX_RUNTIME_LDAP_CONF=/etc/nginx/nginx_ldap_rt.conf

# config file for stunnel if using stunnel to issue LDAP StartTLS function
STUNNEL_CONF=/etc/stunnel/stunnel.conf

if [[ -z $NGINX_BASIC_AUTH ]] || [[ "$NGINX_BASIC_AUTH" == "true" ]]; then
  # doing HTTP basic auth instead of ldap

  # point nginx_auth_rt.conf to nginx_auth_basic.conf
  ln -sf "$NGINX_BASIC_AUTH_CONF" "$NGINX_RUNTIME_AUTH_CONF"

  # ldap configuration is empty
  ln -sf "$NGINX_BLANK_CONF" "$NGINX_RUNTIME_LDAP_CONF"

else
  # point nginx_auth_rt.conf to nginx_auth_ldap.conf
  ln -sf "$NGINX_LDAP_AUTH_CONF" "$NGINX_RUNTIME_AUTH_CONF"

  if [[ "$NGINX_LDAP_TLS_STUNNEL" == "true" ]]; then
    # user provided LDAP configuration, but we need to tweak it and set up stunnel to issue StartTLS

    # parse URL out of user ldap configuration to set up stunnel
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

    if [[ -z $REMOTE_HOST ]]; then
      # missing LDAP info needed to configure tunnel, abort
      exit 1
    fi

    # pick a random local port to listen on for the client side of the tunnel
    read PORT_LOWER POWER_UPPER < /proc/sys/net/ipv4/ip_local_port_range
    LOCAL_PORT=$(shuf -i $PORT_LOWER-$POWER_UPPER -n 1)
    LDAP_PROTOCOL=${NGINX_LDAP_TLS_STUNNEL_PROTOCOL:-"winldap"}

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
cert = /etc/stunnel/stunnel.pem
foreground = yes

[stunnel.ldap_start_tls]
accept = localhost:$LOCAL_PORT
connect = $REMOTE_HOST:$REMOTE_PORT
protocol = $LDAP_PROTOCOL
EOF

    # rewrite modified copy of user ldap configuration to point to local end of tunnel instead of remote
    rm -f "$NGINX_RUNTIME_LDAP_CONF"
    touch "$NGINX_RUNTIME_LDAP_CONF"
    READ_LINE_NUM=0
    while IFS= read -r LINE; do
      READ_LINE_NUM=$((READ_LINE_NUM+1))
      if (( $URL_LINE_NUM == $READ_LINE_NUM )); then
        echo "${HEADER}${OPEN_QUOTE}ldap://localhost:${LOCAL_PORT}${URI_TO_END}" >> "$NGINX_RUNTIME_LDAP_CONF"
      else
        echo "$LINE" >> "$NGINX_RUNTIME_LDAP_CONF"
      fi
    done < "$NGINX_LDAP_USER_CONF"

  else
    # we're doing either LDAP or LDAPS, but not StartTLS, so we don't need to use stunnel.
    # leave LDAP configuration as the user specified without modifications.
    ln -sf "$NGINX_LDAP_USER_CONF" "$NGINX_RUNTIME_LDAP_CONF"
  fi

fi

# start supervisor (which will spawn nginx, stunnel, etc.) or whatever the default command is
exec "$@"
