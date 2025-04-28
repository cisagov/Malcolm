#!/usr/bin/env bash

# htadmin also runs with keycloak selected as the auth mode, as the OpenSearch API endpoint is not (yet) compatible
if [[ "${NGINX_AUTH_MODE:-basic}" =~ ^(true|basic|keycloak|keycloak_remote)$ ]]; then

  cat >/var/www/htadmin/config/config.ini <<EOF
; HTAdmin config file (dynamically generated $(date "+%Y-%m-%d_%H:%M:%S"))

[application]
app_title = ${MALCOLM_HTADMIN_TITLE:-Malcolm User Management}

secure_path  = ./auth/htpasswd
metadata_path  = ./config/metadata

; administrator user/password (htpasswd -b -c -B ...)
admin_user = ${MALCOLM_USERNAME:-}

min_username_len = ${MIN_USERNAME_LEN:-4}
max_username_len = ${MAX_USERNAME_LEN:-32}

min_password_len = ${MIN_PASSWORD_LEN:-8}
max_password_len = ${MAX_PASSWORD_LEN:-128}
EOF
  [[ -n ${PUID} ]] && chown -f ${PUID} /var/www/htadmin/config/config.ini
  [[ -n ${PGID} ]] && chown -f :${PGID} /var/www/htadmin/config/config.ini

  if [[ ! -f /var/www/htadmin/config/metadata ]] && [[ -f /var/www/htadmin/default/metadata ]]; then
    cp /var/www/htadmin/default/metadata /var/www/htadmin/config/metadata
    [[ -n ${PUID} ]] && chown -f ${PUID} /var/www/htadmin/config/metadata
    [[ -n ${PGID} ]] && chown -f :${PGID} /var/www/htadmin/config/metadata
  fi

  sleep 10
  nginx -g "daemon off;"

else
  /usr/local/bin/service_check_passthrough.sh -d -s htadmin -p 80 -f http
fi
