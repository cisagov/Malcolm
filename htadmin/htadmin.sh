#!/usr/bin/env bash

HTADMIN_ENABLED=${NGINX_BASIC_AUTH:-"true"}

if [[ "$HTADMIN_ENABLED" == "true" ]]; then
  sleep 10
  nginx -g "daemon off;"
else
  mkdir -p /tmp/htadmin_disabled
    pushd /tmp/htadmin_disabled >/dev/null 2>&1 && \
    cat << EOF > index.html
      <html>
      <header><title>Basic Authentication Disabled</title></header>
      <body>
      <h1>Basic HTTP authentication has been disabled.</h1>
      <p>Refer to the <a href="/readme#AuthLDAP" onclick="javascript:event.target.port=443">Malcolm documentation</a> for details on LDAP authentication.</p>
      </body>
      </html>
EOF
  python -m SimpleHTTPServer 80
  popd >/dev/null 2>&1
fi