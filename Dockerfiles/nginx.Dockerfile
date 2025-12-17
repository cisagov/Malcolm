# Copyright (c) 2025 Battelle Energy Alliance, LLC.  All rights reserved.

####################################################################################
# first build documentation with jekyll
FROM ghcr.io/mmguero-dev/jekyll:latest as docbuild

ARG GITHUB_TOKEN
ARG VCS_REVISION
ENV VCS_REVISION $VCS_REVISION

ADD --chmod=644 README.md _config.yml Gemfile /site/
ADD _includes/ /site/_includes/
ADD _layouts/ /site/_layouts/
ADD docs/ /site/docs/
ADD --chmod=644 https://use.fontawesome.com/285a5794ed.js /site/_js/fontawesome_285a5794ed.js
ADD --chmod=644 https://use.fontawesome.com/releases/v4.7.0/css/font-awesome-css.min.css /site/_css/font-awesome-css.min.css

WORKDIR /site

# build documentation, remove unnecessary files, then massage a bit to work nicely with NGINX (which will be serving it)
RUN find /site -type f -name "*.md" -exec sed -i "s/{{[[:space:]]*site.github.build_revision[[:space:]]*}}/$VCS_REVISION/g" "{}" \; && \
    ( [ -n "${GITHUB_TOKEN}" ] && export JEKYLL_GITHUB_TOKEN="${GITHUB_TOKEN}" || true ) && \
    sed -i "s/^\(show_downloads:\).*/\1 false/" /site/_config.yml && \
    sed -i "s/^\(offline_mode:\).*/\1 true/" /site/_config.yml && \
    sed -i -e "/^mastodon:/,+2d" /site/_config.yml && \
    sed -i -e "/^reddit:/,+2d" /site/_config.yml && \
    sed -i -e "/^umami:/,+2d" /site/_config.yml && \
    docker-entrypoint.sh bundle exec jekyll build && \
    sh -c 'awk '\'' \
        /window\.FontAwesomeCdnConfig *= *{/ { \
          in_obj = 1; \
          depth = gsub(/{/, "{") - gsub(/}/, "}"); \
          next; \
        } \
        in_obj { \
          depth += gsub(/{/, "{") - gsub(/}/, "}"); \
          if (depth <= 0) in_obj = 0; \
          next; \
        } \
        { print } \
      '\'' /site/_js/fontawesome_285a5794ed.js > /site/_js/fontawesome_clean.js && \
      mv /site/_js/fontawesome_clean.js /site/_js/fontawesome_285a5794ed.js' && \
    mv -v /site/_js/* /site/_site/assets/js/ && \
    mv -v /site/_css/* /site/_site/assets/css/ && \
    rmdir /site/_js /site/_css && \
    find /site/_site -type f -name "*.md" -delete && \
    find /site/_site -type f -name "*.html" -exec sed -i "s@/\(docs\|assets\)@/readme/\1@g" "{}" \; && \
    find /site/_site -type f -name "*.html" -exec sed -i 's@\(href=\)"/"@\1"/readme/"@g' "{}" \;

# build NGINX image
FROM alpine:3.23

LABEL maintainer="malcolm@inl.gov"
LABEL org.opencontainers.image.authors='malcolm@inl.gov'
LABEL org.opencontainers.image.url='https://github.com/idaholab/Malcolm'
LABEL org.opencontainers.image.documentation='https://github.com/idaholab/Malcolm/blob/main/README.md'
LABEL org.opencontainers.image.source='https://github.com/idaholab/Malcolm'
LABEL org.opencontainers.image.vendor='Idaho National Laboratory'
LABEL org.opencontainers.image.title='ghcr.io/idaholab/malcolm/nginx-proxy'
LABEL org.opencontainers.image.description='Malcolm container providing an NGINX reverse proxy for the other services'

ARG DEFAULT_UID=1000
ARG DEFAULT_GID=1000
ENV DEFAULT_UID $DEFAULT_UID
ENV DEFAULT_GID $DEFAULT_GID
ENV PUSER "nginx"
ENV PGROUP "nginx"
# not dropping privileges globally so nginx and stunnel can bind privileged ports internally.
# nginx itself will drop privileges to "nginx" user for worker processes
ENV PUSER_PRIV_DROP false
USER root

ENV TERM xterm

USER root

# encryption method: HTTPS ('true') vs. unencrypted HTTP ('false')
ARG NGINX_SSL=true

# authentication method: basic|ldap|keycloak|keycloak_remote|no_authentication
ARG NGINX_AUTH_MODE=basic

# NGINX LDAP (NGINX_AUTH_MODE=ldap) can support LDAP, LDAPS, or LDAP+StartTLS.
#   For StartTLS, set NGINX_LDAP_TLS_STUNNEL=true to issue the StartTLS command
#   and use stunnel to tunnel the connection.
ARG NGINX_LDAP_TLS_STUNNEL=false

# stunnel will require and verify certificates for StartTLS when one or more
# trusted CA certificate files are placed in the ./nginx/ca-trust directory.
# For additional security, hostname or IP address checking of the associated
# CA certificate(s) can be enabled by providing these values.
# see https://www.stunnel.org/howto.html
#     https://www.openssl.org/docs/man1.1.1/man3/X509_check_host.html
ARG NGINX_LDAP_TLS_STUNNEL_CHECK_HOST=
ARG NGINX_LDAP_TLS_STUNNEL_CHECK_IP=
ARG NGINX_LDAP_TLS_STUNNEL_VERIFY_LEVEL=2

ENV NGINX_SSL $NGINX_SSL
ENV NGINX_AUTH_MODE $NGINX_AUTH_MODE
ENV NGINX_LDAP_TLS_STUNNEL $NGINX_LDAP_TLS_STUNNEL
ENV NGINX_LDAP_TLS_STUNNEL_CHECK_HOST $NGINX_LDAP_TLS_STUNNEL_CHECK_HOST
ENV NGINX_LDAP_TLS_STUNNEL_CHECK_IP $NGINX_LDAP_TLS_STUNNEL_CHECK_IP
ENV NGINX_LDAP_TLS_STUNNEL_VERIFY_LEVEL $NGINX_LDAP_TLS_STUNNEL_VERIFY_LEVEL

# build latest nginx with nginx-auth-ldap
ENV OPENRESTY_VERSION=1.27.1.2
ENV NGINX_AUTH_LDAP_BRANCH=master

# NGINX source
ADD https://codeload.github.com/mmguero-dev/nginx-auth-ldap/tar.gz/$NGINX_AUTH_LDAP_BRANCH /nginx-auth-ldap.tar.gz
ADD https://openresty.org/download/openresty-$OPENRESTY_VERSION.tar.gz /openresty.tar.gz


# component icons from original sources and stuff for offline landing page
ADD https://opensearch.org/wp-content/uploads/2025/01/opensearch_logo_default.svg /usr/share/nginx/html/assets/img/
ADD https://opensearch.org/wp-content/uploads/2025/01/opensearch_logo_darkmode.svg /usr/share/nginx/html/assets/img/
ADD https://opensearch.org/wp-content/uploads/2025/01/opensearch_mark_default.svg /usr/share/nginx/html/assets/img/
ADD https://opensearch.org/wp-content/uploads/2025/01/opensearch_mark_darkmode.svg /usr/share/nginx/html/assets/img/
ADD https://raw.githubusercontent.com/gchq/CyberChef/master/src/web/static/images/logo/cyberchef.svg /usr/share/nginx/html/assets/img/
ADD https://raw.githubusercontent.com/netbox-community/netbox/main/netbox/project-static/img/netbox_icon.svg /usr/share/nginx/html/assets/img/
ADD https://fonts.gstatic.com/s/lato/v24/S6u_w4BMUTPHjxsI9w2_Gwfo.ttf /usr/share/nginx/html/css/
ADD https://fonts.gstatic.com/s/lato/v24/S6u8w4BMUTPHjxsAXC-v.ttf /usr/share/nginx/html/css/
ADD https://fonts.gstatic.com/s/lato/v24/S6u_w4BMUTPHjxsI5wq_Gwfo.ttf /usr/share/nginx/html/css/
ADD https://fonts.gstatic.com/s/lato/v24/S6u9w4BMUTPHh7USSwiPHA.ttf /usr/share/nginx/html/css/
ADD https://fonts.gstatic.com/s/lato/v24/S6uyw4BMUTPHjx4wWw.ttf /usr/share/nginx/html/css/
ADD https://fonts.gstatic.com/s/lato/v24/S6u9w4BMUTPHh6UVSwiPHA.ttf /usr/share/nginx/html/css/
ADD 'https://cdn.jsdelivr.net/npm/bootstrap-icons@1.13.1/font/fonts/bootstrap-icons.woff2' /usr/share/nginx/html/css/bootstrap-icons.woff2
ADD 'https://cdn.jsdelivr.net/npm/bootstrap-icons@1.13.1/font/fonts/bootstrap-icons.woff' /usr/share/nginx/html/css/bootstrap-icons.woff
ADD 'https://cdn.jsdelivr.net/npm/bootstrap-icons@1.13.1/font/bootstrap-icons.css' /usr/share/nginx/html/css/bootstrap-icons.css
ADD 'https://use.fontawesome.com/releases/v4.7.0/fonts/fontawesome-webfont.eot' /usr/share/nginx/html/css/
ADD 'https://use.fontawesome.com/releases/v4.7.0/fonts/fontawesome-webfont.woff2' /usr/share/nginx/html/css/
ADD 'https://use.fontawesome.com/releases/v4.7.0/fonts/fontawesome-webfont.woff' /usr/share/nginx/html/css/
ADD 'https://use.fontawesome.com/releases/v4.7.0/fonts/fontawesome-webfont.ttf' /usr/share/nginx/html/css/
ADD 'https://use.fontawesome.com/releases/v4.7.0/fonts/fontawesome-webfont.svg#fontawesomeregular' /usr/share/nginx/html/css/fontawesome-webfont.svg

ADD --chmod=644 nginx/requirements.txt /usr/local/src/requirements.txt

RUN set -x ; \
    CONFIG="\
    --prefix=/usr/local/openresty \
    --sbin-path=/usr/sbin/nginx \
    --modules-path=/usr/lib/nginx/modules \
    --conf-path=/etc/nginx/nginx.conf \
    --error-log-path=/var/log/nginx/error.log \
    --http-log-path=/var/log/nginx/access.log \
    --pid-path=/var/run/nginx.pid \
    --lock-path=/var/run/nginx.lock \
    --http-client-body-temp-path=/var/cache/nginx/client_temp \
    --http-proxy-temp-path=/var/cache/nginx/proxy_temp \
    --http-fastcgi-temp-path=/var/cache/nginx/fastcgi_temp \
    --http-uwsgi-temp-path=/var/cache/nginx/uwsgi_temp \
    --http-scgi-temp-path=/var/cache/nginx/scgi_temp \
    --user=${PUSER} \
    --group=${PGROUP} \
    --with-http_ssl_module \
    --with-http_realip_module \
    --with-http_addition_module \
    --with-http_sub_module \
    --with-http_dav_module \
    --with-http_gunzip_module \
    --with-http_gzip_static_module \
    --with-http_random_index_module \
    --with-http_secure_link_module \
    --with-http_stub_status_module \
    --with-http_auth_request_module \
    --with-http_xslt_module=dynamic \
    --with-http_geoip_module=dynamic \
    --with-http_perl_module=dynamic \
    --with-luajit \
    --with-threads \
    --with-stream \
    --with-stream_ssl_module \
    --with-stream_ssl_preread_module \
    --with-stream_realip_module \
    --with-stream_geoip_module=dynamic \
    --with-http_slice_module \
    --with-mail \
    --with-mail_ssl_module \
    --with-pcre-jit \
    --with-compat \
    --with-file-aio \
    --with-http_v2_module \
    --add-module=/usr/src/nginx-auth-ldap \
  " ; \
  apk update --no-cache; \
  apk upgrade --no-cache; \
  apk add --no-cache curl rsync shadow openssl; \
  addgroup -g ${DEFAULT_GID} -S ${PGROUP} ; \
  adduser -S -D -H -u ${DEFAULT_UID} -h /var/cache/nginx -s /sbin/nologin -G ${PGROUP} -g ${PUSER} ${PUSER} ; \
  addgroup ${PUSER} shadow ; \
  mkdir -p /var/cache/nginx ; \
  chown ${PUSER}:${PGROUP} /var/cache/nginx ; \
  apk add --no-cache --virtual .nginx-build-deps \
    autoconf \
    automake \
    cmake \
    g++ \
    gcc \
    geoip-dev \
    git \
    gnupg \
    libbsd-dev \
    libc-dev \
    libtool \
    libxslt-dev \
    linux-headers \
    luajit-dev \
    make \
    openldap-dev \
    openssl-dev \
    pcre-dev \
    perl-dev \
    py3-pip \
    py3-setuptools \
    py3-wheel \
    tar \
    zlib-dev \
    ; \
    \
  mkdir -p /usr/src/nginx-auth-ldap /www /www/logs/nginx /var/log/nginx ; \
  tar -zxC /usr/src -f /openresty.tar.gz ; \
  tar -zxC /usr/src/nginx-auth-ldap --strip=1 -f /nginx-auth-ldap.tar.gz ; \
  cd /usr/src/openresty-$OPENRESTY_VERSION ; \
  ./configure $CONFIG ; \
  make -j$(getconf _NPROCESSORS_ONLN) ; \
  make install ; \
  rm -rf /etc/nginx/html/ ; \
  mkdir -p /etc/nginx/conf.d/ /etc/nginx/templates/ /etc/nginx/auth/ /usr/share/nginx/html/ ; \
  ln -s /usr/local/openresty/bin/openresty /usr/sbin/nginx ; \
  ln -s ../../usr/lib/nginx/modules /etc/nginx/modules ; \
  strip /usr/sbin/nginx* ; \
  strip /usr/lib/nginx/modules/*.so ; \
  rm -rf /usr/src/openresty-$OPENRESTY_VERSION ; \
  \
  # Bring in gettext so we can get `envsubst`, then throw
  # the rest away. To do this, we need to install `gettext`
  # then move `envsubst` out of the way so `gettext` can
  # be deleted completely, then move `envsubst` back.
  apk add --no-cache --virtual .gettext gettext ; \
  mv /usr/bin/envsubst /tmp/ ; \
  \
  runDeps="$( \
    scanelf --needed --nobanner /usr/sbin/nginx /usr/lib/nginx/modules/*.so /tmp/envsubst \
      | awk '{ gsub(/,/, "\nso:", $2); print "so:" $2 }' \
      | sort -u \
      | xargs -r apk info --installed \
      | sort -u \
  )" ; \
  apk add --no-cache --virtual .nginx-rundeps $runDeps \
    apache2-utils \
    bash \
    ca-certificates \
    jq \
    libbsd \
    luajit \
    openldap \
    python3 \
    shadow \
    stunnel \
    tini \
    tzdata \
    wget; \
  update-ca-certificates; \
  # trying to solve "no session state" error:
  # https://github.com/zmartzone/lua-resty-openidc/issues/514#issuecomment-2123720551
  /usr/local/openresty/bin/opm install ledgetech/lua-resty-http ; \
  /usr/local/openresty/bin/opm install bungle/lua-resty-session=3.10 ; \
  /usr/local/openresty/bin/opm install cdbattags/lua-resty-jwt ; \
  /usr/local/openresty/bin/opm install zmartzone/lua-resty-openidc ; \
  cd /usr/local/src/ ; \
    pip3 install --break-system-packages --no-compile --no-cache-dir -r ./requirements.txt ; \
  apk del .nginx-build-deps ; \
  apk del .gettext ; \
  mv /tmp/envsubst /usr/local/bin/ ; \
  rm -rf /usr/src/* /usr/local/src/* /var/tmp/* /var/cache/apk/* /openresty.tar.gz /nginx-auth-ldap.tar.gz ; \
  touch /etc/nginx/nginx_ldap.conf /etc/nginx/nginx_blank.conf ; \
  find /usr/share/nginx/html/ -type d -exec chmod 755 "{}" \; ; \
  find /usr/share/nginx/html/ -type f -exec chmod 644 "{}" \; ; \
  cd /usr/share/nginx/html/assets/img ; \
  ln -s ./Malcolm_background.png ./bg-masthead.png ; \
  sed -i '/bootstrap-icons\.woff/ { s|\./fonts/|./|g; s|[?][^")]*||g }' /usr/share/nginx/html/css/bootstrap-icons.css

COPY --from=docbuild /site/_site /usr/share/nginx/html/readme

ADD nginx/landingpage /usr/share/nginx/html
ADD --chmod=755 shared/bin/docker-uid-gid-setup.sh /usr/local/bin/
ADD --chmod=755 container-health-scripts/nginx.sh /usr/local/bin/container_health.sh
ADD nginx/scripts /usr/local/bin/
ADD --chmod=644 nginx/*.conf /etc/nginx/
ADD --chmod=644 nginx/lua/*.lua /usr/local/openresty/lualib/
ADD nginx/templates /etc/nginx/templates/
ADD --chmod=644 nginx/supervisord.conf /etc/
ADD --chmod=644 docs/images/favicon/*.png /usr/share/nginx/html/assets/img/
ADD --chmod=644 docs/images/icon/*.png /usr/share/nginx/html/assets/img/
ADD --chmod=644 docs/images/icon/*.svg /usr/share/nginx/html/assets/img/
ADD --chmod=644 docs/images/icon/favicon.ico /usr/share/nginx/html/assets/favicon.ico
ADD --chmod=644 docs/images/icon/favicon.ico /usr/share/nginx/html/favicon.ico
ADD --chmod=644 docs/images/logo/*.png /usr/share/nginx/html/assets/img/
ADD --chmod=644 docs/images/logo/*.svg /usr/share/nginx/html/assets/img/

VOLUME ["/etc/nginx/certs", "/etc/nginx/dhparam"]

ENTRYPOINT ["/sbin/tini", \
            "--", \
            "/usr/local/bin/docker-uid-gid-setup.sh", \
            "/usr/local/bin/docker_entrypoint.sh"]

CMD ["/usr/bin/supervisord", "-c", "/etc/supervisord.conf", "-u", "root", "-n"]


# to be populated at build-time:
ARG BUILD_DATE
ARG MALCOLM_VERSION
ARG VCS_REVISION
ENV BUILD_DATE $BUILD_DATE
ENV MALCOLM_VERSION $MALCOLM_VERSION
ENV VCS_REVISION $VCS_REVISION

LABEL org.opencontainers.image.created=$BUILD_DATE
LABEL org.opencontainers.image.version=$MALCOLM_VERSION
LABEL org.opencontainers.image.revision=$VCS_REVISION
