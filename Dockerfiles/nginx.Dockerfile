# syntax=docker/dockerfile:1
# Copyright (c) 2026 Battelle Energy Alliance, LLC.  All rights reserved.

####################################################################################
# first build documentation with jekyll
FROM ghcr.io/mmguero-dev/jekyll:latest@sha256:8649ddf866df7b79d1d297b3b6eaff91cde1fbde01f1f4406625e254584c9eca AS docbuild

ARG VCS_REVISION
ENV VCS_REVISION=$VCS_REVISION

ADD --chmod=644 README.md _config.yml Gemfile /site/
ADD _includes/ /site/_includes/
ADD _layouts/ /site/_layouts/
ADD docs/ /site/docs/
ADD --chmod=644 https://use.fontawesome.com/285a5794ed.js /site/_js/fontawesome_285a5794ed.js
ADD --chmod=644 https://use.fontawesome.com/releases/v4.7.0/css/font-awesome-css.min.css /site/_css/font-awesome-css.min.css

WORKDIR /site

# build documentation, remove unnecessary files, then massage a bit to work nicely with NGINX (which will be serving it)
#   GITHUB_TOKEN is provided as a build secret (not a build argument) so it is not recorded in the image history
RUN --mount=type=secret,id=GITHUB_TOKEN,env=JEKYLL_GITHUB_TOKEN \
    find /site -type f -name "*.md" -exec sed -i "s/{{[[:space:]]*site.github.build_revision[[:space:]]*}}/$VCS_REVISION/g" "{}" \; && \
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

# obtain openresty source code bundle from download site or Git
FROM alpine:3.24 AS getresty

# OPENRESTY_VERSION can be like "1.29.2.4" or "318a52b814ef903066002ffa3166b7714b3b9c6f"
ARG OPENRESTY_VERSION=1.31.8.1
ENV OPENRESTY_VERSION=$OPENRESTY_VERSION
# SHA-256 of openresty-${OPENRESTY_VERSION}.tar.gz; only used for release versions (a commit checkout is verified by git)
ARG OPENRESTY_SHA256=b569c63b420f80a4ac8466f2deffe73ed93ab760026532e039c3658409a997f4

RUN set -e; \
    apk update --no-cache; \
    mkdir -p /usr/local/src/openresty; \
    cd /usr/local/src/openresty; \
    if echo "${OPENRESTY_VERSION}" | grep -qE '^[0-9]+\.[0-9]+(\.[0-9]+)*$'; then \
        echo "Downloading OpenResty: ${OPENRESTY_VERSION}"; \
        for i in 1 2 3; do wget -O "./openresty.tar.gz" "https://openresty.org/download/openresty-${OPENRESTY_VERSION}.tar.gz" && break; sleep 5; done; \
        echo "${OPENRESTY_SHA256}  ./openresty.tar.gz" | sha256sum -c -; \
    elif echo "${OPENRESTY_VERSION}" | grep -qE '^[0-9a-f]{40}$'; then \
        apk add --no-cache bash dos2unix git make mercurial patch perl; \
        echo "Checking out OpenResty: ${OPENRESTY_VERSION}"; \
        git clone --no-checkout https://github.com/openresty/openresty.git; \
        cd openresty; \
        git checkout "${OPENRESTY_VERSION}"; \
        make; \
        mv openresty-*.tar.gz ../openresty.tar.gz; \
    else \
        echo "ERROR: Unrecognized OPENRESTY_VERSION format: ${OPENRESTY_VERSION}" >&2; \
        exit 1; \
    fi

# build NGINX image
FROM alpine:3.24

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
ENV DEFAULT_UID=$DEFAULT_UID
ENV DEFAULT_GID=$DEFAULT_GID
ENV PUSER="nginx"
ENV PGROUP="nginx"
# not dropping privileges globally so nginx and stunnel can bind privileged ports internally.
# nginx itself will drop privileges to "nginx" user for worker processes
ENV PUSER_PRIV_DROP=false
USER root

ENV TERM=xterm

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

ENV NGINX_SSL=$NGINX_SSL
ENV NGINX_AUTH_MODE=$NGINX_AUTH_MODE
ENV NGINX_LDAP_TLS_STUNNEL=$NGINX_LDAP_TLS_STUNNEL
ENV NGINX_LDAP_TLS_STUNNEL_CHECK_HOST=$NGINX_LDAP_TLS_STUNNEL_CHECK_HOST
ENV NGINX_LDAP_TLS_STUNNEL_CHECK_IP=$NGINX_LDAP_TLS_STUNNEL_CHECK_IP
ENV NGINX_LDAP_TLS_STUNNEL_VERIFY_LEVEL=$NGINX_LDAP_TLS_STUNNEL_VERIFY_LEVEL

# Build OpenResty with an immutable nginx-auth-ldap revision.
# This module executes inside the authentication reverse proxy. BuildKit must
# reject changed source archives rather than building an unverified branch HEAD.
# Update the revision and SHA-256 together when upgrading the LDAP module.
ARG NGINX_AUTH_LDAP_REVISION=394261b38c77ef692d98e9a05d28843b5a355921

# Lua modules for OpenID Connect (Keycloak auth), fetched from GitHub instead of
# opm. Each is pinned to an immutable commit and verified by BuildKit against
# the SHA-256 below; update the revision and SHA-256 together when upgrading.
# Dependency graph, verified against the rockspecs at the pinned revisions:
#   lua-resty-openidc 1.9.3  -> lua-resty-http    >= 0.08
#                            -> lua-resty-session == 4.2.0-1   (equality, not a floor)
#                            -> lua-resty-jwt     >= 0.2.0
#                            -> lua-resty-openssl >= 1.8.0
#   lua-resty-session 4.2.0  -> lua-ffi-zlib      >= 0.5
#                            -> lua-resty-openssl >= 1.5.0
#   lua-resty-jwt     0.3.2  -> lua-resty-openssl >= 0.6.8
#   lua-resty-openssl 1.8.0  -> (none)
#   lua-resty-http    0.17.1 -> (none)
#   lua-resty-hmac    0.06-1 -> (none)
# lua-resty-openssl 1.8.0 therefore satisfies all three openssl floors, the
#   >= 1.8.0 from openidc being the binding one.
# NOTE: lua-resty-jwt no longer declares lua-resty-hmac; it vendors its own copy
#   at third-party/lua-resty-hmac/lib/resty/hmac.lua, which the lib/-only copy
#   loop below does NOT install. The separate jkeys089 pin is what actually
#   provides resty.hmac. If jwt ever moves that file under lib/, two tarballs
#   would write the same path and glob order would decide the winner.
# Re-read every rockspec on each openidc bump: nothing in this build resolves or
#   validates these constraints at image build time.
# To get a revision and checksum for a tag:
#   pin() { local repo="$1" ref="$2" sha; \
#     sha="$(git ls-remote "https://github.com/${repo}" "refs/tags/${ref}" "refs/tags/${ref}^{}" | tail -n1 | cut -f1)"; \
#     echo "${repo} ${ref} ${sha} $(curl -fsSL "https://codeload.github.com/${repo}/tar.gz/${sha}" | sha256sum | cut -d' ' -f1)"; }
# pin ledgetech/lua-resty-http v0.17.1
# Satisfies openidc 1.9.3's ">= 0.08" with room to spare, so deliberately NOT
#   bumped here. Unlike the other Lua modules, Malcolm calls this one directly
#   (nginx_auth_keycloak_basic.conf and nginx_auth_helpers.lua use
#   http.new/request_uri/set_keepalive), so bump it on its own commit and re-test
#   the NGINX_KEYCLOAK_BASIC_AUTH service-account path when you do.
ARG LUA_RESTY_HTTP_REVISION=4ab4269cf442ba52507aa2c718f606054452fcad
# pin bungle/lua-resty-session v4.2.0
# openidc 1.9.3's rockspec requires EXACTLY lua-resty-session 4.2.0-1 ("=="), so
#   this is not independently upgradable -- it moves only when openidc moves.
#   openidc 1.7.x required session 3.x, so the two MUST be bumped together.
# The 4.x session_opts schema is flat (cookie_secure/cookie_same_site/...) rather
#   than 3.x's nested cookie={...} table, and 4.x silently ignores unknown keys,
#   so a stale 3.x-shaped table yields a session cookie with no Secure flag and
#   no error. See nginx/nginx_auth_keycloak.conf.
#   Background: https://github.com/zmartzone/lua-resty-openidc/issues/514
ARG LUA_RESTY_SESSION_REVISION=9c7e43735b62819b69927b3104c9e1f47696c30a
# pin fffonion/lua-resty-openssl 1.8.0
# Required directly by openidc 1.9.3 (>= 1.8.0), by session 4.2.0 (>= 1.5.0) and
#   by jwt (>= 0.6.8). 1.8.0 is the tightest floor, so this sits exactly on it.
#   Declares no dependencies of its own, but it is a LuaJIT FFI binding to
#   libssl/libcrypto: check its README compatibility matrix against the OpenSSL
#   the OpenResty build above links, since the rockspec constrains nothing there.
ARG LUA_RESTY_OPENSSL_REVISION=16faff4c825eab8d5a78cfabe07adec69d9e2fa5
# pin hamishforbes/lua-ffi-zlib v0.6
# Required by lua-resty-session 4.2.0 (>= 0.5) for session payload compression.
#   Transitive via session, so openidc's own rockspec never names it. Easy to
#   miss, and if session loads it lazily a missing pin would surface on the first
#   login rather than at build time -- hence the explicit require in the smoke
#   test below.
ARG LUA_FFI_ZLIB_REVISION=61e95cb434e4047c8bc65a180c293a05bf754416
# jkeys089/lua-resty-hmac 0.06-1 (rockspec package name is lua-resty-hmac-ffi).
#   No longer declared by lua-resty-jwt, but still the only installed source of
#   resty.hmac, which jwt lists in its build.modules. Verify that
#   lib/resty/jwt.lua at LUA_RESTY_JWT_REVISION really does require it before
#   considering this pin removable.
ARG LUA_RESTY_HMAC_REVISION=23da759b69f208576526c8ac21b7c5ad66740321
# cdbattags/lua-resty-jwt v0.3.2 (satisfies openidc 1.9.3's ">= 0.2.0").
#   NB: this repo only carries a dev-0 rockspec (source = "file://."), so its
#   declared dependencies are indicative rather than release-accurate.
ARG LUA_RESTY_JWT_REVISION=fc0ddeb009e42740506a848552631efc3a24a19e
# pin zmartzone/lua-resty-openidc v1.9.3
ARG LUA_RESTY_OPENIDC_REVISION=a4755bffdfe7b122123c972ce5820529c3e83fdc

# NGINX source
COPY --from=getresty /usr/local/src/openresty/openresty.tar.gz /openresty.tar.gz
ADD --checksum=sha256:925d2b368db64d4bee6b17bb5b1958c44d20a1b945ac194f1db4fdd551614743 https://codeload.github.com/mmguero-dev/nginx-auth-ldap/tar.gz/$NGINX_AUTH_LDAP_REVISION /nginx-auth-ldap.tar.gz

# Lua module sources (see revisions above)
ADD --checksum=sha256:89384290054663289026f7072d49a670ae5be04c8c916537a6df3834bb783a61 https://codeload.github.com/ledgetech/lua-resty-http/tar.gz/$LUA_RESTY_HTTP_REVISION /lua-src/lua-resty-http.tar.gz
ADD --checksum=sha256:97f9536a3ef61a3e4a007294d5f2f9bbc566ea715689b5a5ebc2c07703516d97 https://codeload.github.com/bungle/lua-resty-session/tar.gz/$LUA_RESTY_SESSION_REVISION /lua-src/lua-resty-session.tar.gz
ADD --checksum=sha256:74c470302ca13cb7d6940cf986c2212b9ec524d4f10c5391c32a262bc3a14290 https://codeload.github.com/fffonion/lua-resty-openssl/tar.gz/$LUA_RESTY_OPENSSL_REVISION /lua-src/lua-resty-openssl.tar.gz
ADD --checksum=sha256:664c5b40d4fefce3c4566f209377d23c9e42e1ac342df314944241aa8e3000bb https://codeload.github.com/hamishforbes/lua-ffi-zlib/tar.gz/$LUA_FFI_ZLIB_REVISION /lua-src/lua-ffi-zlib.tar.gz
ADD --checksum=sha256:e15c6441d29f4289ed1ec205363c19f7cce989a95a70a650b6e4d0b2a2a57126 https://codeload.github.com/jkeys089/lua-resty-hmac/tar.gz/$LUA_RESTY_HMAC_REVISION /lua-src/lua-resty-hmac.tar.gz
ADD --checksum=sha256:f71e8ed92998c87368f2d57937c4baad4c1fe7d4786bc89db799a83317cd6553 https://codeload.github.com/cdbattags/lua-resty-jwt/tar.gz/$LUA_RESTY_JWT_REVISION /lua-src/lua-resty-jwt.tar.gz
ADD --checksum=sha256:f6c1f81bfcf8988b6f9e0547d864c6abb06a95afd780dae08d0b9cfd26fbd0ab https://codeload.github.com/zmartzone/lua-resty-openidc/tar.gz/$LUA_RESTY_OPENIDC_REVISION /lua-src/lua-resty-openidc.tar.gz

# component icons from original sources and stuff for offline landing page
ADD --checksum=sha256:44e0882ef03a40fefc148bab511a9b6bbc394c1865500206f6532f66bf4f4482 https://opensearch.org/wp-content/uploads/2025/01/opensearch_logo_default.svg /usr/share/nginx/html/assets/img/
ADD --checksum=sha256:f08d2b1bcc9fa3aa5fa450d8d06087ae64f611ea3dfe084e5db8b29a2f9f8090 https://opensearch.org/wp-content/uploads/2025/01/opensearch_logo_darkmode.svg /usr/share/nginx/html/assets/img/
ADD --checksum=sha256:d89d0555a75fa2c745bfdd782589cc17ce596d3fd41e5008bef8ff3fec695bc8 https://opensearch.org/wp-content/uploads/2025/01/opensearch_mark_default.svg /usr/share/nginx/html/assets/img/
ADD --checksum=sha256:72c3cc4bdb44fe9bc567d1345aa8a00d3ee059ce23f38248c067dc580448821d https://opensearch.org/wp-content/uploads/2025/01/opensearch_mark_darkmode.svg /usr/share/nginx/html/assets/img/
# Both icons use immutable source revisions, with BuildKit verifying content
# against SHA-256 digests committed in this Dockerfile.
ADD --checksum=sha256:1164d73b01454118b28a3200ed04c4f8e8dc7f67ef8faa9243cc142e92971812 https://raw.githubusercontent.com/gchq/CyberChef/609951ac13967da6d497e0600c922f56bfd0b7af/src/web/static/images/logo/cyberchef.svg /usr/share/nginx/html/assets/img/
ADD --checksum=sha256:a80e71eca8315be12d1f005ed68847f7c7aed8b9bf71dabf8479cd40b96abae6 https://raw.githubusercontent.com/netbox-community/netbox/74cb44fabed082aaacd841c984f2dbb435b0833d/netbox/project-static/img/netbox_icon.svg /usr/share/nginx/html/assets/img/
ADD --checksum=sha256:287f2b0a046343d811ae43312783880cba0e09850886d6dcdd57a73f65147f01 https://fonts.gstatic.com/s/lato/v24/S6u_w4BMUTPHjxsI9w2_Gwfo.ttf /usr/share/nginx/html/css/
ADD --checksum=sha256:218f6f647f83ceec4b0995a5186404d9fc4a5fb5c535d0cdd016bf52afbb5e7e https://fonts.gstatic.com/s/lato/v24/S6u8w4BMUTPHjxsAXC-v.ttf /usr/share/nginx/html/css/
ADD --checksum=sha256:726beec7cd96f06f5b05b5af54d47321b6270f94e21f4a3bdc80cefc3b79ba69 https://fonts.gstatic.com/s/lato/v24/S6u_w4BMUTPHjxsI5wq_Gwfo.ttf /usr/share/nginx/html/css/
ADD --checksum=sha256:b229d664a58a75e0a438fad204b292b5777e79fafd4b840cce21bac7ad2a7a28 https://fonts.gstatic.com/s/lato/v24/S6u9w4BMUTPHh7USSwiPHA.ttf /usr/share/nginx/html/css/
ADD --checksum=sha256:b6e055ad6056d64c89133fd73e9ee935c068d8bd3ac09366d5d99f9eee99e3f4 https://fonts.gstatic.com/s/lato/v24/S6uyw4BMUTPHjx4wWw.ttf /usr/share/nginx/html/css/
ADD --checksum=sha256:7e15d8482756e9d79c5b14dde8cd92256fd2afe0307703d825d4e8178d416c41 https://fonts.gstatic.com/s/lato/v24/S6u9w4BMUTPHh6UVSwiPHA.ttf /usr/share/nginx/html/css/
ADD --checksum=sha256:6c75710364a1ca5604267716f6d28997b26319fdb078cf11e0b42ab66ff2ea61 'https://cdn.jsdelivr.net/npm/bootstrap-icons@1.13.1/font/fonts/bootstrap-icons.woff2' /usr/share/nginx/html/css/bootstrap-icons.woff2
ADD --checksum=sha256:f55513b7b591cb84a3b87ff0e34ea24d4831d6fedc22e54b911ca64b5b544a15 'https://cdn.jsdelivr.net/npm/bootstrap-icons@1.13.1/font/fonts/bootstrap-icons.woff' /usr/share/nginx/html/css/bootstrap-icons.woff
ADD --checksum=sha256:004322721c8557331759bc6ddaacbb689b0f0715d688aec82bd056d2d5b5cc3b 'https://cdn.jsdelivr.net/npm/bootstrap-icons@1.13.1/font/bootstrap-icons.css' /usr/share/nginx/html/css/bootstrap-icons.css
ADD --checksum=sha256:7bfcab6db99d5cfbf1705ca0536ddc78585432cc5fa41bbd7ad0f009033b2979 'https://use.fontawesome.com/releases/v4.7.0/fonts/fontawesome-webfont.eot' /usr/share/nginx/html/css/
ADD --checksum=sha256:2adefcbc041e7d18fcf2d417879dc5a09997aa64d675b7a3c4b6ce33da13f3fe 'https://use.fontawesome.com/releases/v4.7.0/fonts/fontawesome-webfont.woff2' /usr/share/nginx/html/css/
ADD --checksum=sha256:ba0c59deb5450f5cb41b3f93609ee2d0d995415877ddfa223e8a8a7533474f07 'https://use.fontawesome.com/releases/v4.7.0/fonts/fontawesome-webfont.woff' /usr/share/nginx/html/css/
ADD --checksum=sha256:aa58f33f239a0fb02f5c7a6c45c043d7a9ac9a093335806694ecd6d4edc0d6a8 'https://use.fontawesome.com/releases/v4.7.0/fonts/fontawesome-webfont.ttf' /usr/share/nginx/html/css/
ADD --checksum=sha256:ad6157926c1622ba4e1d03d478f1541368524bfc46f51e42fe0d945f7ef323e4 'https://use.fontawesome.com/releases/v4.7.0/fonts/fontawesome-webfont.svg#fontawesomeregular' /usr/share/nginx/html/css/fontawesome-webfont.svg

ADD --chmod=644 nginx/requirements.txt /usr/local/src/requirements.txt

RUN set -eux; \
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
    su-exec \
    tar \
    zlib-dev \
    ; \
    \
  mkdir -p /usr/src/openresty /usr/src/nginx-auth-ldap /www /www/logs/nginx /var/log/nginx ; \
  tar -zxC /usr/src/nginx-auth-ldap --strip=1 -f /nginx-auth-ldap.tar.gz ; \
  tar -zxC /usr/src/openresty --strip=1 -f /openresty.tar.gz ; \
  cd /usr/src/openresty ; \
  ./configure $CONFIG ; \
  make -j$(getconf _NPROCESSORS_ONLN) ; \
  make install ; \
  rm -rf /etc/nginx/html/ ; \
  mkdir -p /etc/nginx/conf.d/ /etc/nginx/templates/ /etc/nginx/auth/ /usr/share/nginx/html/ ; \
  ln -s ../../usr/lib/nginx/modules /etc/nginx/modules ; \
  strip /usr/sbin/nginx* ; \
  strip /usr/lib/nginx/modules/*.so ; \
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
  # install OpenID Connect Lua modules from the pinned GitHub tarballs into the
  # same site/lualib tree opm would have used.
  mkdir -p /usr/local/openresty/site/lualib ; \
  # Most of these tarballs put their modules under lib/, but lua-ffi-zlib
  # publishes ffi-zlib.lua at the repo root, so a lib/-only copy would silently
  # install nothing for it. Handle both layouts.
  for t in /lua-src/*.tar.gz; do \
    d="$(mktemp -d)" ; \
    tar -xzf "$t" -C "$d" --strip-components=1 ; \
    if [ -d "$d"/lib ]; then \
      cp -rv "$d"/lib/* /usr/local/openresty/site/lualib/ ; \
    else \
      find "$d" -maxdepth 1 -name '*.lua' -exec cp -v {} /usr/local/openresty/site/lualib/ \; ; \
    fi ; \
    rm -rf "$d" ; \
  done ; \
  # Fail the build here if any module or transitive dependency is missing.
  #   Each entry is load-bearing:
  #     resty.openssl.version  - FFI entry point that actually dlopens libcrypto,
  #                              so an ABI mismatch fails here, not on first login
  #     ffi-zlib               - transitive via session 4.x; session may require it
  #                              lazily, so assert it eagerly
  #     resty.session.utils    - what drags lua-resty-openssl in under session 4.x
  /usr/local/openresty/bin/resty -e 'require "resty.http"; require "resty.openssl.version"; require "ffi-zlib"; require "resty.session"; require "resty.session.utils"; require "resty.hmac"; require "resty.jwt"; require "resty.openidc"' ; \
  cd /usr/local/src/ ; \
    pip3 install --break-system-packages --no-compile --no-cache-dir -r ./requirements.txt ; \
  apk del .nginx-build-deps ; \
  apk del .gettext ; \
  mv /tmp/envsubst /usr/local/bin/ ; \
  rm -rf /usr/src/* /usr/local/src/* /var/tmp/* /var/cache/apk/* /openresty.tar.gz /nginx-auth-ldap.tar.gz /lua-src ; \
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
ENV BUILD_DATE=$BUILD_DATE
ENV MALCOLM_VERSION=$MALCOLM_VERSION
ENV VCS_REVISION=$VCS_REVISION

LABEL org.opencontainers.image.created=$BUILD_DATE
LABEL org.opencontainers.image.version=$MALCOLM_VERSION
LABEL org.opencontainers.image.revision=$VCS_REVISION
