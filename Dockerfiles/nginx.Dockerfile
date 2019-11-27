FROM jwilder/nginx-proxy:latest as build

ENV NGINX_AUTH_LDAP_GIT_URL=https://github.com/kvspb/nginx-auth-ldap.git
ENV NGINX_GPG_KEY=573BFD6B3D8FBC641079A6ABABF5BD827BD9BF62
ENV NGINX_IMAGE_DIST=buster
ENV NGINX_VERSION=1.17.6

# repackage latest nginx DEB with nginx-auth-ldap
RUN apt-get -y -q update \
  && apt-get install -y -q --no-install-recommends \
     ca-certificates \
     dpkg-dev \
     git \
     gnupg1 \
     libldap2-dev \
  && KEY_FOUND=''; \
    for KEY_SERVER in \
      hkp://keyserver.ubuntu.com:80 \
      hkp://p80.pool.sks-keyservers.net:80 \
      ha.pool.sks-keyservers.net \
      pgp.mit.edu \
    ; do \
      echo "Fetching GPG key $NGINX_GPG_KEY from $server"; \
      apt-key adv --keyserver "$KEY_SERVER" --keyserver-options timeout=10 --recv-keys "$NGINX_GPG_KEY" && KEY_FOUND=yes && break; \
    done \
  && apt-get remove --purge --auto-remove -y -q gnupg1 \
  && echo "deb https://nginx.org/packages/mainline/debian/ $NGINX_IMAGE_DIST nginx" >> /etc/apt/sources.list.d/nginx.list \
  && echo "deb-src https://nginx.org/packages/mainline/debian/ $NGINX_IMAGE_DIST nginx" >> /etc/apt/sources.list.d/nginx.list \
  && apt-get -y -q update \
  && cd /tmp \
  && git clone $NGINX_AUTH_LDAP_GIT_URL \
  && apt-get source nginx=$NGINX_VERSION-1~$NGINX_IMAGE_DIST \
  && apt-get build-dep -y -q nginx \
  && sed -i 's/with-file-aio/& \\\n              \-\-add-module=\/tmp\/nginx-auth-ldap\//g' ./nginx-$NGINX_VERSION/debian/rules \
  && cd ./nginx-$NGINX_VERSION/ \
  && dpkg-buildpackage -b

FROM jwilder/nginx-proxy:latest

# Copyright (c) 2019 Battelle Energy Alliance, LLC.  All rights reserved.
LABEL maintainer="Seth.Grover@inl.gov"
LABEL org.opencontainers.image.authors='Seth.Grover@inl.gov'
LABEL org.opencontainers.image.url='https://github.com/idaholab/Malcolm'
LABEL org.opencontainers.image.documentation='https://github.com/idaholab/Malcolm/blob/master/README.md'
LABEL org.opencontainers.image.source='https://github.com/idaholab/Malcolm'
LABEL org.opencontainers.image.vendor='Idaho National Laboratory'
LABEL org.opencontainers.image.title='malcolmnetsec/nginx-proxy'
LABEL org.opencontainers.image.description='Malcolm container providing an NGINX reverse proxy for the other services'

ENV NGINX_IMAGE_DIST=buster
ENV NGINX_VERSION=1.17.6

# install repackaged nginx DEB with nginx-auth-ldap we built earlier
COPY --from=build /tmp/nginx_$NGINX_VERSION-1~${NGINX_IMAGE_DIST}_amd64.deb /tmp/nginx_$NGINX_VERSION-1~${NGINX_IMAGE_DIST}_amd64.deb
RUN apt-get -y -q update \
  && apt-get install -y -q --no-install-recommends libldap-2.4-2 \
  && dpkg -i /tmp/nginx_$NGINX_VERSION-1~${NGINX_IMAGE_DIST}_amd64.deb \
  && rm -f /tmp/nginx_$NGINX_VERSION-1~${NGINX_IMAGE_DIST}_amd64.deb \
  && apt-get clean \
  && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

ADD nginx/nginx.conf /etc/nginx/nginx.conf
ADD docs/images/icon/favicon.ico /etc/nginx/favicon.ico

# to be populated at build-time:
ARG BUILD_DATE
ARG MALCOLM_VERSION
ARG VCS_REVISION

LABEL org.opencontainers.image.created=$BUILD_DATE
LABEL org.opencontainers.image.version=$MALCOLM_VERSION
LABEL org.opencontainers.image.revision=$VCS_REVISION
