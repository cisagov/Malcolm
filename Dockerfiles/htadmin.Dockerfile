FROM debian:11-slim

# Copyright (c) 2025 Battelle Energy Alliance, LLC.  All rights reserved.
LABEL maintainer="malcolm@inl.gov"
LABEL org.opencontainers.image.authors='malcolm@inl.gov'
LABEL org.opencontainers.image.url='https://github.com/cisagov/Malcolm'
LABEL org.opencontainers.image.documentation='https://github.com/cisagov/Malcolm/blob/main/README.md'
LABEL org.opencontainers.image.source='https://github.com/cisagov/Malcolm'
LABEL org.opencontainers.image.vendor='Cybersecurity and Infrastructure Security Agency'
LABEL org.opencontainers.image.title='ghcr.io/cisagov/malcolm/htadmin'
LABEL org.opencontainers.image.description='Malcolm container providing htadmin for managing login accounts in an htpasswd file'

ARG DEFAULT_UID=33
ARG DEFAULT_GID=33
ENV DEFAULT_UID $DEFAULT_UID
ENV DEFAULT_GID $DEFAULT_GID
ENV PUSER "www-data"
ENV PGROUP "www-data"
ENV PUSER_CHOWN "/var/www"
# not dropping privileges globally so nginx can bind privileged ports internally.
# nginx and php-fpm will drop privileges to "www-data" user for worker processes
ENV PUSER_PRIV_DROP false
USER root

ENV DEBIAN_FRONTEND noninteractive
ENV TERM xterm

ARG PHP_VERSION=7.4
ARG MCRYPT_VERSION=1.0.4
ARG BOOTSTRAP_VERSION=3.3.6

ENV PHP_VERSION $PHP_VERSION
ENV MCRYPT_VERSION $MCRYPT_VERSION
ENV BOOTSTRAP_VERSION $BOOTSTRAP_VERSION

ENV HTADMIN_URL "https://codeload.github.com/mmguero-dev/htadmin/tar.gz/master"

RUN apt-get -q update && \
    apt-get -y -q --no-install-recommends upgrade && \
    apt-get -y -q --allow-downgrades --allow-remove-essential --allow-change-held-packages --no-install-recommends install \
      ca-certificates \
      curl \
      jq \
      libmcrypt-dev \
      libmcrypt4 \
      make \
      mcrypt \
      nginx-light \
      php-dev \
      php-pear \
      php$PHP_VERSION-apcu \
      php$PHP_VERSION-cli \
      php$PHP_VERSION-curl \
      php$PHP_VERSION-fpm \
      php$PHP_VERSION-gd \
      procps \
      rsync \
      supervisor \
      tini && \
    ( yes '' | pecl channel-update pecl.php.net ) && \
    ( yes '' | pecl install mcrypt-$MCRYPT_VERSION ) && \
    ln -s -r /usr/lib/php/20??????/*.so /usr/lib/php/$PHP_VERSION/ && \
    mkdir -p /run/php && \
  cd /tmp && \
    mkdir -p ./htadmin && \
    curl -sSL "$HTADMIN_URL" | tar xzvf - -C ./htadmin --strip-components 1 && \
    find /tmp/htadmin -type f -name index.php -execdir mv index.php htadmin.php \; && \
    find /tmp/htadmin -type f -exec sed -i 's/index.php/htadmin.php/g' "{}" \; && \
    mv /tmp/htadmin/sites/html/htadmin /var/www/htadmin && \
    cd /var/www/htadmin && \
    ( grep -rhoPi "(src|href)=['\"]https?://.+?['\"]" ./includes/* | sed "s/^[a-zA-Z]*=['\"]*//" | sed "s/['\"]$//" | xargs -r -l curl -s -S -L -J -O ) && \
    sed -i "s@http[^'\"]*/@@gI" ./includes/* && \
    mkdir -p fonts config auth default && \
    cd fonts && \
    curl -s -S -L -J -O "https://maxcdn.bootstrapcdn.com/bootstrap/$BOOTSTRAP_VERSION/fonts/glyphicons-halflings-regular.ttf" && \
    curl -s -S -L -J -O "https://maxcdn.bootstrapcdn.com/bootstrap/$BOOTSTRAP_VERSION/fonts/glyphicons-halflings-regular.woff" && \
    curl -s -S -L -J -O "https://maxcdn.bootstrapcdn.com/bootstrap/$BOOTSTRAP_VERSION/fonts/glyphicons-halflings-regular.woff2" && \
  chown -R ${PUSER}:${PGROUP} /var/www && \
  apt-get -y -q --allow-downgrades --allow-remove-essential --allow-change-held-packages --purge remove \
    make libmcrypt-dev php-pear php-dev && \
  apt-get autoremove -y -q && \
  apt-get clean -y -q && \
  rm -rf /var/lib/apt/lists/* /var/cache/* /tmp/* /var/tmp/* /var/www/html

COPY --from=ghcr.io/mmguero-dev/gostatic --chmod=755 /goStatic /usr/bin/goStatic
ADD --chmod=755 shared/bin/docker-uid-gid-setup.sh /usr/local/bin/
ADD --chmod=755 shared/bin/service_check_passthrough.sh /usr/local/bin/
ADD --chmod=755 container-health-scripts/htadmin.sh /usr/local/bin/container_health.sh
ADD --chmod=644 docs/images/favicon/favicon.ico /var/www/htadmin/
ADD --chmod=644 htadmin/supervisord.conf /supervisord.conf
ADD --chmod=755 htadmin/htadmin.sh /usr/local/bin/
ADD --chmod=644 htadmin/src/bootstrap.* /var/www/htadmin/
ADD --chmod=644 htadmin/src/includes/*.php /var/www/htadmin/includes/
ADD --chmod=644 htadmin/php/php.ini /etc/php/$PHP_VERSION/fpm/php.ini
ADD --chmod=644 htadmin/nginx/sites-available/default /etc/nginx/sites-available/default

EXPOSE 80

ENTRYPOINT ["/usr/bin/tini", \
            "--", \
            "/usr/local/bin/docker-uid-gid-setup.sh", \
            "/usr/local/bin/service_check_passthrough.sh", \
            "-s", "htadmin"]

CMD ["/usr/bin/supervisord", "-c", "/supervisord.conf", "-u", "root", "-n"]


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
