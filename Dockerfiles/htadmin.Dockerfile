FROM debian:bullseye-slim

# Copyright (c) 2022 Battelle Energy Alliance, LLC.  All rights reserved.
LABEL maintainer="malcolm@inl.gov"
LABEL org.opencontainers.image.authors='malcolm@inl.gov'
LABEL org.opencontainers.image.url='https://github.com/idaholab/Malcolm'
LABEL org.opencontainers.image.documentation='https://github.com/idaholab/Malcolm/blob/main/README.md'
LABEL org.opencontainers.image.source='https://github.com/idaholab/Malcolm'
LABEL org.opencontainers.image.vendor='Idaho National Laboratory'
LABEL org.opencontainers.image.title='malcolmnetsec/htadmin'
LABEL org.opencontainers.image.description='Malcolm container providing htadmin for managing login accounts in an htpasswd file'

ARG DEFAULT_UID=33
ARG DEFAULT_GID=33
ENV DEFAULT_UID $DEFAULT_UID
ENV DEFAULT_GID $DEFAULT_GID
ENV PUSER "www-data"
ENV PGROUP "www-data"
# not dropping privileges globally so nginx can bind privileged ports internally.
# nginx and php-fpm will drop privileges to "www-data" user for worker processes
ENV PUSER_PRIV_DROP false

ENV DEBIAN_FRONTEND noninteractive
ENV TERM xterm

ARG PHP_VERSION=7.4
ARG MCRYPT_VERSION=1.0.4
ARG BOOTSTRAP_VERSION=3.3.6

ENV PHP_VERSION $PHP_VERSION
ENV MCRYPT_VERSION $MCRYPT_VERSION
ENV BOOTSTRAP_VERSION $BOOTSTRAP_VERSION

ENV HTADMIN_URL "https://codeload.github.com/mmguero-dev/htadmin/tar.gz/master"

RUN apt-get update && \
    apt-get -y -q --allow-downgrades --allow-remove-essential --allow-change-held-packages --no-install-recommends install \
      ca-certificates \
      curl \
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
      supervisor && \
    ( yes '' | pecl channel-update pecl.php.net ) && \
    ( yes '' | pecl install mcrypt-$MCRYPT_VERSION ) && \
    ln -s -r /usr/lib/php/20??????/*.so /usr/lib/php/$PHP_VERSION/ && \
    mkdir -p /run/php && \
  cd /tmp && \
    mkdir -p ./htadmin && \
    curl -sSL "$HTADMIN_URL" | tar xzvf - -C ./htadmin --strip-components 1 && \
    mv /tmp/htadmin/sites/html/htadmin /var/www/htadmin && \
    cd /var/www/htadmin && \
    ( grep -rhoPi "(src|href)=['\"]https?://.+?['\"]" ./includes/* | sed "s/^[a-zA-Z]*=['\"]*//" | sed "s/['\"]$//" | xargs -r -l curl -s -S -L -J -O ) && \
    sed -i "s@http[^'\"]*/@@gI" ./includes/* && \
    mkdir fonts && cd fonts && \
    curl -s -S -L -J -O "https://maxcdn.bootstrapcdn.com/bootstrap/$BOOTSTRAP_VERSION/fonts/glyphicons-halflings-regular.ttf" && \
    curl -s -S -L -J -O "https://maxcdn.bootstrapcdn.com/bootstrap/$BOOTSTRAP_VERSION/fonts/glyphicons-halflings-regular.woff" && \
    curl -s -S -L -J -O "https://maxcdn.bootstrapcdn.com/bootstrap/$BOOTSTRAP_VERSION/fonts/glyphicons-halflings-regular.woff2" && \
  chown -R ${PUSER}:${PGROUP} /var/www && \
  apt-get -y -q --allow-downgrades --allow-remove-essential --allow-change-held-packages --purge remove \
    make libmcrypt-dev php-pear php-dev && \
  apt-get autoremove -y -q && \
  apt-get clean -y -q && \
  rm -rf /var/lib/apt/lists/* /var/cache/* /tmp/* /var/tmp/* /var/www/html

ADD shared/bin/docker-uid-gid-setup.sh /usr/local/bin/
ADD docs/images/favicon/favicon.ico /var/www/htadmin/
ADD htadmin/supervisord.conf /supervisord.conf
ADD htadmin/htadmin.sh /usr/local/bin/
ADD htadmin/src /var/www/htadmin/
ADD htadmin/php/php.ini /etc/php/$PHP_VERSION/fpm/php.ini
ADD htadmin/nginx/sites-available/default /etc/nginx/sites-available/default

EXPOSE 80

ENTRYPOINT ["/usr/local/bin/docker-uid-gid-setup.sh"]

CMD ["/usr/bin/supervisord", "-c", "/supervisord.conf", "-u", "root", "-n"]


# to be populated at build-time:
ARG BUILD_DATE
ARG MALCOLM_VERSION
ARG VCS_REVISION

LABEL org.opencontainers.image.created=$BUILD_DATE
LABEL org.opencontainers.image.version=$MALCOLM_VERSION
LABEL org.opencontainers.image.revision=$VCS_REVISION
