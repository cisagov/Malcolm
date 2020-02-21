FROM debian:buster-slim

# Copyright (c) 2020 Battelle Energy Alliance, LLC.  All rights reserved.
LABEL maintainer="malcolm.netsec@gmail.com"
LABEL org.opencontainers.image.authors='malcolm.netsec@gmail.com'
LABEL org.opencontainers.image.url='https://github.com/idaholab/Malcolm'
LABEL org.opencontainers.image.documentation='https://github.com/idaholab/Malcolm/blob/master/README.md'
LABEL org.opencontainers.image.source='https://github.com/idaholab/Malcolm'
LABEL org.opencontainers.image.vendor='Idaho National Laboratory'
LABEL org.opencontainers.image.title='malcolmnetsec/htadmin'
LABEL org.opencontainers.image.description='Malcolm container providing htadmin for managing login accounts in an htpasswd file'


ENV DEBIAN_FRONTEND noninteractive
ENV TERM xterm

ARG PHP_VERSION=7.3
ARG MCRYPT_VERSION=1.0.2
ARG BOOTSTRAP_VERSION=3.3.6

ENV PHP_VERSION $PHP_VERSION
ENV MCRYPT_VERSION $MCRYPT_VERSION
ENV BOOTSTRAP_VERSION $BOOTSTRAP_VERSION

RUN apt-get update && \
    apt-get -y -q --allow-downgrades --allow-remove-essential --allow-change-held-packages --no-install-recommends install \
      bcrypt \
      ca-certificates \
      curl \
      git \
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
    apt-get -y -q --allow-downgrades --allow-remove-essential --allow-change-held-packages --purge remove \
      make libmcrypt-dev php-pear php-dev && \
    apt-get autoremove -y -q && \
    apt-get clean -y -q && \
    rm -rf /var/lib/apt/lists/* /var/cache/* /tmp/* /var/tmp/* /var/www/html

  RUN git clone --depth 1 https://github.com/mmguero/htadmin /tmp/htadmin && \
      mv /tmp/htadmin/sites/html/htadmin /var/www/htadmin && \
      cd /var/www/htadmin && \
      ( grep -rhoPi "(src|href)=['\"]https?://.+?['\"]" ./includes/* | sed "s/^[a-zA-Z]*=['\"]*//" | sed "s/['\"]$//" | xargs -r -l curl -s -S -L -J -O ) && \
      sed -i "s@http[^'\"]*/@@gI" ./includes/* && \
      mkdir fonts && cd fonts && \
      curl -s -S -L -J -O "https://maxcdn.bootstrapcdn.com/bootstrap/$BOOTSTRAP_VERSION/fonts/glyphicons-halflings-regular.ttf" && \
      curl -s -S -L -J -O "https://maxcdn.bootstrapcdn.com/bootstrap/$BOOTSTRAP_VERSION/fonts/glyphicons-halflings-regular.woff" && \
      curl -s -S -L -J -O "https://maxcdn.bootstrapcdn.com/bootstrap/$BOOTSTRAP_VERSION/fonts/glyphicons-halflings-regular.woff2" && \
    usermod --non-unique --uid 1000 www-data && \
      groupmod --non-unique --gid 1000 www-data && \
      chown -R www-data:www-data /var/www && \
      apt-get -y -q --allow-downgrades --allow-remove-essential --allow-change-held-packages --purge remove git && \
        apt-get autoremove -y -q && \
        apt-get clean -y -q && \
        rm -rf /var/lib/apt/lists/* /var/cache/* /tmp/* /var/tmp/*

ADD docs/images/favicon/favicon.ico /var/www/htadmin/
ADD htadmin/supervisord.conf /supervisord.conf
ADD htadmin/src /var/www/htadmin/
ADD htadmin/php/php.ini /etc/php/$PHP_VERSION/fpm/php.ini
ADD htadmin/nginx/sites-available/default /etc/nginx/sites-available/default

EXPOSE 80

CMD ["/usr/bin/supervisord", "-c", "/supervisord.conf", "-u", "root", "-n"]


# to be populated at build-time:
ARG BUILD_DATE
ARG MALCOLM_VERSION
ARG VCS_REVISION

LABEL org.opencontainers.image.created=$BUILD_DATE
LABEL org.opencontainers.image.version=$MALCOLM_VERSION
LABEL org.opencontainers.image.revision=$VCS_REVISION
