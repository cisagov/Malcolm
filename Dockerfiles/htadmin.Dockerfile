FROM debian:buster-slim
# Copyright (c) 2019 Battelle Energy Alliance, LLC.  All rights reserved.
LABEL maintainer="Seth.Grover@inl.gov"

ENV DEBIAN_FRONTEND noninteractive
ENV TERM xterm

ARG PHP_VERSION=7.3
ARG MCRYPT_VERSION=1.0.2

ENV PHP_VERSION $PHP_VERSION
ENV MCRYPT_VERSION $MCRYPT_VERSION

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
    yes '' | pecl channel-update pecl.php.net && \
    yes '' | pecl install mcrypt-$MCRYPT_VERSION && \
    ln -s -r /usr/lib/php/20??????/*.so /usr/lib/php/$PHP_VERSION/ && \
    mkdir -p /run/php && \
    git clone --depth 1 https://github.com/mmguero/htadmin /tmp/htadmin && \
    mv /tmp/htadmin/sites/html/htadmin /var/www/htadmin && \
    apt-get -y -q --allow-downgrades --allow-remove-essential --allow-change-held-packages --purge remove \
      git make libmcrypt-dev php-pear php-dev && \
    apt-get autoremove -y -q && \
    apt-get clean -y -q && \
    usermod --non-unique --uid 1000 www-data && \
      groupmod --non-unique --gid 1000 www-data && \
      chown -R www-data:www-data /var/www && \
    rm -rf /var/lib/apt/lists/* /var/cache/* /tmp/* /var/tmp/* /var/www/html

ADD htadmin/supervisord.conf /supervisord.conf
ADD htadmin/php/php.ini /etc/php/$PHP_VERSION/fpm/php.ini
ADD htadmin/nginx/sites-available/default /etc/nginx/sites-available/default

EXPOSE 80

CMD ["/usr/bin/supervisord", "-c", "/supervisord.conf", "-u", "root", "-n"]
