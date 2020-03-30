FROM alpine:3.11

# Copyright (c) 2020 Battelle Energy Alliance, LLC.  All rights reserved.
LABEL maintainer="malcolm.netsec@gmail.com"
LABEL org.opencontainers.image.authors='malcolm.netsec@gmail.com'
LABEL org.opencontainers.image.url='https://github.com/idaholab/Malcolm'
LABEL org.opencontainers.image.documentation='https://github.com/idaholab/Malcolm/blob/master/README.md'
LABEL org.opencontainers.image.source='https://github.com/idaholab/Malcolm'
LABEL org.opencontainers.image.vendor='Idaho National Laboratory'
LABEL org.opencontainers.image.title='malcolmnetsec/name-map-ui'
LABEL org.opencontainers.image.description='Malcolm container providing a user interface for mapping names to network hosts and subnets'

ENV JQUERY_VERSION 1.6.4
ENV LISTJS_VERSION v1.5.0

RUN apk --no-cache add php7 php7-fpm php7-mysqli php7-json php7-openssl php7-curl php7-fileinfo \
    php7-zlib php7-xml php7-phar php7-intl php7-dom php7-xmlreader php7-ctype php7-session \
    php7-mbstring php7-gd nginx supervisor curl

COPY name-map-ui/config/nginx.conf /etc/nginx/nginx.conf
COPY name-map-ui/config/fpm-pool.conf /etc/php7/php-fpm.d/www.conf
COPY name-map-ui/config/php.ini /etc/php7/conf.d/custom.ini
COPY name-map-ui/config/supervisord.conf /etc/supervisor/conf.d/supervisord.conf

ADD https://code.jquery.com/jquery-${JQUERY_VERSION}.min.js /tmp/jquery.min.js
ADD https://raw.githubusercontent.com/javve/list.js/${LISTJS_VERSION}/dist/list.min.js /tmp/list.min.js

RUN rm -rf /etc/nginx/conf.d/default.conf /var/www/html/* && \
    mkdir -p /var/www/html/upload && \
    cd /var/www/html && \
    mv /tmp/jquery.min.js /tmp/list.min.js ./ && \
    chmod 644 ./jquery.min.js ./list.min.js && \
    ln -s . name-map-ui && \
    chown -R nobody.nobody /var/www/html && \
    chown -R nobody.nobody /run && \
    chown -R nobody.nobody /var/lib/nginx && \
    chown -R nobody.nobody /var/log/nginx

VOLUME /var/www/html

USER nobody

WORKDIR /var/www/html

COPY --chown=nobody name-map-ui/site/ /var/www/html/
COPY --chown=nobody docs/images/logo/Malcolm_banner.png /var/www/html/
COPY --chown=nobody docs/images/favicon/favicon.ico /var/www/html/

EXPOSE 8080

CMD ["/usr/bin/supervisord", "-c", "/etc/supervisor/conf.d/supervisord.conf"]

# to be populated at build-time:
ARG BUILD_DATE
ARG MALCOLM_VERSION
ARG VCS_REVISION

LABEL org.opencontainers.image.created=$BUILD_DATE
LABEL org.opencontainers.image.version=$MALCOLM_VERSION
LABEL org.opencontainers.image.revision=$VCS_REVISION
