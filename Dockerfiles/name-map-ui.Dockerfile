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

RUN apk --no-cache add bash php7 php7-fpm php7-mysqli php7-json php7-openssl php7-curl php7-fileinfo \
    php7-zlib php7-xml php7-phar php7-intl php7-dom php7-xmlreader php7-ctype php7-session \
    php7-mbstring php7-gd nginx supervisor curl inotify-tools file psmisc

COPY name-map-ui/config/nginx.conf /etc/nginx/nginx.conf
COPY name-map-ui/config/fpm-pool.conf /etc/php7/php-fpm.d/www.conf
COPY name-map-ui/config/php.ini /etc/php7/conf.d/custom.ini
COPY name-map-ui/config/supervisord.conf /etc/supervisord.conf
COPY name-map-ui/config/supervisor_logstash_ctl.conf /etc/supervisor/logstash/supervisord.conf
COPY name-map-ui/scripts/*.sh /usr/local/bin/

ADD https://code.jquery.com/jquery-${JQUERY_VERSION}.min.js /tmp/jquery.min.js
ADD https://raw.githubusercontent.com/javve/list.js/${LISTJS_VERSION}/dist/list.min.js /tmp/list.min.js

RUN rm -rf /etc/nginx/conf.d/default.conf /var/www/html/* && \
    mkdir -p /var/www/html/upload /var/www/html/maps && \
    cd /var/www/html && \
    mv /tmp/jquery.min.js /tmp/list.min.js ./ && \
    chmod 644 ./jquery.min.js ./list.min.js && \
    ln -s . name-map-ui && \
    addgroup -g 1000 nginxsrv ; \
    adduser -D -H -u 1000 -h /var/www/html -s /sbin/nologin -G nginxsrv -g nginxsrv nginxsrv ; \
    addgroup nginxsrv nginx ; \
    addgroup nginxsrv shadow ; \
    chown -R nginxsrv.nginxsrv /var/www/html && \
    chown -R nginxsrv.nginxsrv /run && \
    chown -R nginxsrv.nginxsrv /var/lib/nginx && \
    chown -R nginxsrv.nginxsrv /var/log/nginx && \
    chmod 755 /usr/local/bin/*.sh

VOLUME /var/www/html

USER nginxsrv

WORKDIR /var/www/html

COPY --chown=1000 name-map-ui/site/ /var/www/html/
COPY --chown=1000 docs/images/logo/Malcolm_banner.png /var/www/html/
COPY --chown=1000 docs/images/favicon/favicon.ico /var/www/html/

EXPOSE 8080

CMD ["/usr/bin/supervisord", "-c", "/etc/supervisord.conf"]

# to be populated at build-time:
ARG BUILD_DATE
ARG MALCOLM_VERSION
ARG VCS_REVISION

LABEL org.opencontainers.image.created=$BUILD_DATE
LABEL org.opencontainers.image.version=$MALCOLM_VERSION
LABEL org.opencontainers.image.revision=$VCS_REVISION
