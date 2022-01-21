FROM debian:bullseye-slim AS build

# Copyright (c) 2022 Battelle Energy Alliance, LLC.  All rights reserved.

ENV DEBIAN_FRONTEND noninteractive

ARG SITE_NAME="Capture File and Log Archive Upload"

ENV SITE_NAME $SITE_NAME
ENV JQUERY_FILE_UPLOAD_VERSION v9.19.1
ENV JQUERY_FILE_UPLOAD_URL "https://github.com/blueimp/jQuery-File-Upload/archive/${JQUERY_FILE_UPLOAD_VERSION}.tar.gz"

RUN apt-get update && \
    apt-get -y -q --allow-downgrades --allow-remove-essential --allow-change-held-packages install --no-install-recommends npm node-encoding git ca-certificates curl wget && \
    npm install -g bower && \
    mkdir -p /jQuery-File-Upload && \
      curl -sSL "$JQUERY_FILE_UPLOAD_URL" | tar xzvf - -C /jQuery-File-Upload --strip-components 1 && \
    cd /jQuery-File-Upload && \
    bower --allow-root install bootstrap && \
    bower --allow-root install jquery && \
    bower --allow-root install blueimp-gallery && \
    bower --allow-root install bootstrap-tagsinput && \
    rm -rf /jQuery-File-Upload/*.html /jQuery-File-Upload/test/ /jQuery-File-Upload/server/gae-go/ \
           /jQuery-File-Upload/server/gae-python/

FROM debian:bullseye-slim AS runtime

LABEL maintainer="malcolm@inl.gov"
LABEL org.opencontainers.image.authors='malcolm@inl.gov'
LABEL org.opencontainers.image.url='https://github.com/cisagov/Malcolm'
LABEL org.opencontainers.image.documentation='https://github.com/cisagov/Malcolm/blob/main/README.md'
LABEL org.opencontainers.image.source='https://github.com/cisagov/Malcolm'
LABEL org.opencontainers.image.vendor='Cybersecurity and Infrastructure Security Agency'
LABEL org.opencontainers.image.title='malcolmnetsec/file-upload'
LABEL org.opencontainers.image.description='Malcolm container providing an interface for uploading PCAP files and Zeek logs for processing'

ARG DEFAULT_UID=33
ARG DEFAULT_GID=33
ENV DEFAULT_UID $DEFAULT_UID
ENV DEFAULT_GID $DEFAULT_GID
ENV PUSER "www-data"
ENV PGROUP "www-data"
# not dropping privileges globally in this container as required to run SFTP server. this can
# be handled by supervisord instead on an as-needed basis, and/or php-fpm/nginx itself
# will drop privileges to www-data as well.
ENV PUSER_PRIV_DROP false

ENV DEBIAN_FRONTEND noninteractive
ENV TERM xterm

ARG PHP_VERSION=7.4
ENV PHP_VERSION $PHP_VERSION

COPY --from=build /jQuery-File-Upload/ /var/www/upload/

RUN apt-get update && \
    apt-get -y -q --allow-downgrades --allow-remove-essential --allow-change-held-packages install --no-install-recommends \
      wget \
      ca-certificates \
      openssh-server \
      supervisor \
      vim-tiny \
      less \
      php$PHP_VERSION \
      php$PHP_VERSION-fpm \
      php$PHP_VERSION-apcu \
      nginx-light && \
    apt-get clean -y -q && \
    rm -rf /var/lib/apt/lists/*

ADD shared/bin/docker-uid-gid-setup.sh /usr/local/bin/
ADD docs/images/logo/Malcolm_banner.png /var/www/upload/Malcolm_banner.png
ADD file-upload/docker-entrypoint.sh /docker-entrypoint.sh
ADD file-upload/jquery-file-upload/bootstrap.min.css /var/www/upload/bower_components/bootstrap/dist/css/bootstrap.min.css
ADD file-upload/jquery-file-upload/index.html /var/www/upload/index.html
ADD file-upload/jquery-file-upload/index.php /var/www/upload/server/php/index.php
ADD file-upload/nginx/sites-available/default /etc/nginx/sites-available/default
ADD file-upload/php/php.ini /etc/php/$PHP_VERSION/fpm/php.ini
ADD file-upload/sshd_config /tmp/sshd_config
ADD file-upload/supervisord.conf /supervisord.conf

RUN mkdir -p /var/run/sshd /var/www/upload/server/php/chroot /run/php && \
  mv /var/www/upload/server/php/files /var/www/upload/server/php/chroot && \
  ln -s /var/www/upload/server/php/chroot/files /var/www/upload/server/php/files && \
  ln -sr /var/www/upload /var/www/upload/upload && \
  perl -i -pl -e 's/^#?(\s*PermitRootLogin\s+)[\w\-]+$/$1no/i;' \
       -e 's/^#?(\s*PasswordAuthentication\s+)\w+$/$1no/i' /etc/ssh/sshd_config && \
  chmod a+x /docker-entrypoint.sh && \
  cat /tmp/sshd_config >>/etc/ssh/sshd_config && \
  chmod 775 /var/www/upload/server/php/chroot/files && \
  chmod 755 /var /var/www /var/www/upload /var/www/upload/server /var/www/upload/server/php \
            /var/www/upload/server/php/chroot && \
  echo "Put your files into /files. Don't use subdirectories." \
      >/var/www/upload/server/php/chroot/README.txt && \
  rm -rf /var/lib/apt/lists/* /var/cache/* /tmp/* /var/tmp/* /var/www/upload/server/php/chroot/files/.gitignore /tmp/sshd_config

VOLUME [ "/var/www/upload/server/php/chroot/files" ]
EXPOSE 22 80

ENTRYPOINT ["/usr/local/bin/docker-uid-gid-setup.sh", "/docker-entrypoint.sh"]

CMD ["/usr/bin/supervisord", "-c", "/supervisord.conf", "-u", "root", "-n"]


# to be populated at build-time:
ARG BUILD_DATE
ARG MALCOLM_VERSION
ARG VCS_REVISION

LABEL org.opencontainers.image.created=$BUILD_DATE
LABEL org.opencontainers.image.version=$MALCOLM_VERSION
LABEL org.opencontainers.image.revision=$VCS_REVISION
