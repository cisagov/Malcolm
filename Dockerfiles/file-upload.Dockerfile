FROM debian:12-slim AS npmget

# Copyright (c) 2023 Battelle Energy Alliance, LLC.  All rights reserved.

ENV DEBIAN_FRONTEND noninteractive

RUN apt-get -q update && \
    apt-get -y -q --no-install-recommends upgrade && \
    apt-get -y -q --allow-downgrades --allow-remove-essential --allow-change-held-packages install --no-install-recommends npm node-encoding git ca-certificates && \
    npm install -g \
      filepond \
      filepond-plugin-file-validate-size \
      filepond-plugin-file-validate-type \
      filepond-plugin-file-metadata \
      filepond-plugin-file-rename \
      @jcubic/tagger

FROM debian:12-slim AS runtime

LABEL maintainer="malcolm@inl.gov"
LABEL org.opencontainers.image.authors='malcolm@inl.gov'
LABEL org.opencontainers.image.url='https://github.com/idaholab/Malcolm'
LABEL org.opencontainers.image.documentation='https://github.com/idaholab/Malcolm/blob/main/README.md'
LABEL org.opencontainers.image.source='https://github.com/idaholab/Malcolm'
LABEL org.opencontainers.image.vendor='Idaho National Laboratory'
LABEL org.opencontainers.image.title='ghcr.io/idaholab/malcolm/file-upload'
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

ARG PHP_VERSION=8.2
ENV PHP_VERSION $PHP_VERSION

ARG FILEPOND_SERVER_BRANCH=master
ENV FILEPOND_SERVER_BRANCH $FILEPOND_SERVER_BRANCH

ARG STALE_UPLOAD_DELETE_MIN=360
ENV STALE_UPLOAD_DELETE_MIN $STALE_UPLOAD_DELETE_MIN

ENV SUPERCRONIC_VERSION "0.2.26"
ENV SUPERCRONIC_URL "https://github.com/aptible/supercronic/releases/download/v$SUPERCRONIC_VERSION/supercronic-linux-amd64"
ENV SUPERCRONIC "supercronic-linux-amd64"
ENV SUPERCRONIC_SHA1SUM "7a79496cf8ad899b99a719355d4db27422396735"
ENV SUPERCRONIC_CRONTAB "/etc/crontab"

COPY --from=npmget /usr/local/lib/node_modules/filepond /var/www/upload/filepond
COPY --from=npmget /usr/local/lib/node_modules/filepond-plugin-file-validate-size /var/www/upload/filepond-plugin-file-validate-size
COPY --from=npmget /usr/local/lib/node_modules/filepond-plugin-file-validate-type /var/www/upload/filepond-plugin-file-validate-type
COPY --from=npmget /usr/local/lib/node_modules/filepond-plugin-file-metadata /var/www/upload/filepond-plugin-file-metadata
COPY --from=npmget /usr/local/lib/node_modules/filepond-plugin-file-rename /var/www/upload/filepond-plugin-file-rename
COPY --from=npmget /usr/local/lib/node_modules/@jcubic /var/www/upload/@jcubic

RUN apt-get -q update && \
    apt-get -y -q --no-install-recommends upgrade && \
    apt-get -y -q --allow-downgrades --allow-remove-essential --allow-change-held-packages install --no-install-recommends \
      ca-certificates \
      curl \
      file \
      less \
      nginx-light \
      openssh-server \
      php$PHP_VERSION \
      php$PHP_VERSION-apcu \
      php$PHP_VERSION-fpm \
      rsync \
      supervisor \
      tini \
      vim-tiny && \
    curl -fsSLO "$SUPERCRONIC_URL" && \
      echo "${SUPERCRONIC_SHA1SUM}  ${SUPERCRONIC}" | sha1sum -c - && \
      chmod +x "$SUPERCRONIC" && \
      mv "$SUPERCRONIC" "/usr/local/bin/${SUPERCRONIC}" && \
      ln -sr "/usr/local/bin/${SUPERCRONIC}" /usr/local/bin/supercronic && \
    mkdir -p /var/www/upload/server/php \
             /tmp/filepond-server && \
    cd /tmp && \
      curl -sSL "https://github.com/pqina/filepond-server-php/archive/${FILEPOND_SERVER_BRANCH}.tar.gz" | tar xzvf - -C ./filepond-server --strip-components 1 && \
      rsync -a --include="*/" --include="*.php" --exclude="*" ./filepond-server/ /var/www/upload/server/php/ && \
    apt-get clean -y -q && \
    rm -rf /var/lib/apt/lists/* /var/cache/* /tmp/* /var/tmp/*

COPY --chmod=755 shared/bin/docker-uid-gid-setup.sh /usr/local/bin/
COPY --chmod=755 shared/bin/service_check_passthrough.sh /usr/local/bin/
COPY --from=ghcr.io/mmguero-dev/gostatic --chmod=755 /goStatic /usr/bin/goStatic
COPY --chmod=755 file-upload/docker-entrypoint.sh /docker-entrypoint.sh
ADD docs/images/logo/Malcolm_banner.png /var/www/upload/Malcolm_banner.png
ADD file-upload/nginx/sites-available/default /etc/nginx/sites-available/default
ADD file-upload/php/php.ini /etc/php/$PHP_VERSION/fpm/php.ini
ADD file-upload/php/*.php /var/www/upload/server/php/
ADD file-upload/site/index.html /var/www/upload/index.html
ADD file-upload/sshd_config /tmp/sshd_config
ADD file-upload/supervisord.conf /supervisord.conf

RUN mkdir -p /run/php \
             /var/run/sshd \
             /var/www/upload/server/php/chroot/files && \
  ln -s /var/www/upload/server/php/chroot/files /var/www/upload/server/php/files && \
  ln -sr /var/www/upload /var/www/upload/upload && \
  perl -i -pl -e 's/^#?(\s*PermitRootLogin\s+)[\w\-]+$/$1no/i;' \
              -e 's/^#?(\s*PasswordAuthentication\s+)\w+$/$1no/i' /etc/ssh/sshd_config && \
  cat /tmp/sshd_config >>/etc/ssh/sshd_config && \
  echo "0/10 * * * * find /var/www/upload/server/php/chroot/files -mindepth 3 -type f -mmin +\$STALE_UPLOAD_DELETE_MIN -delete" > ${SUPERCRONIC_CRONTAB} && \
  echo "5 * * * * find /var/www/upload/server/php/chroot/files -mindepth 2 -type d -empty -mmin +\$STALE_UPLOAD_DELETE_MIN -delete" >> ${SUPERCRONIC_CRONTAB} && \
  chmod 775 /var/www/upload/server/php/chroot/files && \
  chmod 755 /var \
            /var/www \
            /var/www/upload \
            /var/www/upload/server \
            /var/www/upload/server/php \
            /var/www/upload/server/php/chroot && \
  echo "Put your files into /files. Don't use subdirectories." \
      >/var/www/upload/server/php/chroot/README.txt && \
  rm -rf /var/lib/apt/lists/* /var/cache/* /tmp/* /var/tmp/*

VOLUME [ "/var/www/upload/server/php/chroot/files" ]
EXPOSE 22 80

ENTRYPOINT ["/usr/bin/tini", \
            "--", \
            "/usr/local/bin/docker-uid-gid-setup.sh", \
            "/usr/local/bin/service_check_passthrough.sh", \
            "-s", "upload", \
            "/docker-entrypoint.sh"]

CMD ["/usr/bin/supervisord", "-c", "/supervisord.conf", "-u", "root", "-n"]

# to be populated at build-time:
ARG BUILD_DATE
ARG MALCOLM_VERSION
ARG VCS_REVISION

LABEL org.opencontainers.image.created=$BUILD_DATE
LABEL org.opencontainers.image.version=$MALCOLM_VERSION
LABEL org.opencontainers.image.revision=$VCS_REVISION
