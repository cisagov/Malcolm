FROM debian:buster-slim AS build

# Copyright (c) 2019 Battelle Energy Alliance, LLC.  All rights reserved.
LABEL maintainer="malcolm.netsec@gmail.com"
LABEL org.opencontainers.image.authors='malcolm.netsec@gmail.com'
LABEL org.opencontainers.image.url='https://github.com/idaholab/Malcolm'
LABEL org.opencontainers.image.documentation='https://github.com/idaholab/Malcolm/blob/master/README.md'
LABEL org.opencontainers.image.source='https://github.com/idaholab/Malcolm'
LABEL org.opencontainers.image.vendor='Idaho National Laboratory'
LABEL org.opencontainers.image.title='malcolmnetsec/file-upload'
LABEL org.opencontainers.image.description='Malcolm container providing an interface for uploading PCAP files and Zeek logs for processing'


ARG SITE_NAME="Capture File and Log Archive Upload"

ENV SITE_NAME $SITE_NAME
ENV JQUERY_FILE_UPLOAD_VERSION v9.19.1
ADD https://github.com/blueimp/jQuery-File-Upload/archive/${JQUERY_FILE_UPLOAD_VERSION}.tar.gz /jQuery-File-Upload.tar.gz

RUN apt-get update && \
    apt-get -y -q --allow-downgrades --allow-remove-essential --allow-change-held-packages install --no-install-recommends npm node-encoding git ca-certificates wget && \
    npm install -g bower && \
    mkdir /jQuery-File-Upload && \
    tar --strip-components=1 -C /jQuery-File-Upload -xzf /jQuery-File-Upload.tar.gz && \
    cd /jQuery-File-Upload && \
    bower --allow-root install bootstrap && \
    bower --allow-root install jquery && \
    bower --allow-root install blueimp-gallery && \
    bower --allow-root install bootstrap-tagsinput && \
    rm -rf /jQuery-File-Upload/*.html /jQuery-File-Upload/test/ /jQuery-File-Upload/server/gae-go/ \
           /jQuery-File-Upload/server/gae-python/

FROM debian:buster-slim AS runtime

COPY --from=build /jQuery-File-Upload/ /var/www/upload/

ENV DEBIAN_FRONTEND noninteractive
ENV TERM xterm

RUN apt-get update && \
    apt-get -y -q --allow-downgrades --allow-remove-essential --allow-change-held-packages install --no-install-recommends \
      wget \
      ca-certificates \
      openssh-server \
      supervisor \
      vim-tiny \
      less \
      php7.3-gd \
      php7.3-fpm \
      php7.3-apcu \
      nginx-light && \
    apt-get clean -y -q && \
    rm -rf /var/lib/apt/lists/*

ADD file-upload/supervisord.conf /supervisord.conf
ADD file-upload/jquery-file-upload/index.html /var/www/upload/index.html
ADD docs/images/logo/Malcolm_banner.png /var/www/upload/Malcolm_banner.png
ADD file-upload/jquery-file-upload/index.php /var/www/upload/server/php/index.php
ADD file-upload/php/php.ini /etc/php/7.3/fpm/php.ini
ADD file-upload/nginx/sites-available/default /etc/nginx/sites-available/default
ADD file-upload/sshd_config /tmp/sshd_config
ADD file-upload/docker-entrypoint.sh /docker-entrypoint.sh

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
  echo "Put your files into /files. Don't use subdirectories.\nThey cannot be accessed via the web user interface!" \
      >/var/www/upload/server/php/chroot/README.txt && \
  rm -rf /var/lib/apt/lists/* /var/cache/* /tmp/* /var/tmp/* /var/www/upload/server/php/chroot/files/.gitignore /tmp/sshd_config

VOLUME [ "/var/www/upload/server/php/chroot/files" ]
EXPOSE 22 80

ENTRYPOINT [ "/docker-entrypoint.sh" ]
CMD ["/usr/bin/supervisord", "-c", "/supervisord.conf", "-u", "root", "-n"]


# to be populated at build-time:
ARG BUILD_DATE
ARG MALCOLM_VERSION
ARG VCS_REVISION

LABEL org.opencontainers.image.created=$BUILD_DATE
LABEL org.opencontainers.image.version=$MALCOLM_VERSION
LABEL org.opencontainers.image.revision=$VCS_REVISION
